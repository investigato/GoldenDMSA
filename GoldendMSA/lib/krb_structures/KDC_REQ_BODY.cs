using System;
using System.Collections.Generic;
using System.Globalization;
using Asn1;

namespace GoldendMSA.lib
{
    public class KDCReqBody
    {
        //KDC-REQ-BODY::= SEQUENCE {
        //    kdc-options[0] KDCOptions,
        //    cname[1] PrincipalName OPTIONAL
        //                                -- Used only in AS-REQ --,
        //    realm[2] Realm
        //                                -- Server's realm
        //                                -- Also client's in AS-REQ --,
        //    sname[3] PrincipalName OPTIONAL,
        //    from[4] KerberosTime OPTIONAL,
        //    till[5] KerberosTime,
        //    rtime[6] KerberosTime OPTIONAL,
        //    nonce[7] UInt32,
        //            etype[8] SEQUENCE OF Int32 -- EncryptionType
        //                                        -- in preference order --,
        //            addresses[9] HostAddresses OPTIONAL,
        //    enc-authorization-data[10] EncryptedData OPTIONAL
        //                                        -- AuthorizationData --,
        //            additional-tickets[11] SEQUENCE OF Ticket OPTIONAL
        //                                            -- NOTE: not empty
        //}

        public KDCReqBody(bool c = true, bool r = false)
        {
            // defaults for creation
            kdcOptions = Interop.KdcOptions.FORWARDABLE | Interop.KdcOptions.RENEWABLE | Interop.KdcOptions.RENEWABLEOK;

            // added ability to remove cname from request
            // seems to be useful for cross domain stuff
            // didn't see a cname in "real" S4U request traffic
            if (c) cname = new PrincipalName();

            sname = new PrincipalName();


            till = DateTime.ParseExact("20370913024805Z", "yyyyMMddHHmmssZ", CultureInfo.InvariantCulture);

            // add rtime for AS-REQs
            if (r) rtime = DateTime.ParseExact("20370913024805Z", "yyyyMMddHHmmssZ", CultureInfo.InvariantCulture);

            var rand = new Random();
            nonce = (uint)rand.Next(1, int.MaxValue);

            additional_tickets = new List<Ticket>();

            etypes = new List<Interop.KERB_ETYPE>();
        }


        public Interop.KdcOptions kdcOptions { get; set; }

        public PrincipalName cname { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        public DateTime from { get; set; }

        public DateTime till { get; set; }

        public DateTime rtime { get; set; }

        public uint nonce { get; set; }

        public List<Interop.KERB_ETYPE> etypes { get; set; }

        public List<HostAddress> addresses { get; set; }

        public EncryptedData enc_authorization_data { get; set; }

        public List<Ticket> additional_tickets { get; set; }


        public AsnElt Encode()
        {
            // TODO: error-checking!

            var allNodes = new List<AsnElt>();

            // kdc-options             [0] KDCOptions
            var kdcOptionsBytes = BitConverter.GetBytes((uint)kdcOptions);
            if (BitConverter.IsLittleEndian) Array.Reverse(kdcOptionsBytes);
            var kdcOptionsAsn = AsnElt.MakeBitString(kdcOptionsBytes);
            var kdcOptionsSeq = AsnElt.Make(AsnElt.SEQUENCE, kdcOptionsAsn);
            kdcOptionsSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, kdcOptionsSeq);
            allNodes.Add(kdcOptionsSeq);


            // cname                   [1] PrincipalName
            if (cname != null)
            {
                var cnameElt = cname.Encode();
                cnameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, cnameElt);
                allNodes.Add(cnameElt);
            }


            // realm                   [2] Realm
            //                          --Server's realm
            //                          -- Also client's in AS-REQ --
            var realmAsn = AsnElt.MakeString(AsnElt.UTF8String, realm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            var realmSeq = AsnElt.Make(AsnElt.SEQUENCE, realmAsn);
            realmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, realmSeq);
            allNodes.Add(realmSeq);


            // sname                   [3] PrincipalName OPTIONAL
            var snameElt = sname.Encode();
            snameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, snameElt);
            allNodes.Add(snameElt);


            // from                    [4] KerberosTime OPTIONAL


            // till                    [5] KerberosTime
            var tillAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, till.ToString("yyyyMMddHHmmssZ"));
            var tillSeq = AsnElt.Make(AsnElt.SEQUENCE, tillAsn);
            tillSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, tillSeq);
            allNodes.Add(tillSeq);


            // rtime                   [6] KerberosTime
            if (rtime.Year > 0001)
            {
                var rtimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, rtime.ToString("yyyyMMddHHmmssZ"));
                var rtimeSeq = AsnElt.Make(AsnElt.SEQUENCE, rtimeAsn);
                rtimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 6, rtimeSeq);
                allNodes.Add(rtimeSeq);
            }

            // nonce                   [7] UInt32
            var nonceAsn = AsnElt.MakeInteger(nonce);
            var nonceSeq = AsnElt.Make(AsnElt.SEQUENCE, nonceAsn);
            nonceSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 7, nonceSeq);
            allNodes.Add(nonceSeq);


            // etype                   [8] SEQUENCE OF Int32 -- EncryptionType -- in preference order --
            var etypeList = new List<AsnElt>();
            foreach (var etype in etypes)
            {
                var etypeAsn = AsnElt.MakeInteger((int)etype);
                //AsnElt etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { etypeAsn });
                etypeList.Add(etypeAsn);
            }

            var etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, etypeList.ToArray());
            var etypeSeqTotal1 = AsnElt.Make(AsnElt.SEQUENCE, etypeList.ToArray());
            var etypeSeqTotal2 = AsnElt.Make(AsnElt.SEQUENCE, etypeSeqTotal1);
            etypeSeqTotal2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 8, etypeSeqTotal2);
            allNodes.Add(etypeSeqTotal2);


            // addresses               [9] HostAddresses OPTIONAL
            if (addresses != null)
            {
                var addrList = new List<AsnElt>();
                foreach (var addr in addresses)
                {
                    var addrElt = addr.Encode();
                    addrList.Add(addrElt);
                }

                var addrSeqTotal1 = AsnElt.Make(AsnElt.SEQUENCE, addrList.ToArray());
                var addrSeqTotal2 = AsnElt.Make(AsnElt.SEQUENCE, addrSeqTotal1);
                addrSeqTotal2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 9, addrSeqTotal2);
                allNodes.Add(addrSeqTotal2);
            }

            // enc-authorization-data  [10] EncryptedData OPTIONAL
            if (enc_authorization_data != null)
            {
                var authorizationEncryptedDataASN = enc_authorization_data.Encode();
                var authorizationEncryptedDataSeq = AsnElt.Make(AsnElt.SEQUENCE, authorizationEncryptedDataASN);
                authorizationEncryptedDataSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 10, authorizationEncryptedDataSeq);
                allNodes.Add(authorizationEncryptedDataSeq);
            }

            // additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
            if (additional_tickets.Count > 0)
            {
                var ticketAsn = additional_tickets[0].Encode();
                var ticketSeq = AsnElt.Make(AsnElt.SEQUENCE, ticketAsn);
                var ticketSeq2 = AsnElt.Make(AsnElt.SEQUENCE, ticketSeq);
                ticketSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 11, ticketSeq2);
                allNodes.Add(ticketSeq2);
            }

            var seq = AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());

            return seq;
        }
    }
}