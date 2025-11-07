using System;
using System.Collections.Generic;
using Asn1;

namespace GoldendMSA.lib
{
    public class KrbCredInfo
    {
        //KrbCredInfo     ::= SEQUENCE {
        //        key             [0] EncryptionKey,
        //        prealm          [1] Realm OPTIONAL,
        //        pname           [2] PrincipalName OPTIONAL,
        //        flags           [3] TicketFlags OPTIONAL,
        //        authtime        [4] KerberosTime OPTIONAL,
        //        starttime       [5] KerberosTime OPTIONAL,
        //        endtime         [6] KerberosTime OPTIONAL,
        //        renew-till      [7] KerberosTime OPTIONAL,
        //        srealm          [8] Realm OPTIONAL,
        //        sname           [9] PrincipalName OPTIONAL,
        //        caddr           [10] HostAddresses OPTIONAL
        //}

        public KrbCredInfo()
        {
            key = new EncryptionKey();

            prealm = "";

            pname = new PrincipalName();

            flags = 0;

            srealm = "";

            sname = new PrincipalName();
        }

        public EncryptionKey key { get; set; }

        public string prealm { get; set; }

        public PrincipalName pname { get; set; }

        public Interop.TicketFlags flags { get; set; }

        public DateTime authtime { get; set; }

        public DateTime starttime { get; set; }

        public DateTime endtime { get; set; }

        public DateTime renew_till { get; set; }

        public string srealm { get; set; }

        public PrincipalName sname { get; set; }

        public AsnElt Encode()
        {
            var asnElements = new List<AsnElt>();

            // key             [0] EncryptionKey
            var keyAsn = key.Encode();
            keyAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, keyAsn);
            asnElements.Add(keyAsn);


            // prealm          [1] Realm OPTIONAL
            if (!string.IsNullOrEmpty(prealm))
            {
                var prealmAsn = AsnElt.MakeString(AsnElt.UTF8String, prealm);
                prealmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, prealmAsn);
                var prealmAsnSeq = AsnElt.Make(AsnElt.SEQUENCE, prealmAsn);
                prealmAsnSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, prealmAsnSeq);

                asnElements.Add(prealmAsnSeq);
            }


            // pname           [2] PrincipalName OPTIONAL
            if (pname.name_string != null && pname.name_string.Count != 0 &&
                !string.IsNullOrEmpty(pname.name_string[0]))
            {
                var pnameAsn = pname.Encode();
                pnameAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, pnameAsn);
                asnElements.Add(pnameAsn);
            }


            // pname           [2] PrincipalName OPTIONAL
            var flagBytes = BitConverter.GetBytes((uint)flags);
            if (BitConverter.IsLittleEndian) Array.Reverse(flagBytes);
            var flagBytesAsn = AsnElt.MakeBitString(flagBytes);
            var flagBytesSeq = AsnElt.Make(AsnElt.SEQUENCE, flagBytesAsn);
            flagBytesSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, flagBytesSeq);
            asnElements.Add(flagBytesSeq);


            // authtime        [4] KerberosTime OPTIONAL
            if (authtime != null && authtime != DateTime.MinValue)
            {
                var authtimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, authtime.ToString("yyyyMMddHHmmssZ"));
                var authtimeSeq = AsnElt.Make(AsnElt.SEQUENCE, authtimeAsn);
                authtimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, authtimeSeq);
                asnElements.Add(authtimeSeq);
            }


            // starttime       [5] KerberosTime OPTIONAL
            if (starttime != null && starttime != DateTime.MinValue)
            {
                var starttimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, starttime.ToString("yyyyMMddHHmmssZ"));
                var starttimeSeq = AsnElt.Make(AsnElt.SEQUENCE, starttimeAsn);
                starttimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, starttimeSeq);
                asnElements.Add(starttimeSeq);
            }


            // endtime         [6] KerberosTime OPTIONAL
            if (endtime != null && endtime != DateTime.MinValue)
            {
                var endtimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, endtime.ToString("yyyyMMddHHmmssZ"));
                var endtimeSeq = AsnElt.Make(AsnElt.SEQUENCE, endtimeAsn);
                endtimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 6, endtimeSeq);
                asnElements.Add(endtimeSeq);
            }


            // renew-till      [7] KerberosTime OPTIONAL
            if (renew_till != null && renew_till != DateTime.MinValue)
            {
                var renew_tillAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, renew_till.ToString("yyyyMMddHHmmssZ"));
                var renew_tillSeq = AsnElt.Make(AsnElt.SEQUENCE, renew_tillAsn);
                renew_tillSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 7, renew_tillSeq);
                asnElements.Add(renew_tillSeq);
            }


            // srealm          [8] Realm OPTIONAL
            if (!string.IsNullOrEmpty(srealm))
            {
                var srealmAsn = AsnElt.MakeString(AsnElt.UTF8String, srealm);
                srealmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, srealmAsn);
                var srealmAsnSeq = AsnElt.Make(AsnElt.SEQUENCE, srealmAsn);
                srealmAsnSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 8, srealmAsnSeq);
                asnElements.Add(srealmAsnSeq);
            }


            // sname           [9] PrincipalName OPTIONAL
            if (sname.name_string != null && sname.name_string.Count != 0 &&
                !string.IsNullOrEmpty(sname.name_string[0]))
            {
                var pnameAsn = sname.Encode();
                pnameAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 9, pnameAsn);
                asnElements.Add(pnameAsn);
            }


            // caddr           [10] HostAddresses OPTIONAL


            var seq = AsnElt.Make(AsnElt.SEQUENCE, asnElements.ToArray());

            return seq;
        }

        // caddr (optional) - skipping for now
    }
}