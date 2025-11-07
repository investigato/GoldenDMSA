using System;
using Asn1;

namespace GoldendMSA.lib
{
    public class EncryptionKey
    {
        //EncryptionKey::= SEQUENCE {
        //    keytype[0] Int32 -- actually encryption type --,
        //    keyvalue[1] OCTET STRING
        //}

        public EncryptionKey()
        {
            keytype = 0;

            keyvalue = null;
        }

        public EncryptionKey(AsnElt body)
        {
            foreach (var s in body.Sub[0].Sub)
                switch (s.TagValue)
                {
                    case 0:
                        keytype = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        keyvalue = s.Sub[0].GetOctetString();
                        break;
                    case 2:
                        keyvalue = s.Sub[0].GetOctetString();
                        break;
                }
        }

        public int keytype { get; set; }

        public byte[] keyvalue { get; set; }

        public AsnElt Encode()
        {
            // keytype[0] Int32 -- actually encryption type --
            var keyTypeElt = AsnElt.MakeInteger(keytype);
            var keyTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, keyTypeElt);
            keyTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, keyTypeSeq);


            // keyvalue[1] OCTET STRING
            var blob = AsnElt.MakeBlob(keyvalue);
            var blobSeq = AsnElt.Make(AsnElt.SEQUENCE, blob);
            blobSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, blobSeq);


            // build the final sequences (s)
            var seq = AsnElt.Make(AsnElt.SEQUENCE, keyTypeSeq, blobSeq);
            var seq2 = AsnElt.Make(AsnElt.SEQUENCE, seq);

            return seq2;
        }
    }
}