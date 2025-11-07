using System;
using Asn1;

namespace GoldendMSA.lib
{
    public class EncryptedData
    {
        //EncryptedData::= SEQUENCE {
        //    etype[0] Int32 -- EncryptionType --,
        //    kvno[1] UInt32 OPTIONAL,
        //    cipher[2] OCTET STRING -- ciphertext
        //}


        public EncryptedData(int encType, byte[] data)
        {
            etype = encType;
            cipher = data;
        }

        public EncryptedData(AsnElt body)
        {
            foreach (var s in body.Sub)
                switch (s.TagValue)
                {
                    case 0:
                        etype = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        var tmpLong = s.Sub[0].GetInteger();
                        kvno = Convert.ToUInt32(tmpLong & 0x00000000ffffffff);
                        break;
                    case 2:
                        cipher = s.Sub[0].GetOctetString();
                        break;
                }
        }

        public int etype { get; set; }

        public uint kvno { get; set; }

        public byte[] cipher { get; set; }

        public AsnElt Encode()
        {
            // etype   [0] Int32 -- EncryptionType --,
            var etypeAsn = AsnElt.MakeInteger(etype);
            var etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, etypeAsn);
            etypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, etypeSeq);


            // cipher  [2] OCTET STRING -- ciphertext
            var cipherAsn = AsnElt.MakeBlob(cipher);
            var cipherSeq = AsnElt.Make(AsnElt.SEQUENCE, cipherAsn);
            cipherSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, cipherSeq);


            if (kvno != 0)
            {
                // kvno    [1] UInt32 OPTIONAL
                var kvnoAsn = AsnElt.MakeInteger(kvno);
                var kvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, kvnoAsn);
                kvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, kvnoSeq);

                var totalSeq = AsnElt.Make(AsnElt.SEQUENCE, etypeSeq, kvnoSeq, cipherSeq);
                return totalSeq;
            }
            else
            {
                var totalSeq = AsnElt.Make(AsnElt.SEQUENCE, etypeSeq, cipherSeq);
                return totalSeq;
            }
        }
    }
}