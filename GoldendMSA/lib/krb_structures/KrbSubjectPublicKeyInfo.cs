using Asn1;

namespace GoldendMSA.lib
{
    public class KrbSubjectPublicKeyInfo
    {
        public KrbAlgorithmIdentifier Algorithm { get; set; }
        public byte[] SubjectPublicKey { get; set; }

        public AsnElt Encode()
        {
            return AsnElt.Make(
                AsnElt.SEQUENCE, Algorithm.Encode(), AsnElt.MakeBitString(SubjectPublicKey));
        }
    }
}