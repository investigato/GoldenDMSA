using System.Security.Cryptography;
using Asn1;

namespace GoldendMSA.lib
{
    public class KrbAlgorithmIdentifier
    {
        public Oid Algorithm { get; set; }
        public byte[] Parameters { get; set; }


        public AsnElt Encode()
        {
            var parameters = AsnElt.Decode(Parameters);

            return AsnElt.Make(
                AsnElt.SEQUENCE, AsnElt.MakeOID(Algorithm.Value), parameters);
        }
    }
}