using System;
using System.Security.Cryptography;
using Asn1;

namespace GoldendMSA.lib
{
    public class KrbPkAuthenticator
    {
        public KDCReqBody RequestBody { get; private set; }
        public uint CuSec { get; set; }
        public DateTime CTime { get; set; }
        public int Nonce { get; set; }

        public AsnElt Encode()
        {
            byte[] paChecksum;

            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                paChecksum = sha1.ComputeHash(RequestBody.Encode().Encode());
            }

            var asnCTime = AsnElt.MakeString(AsnElt.GeneralizedTime, CTime.ToString("yyyyMMddHHmmssZ"));

            return AsnElt.Make(AsnElt.SEQUENCE, AsnElt.Make(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(CuSec)),
                AsnElt.Make(AsnElt.CONTEXT, 1, asnCTime), AsnElt.Make(AsnElt.CONTEXT, 2, AsnElt.MakeInteger(Nonce)),
                AsnElt.Make(AsnElt.CONTEXT, 3, AsnElt.MakeBlob(paChecksum)));
        }
    }
}