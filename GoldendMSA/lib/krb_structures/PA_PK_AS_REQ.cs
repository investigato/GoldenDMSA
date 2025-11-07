using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Asn1;

namespace GoldendMSA.lib
{
    public class PA_PK_AS_REQ
    {
        public static readonly Oid IdPkInitAuthData = new Oid("1.3.6.1.5.2.3.1");
        public KrbAuthPack AuthPack { get; private set; }
        public X509Certificate2 PKCert { get; private set; }
        public bool VerifyCerts { get; private set; }

        public AsnElt Encode()
        {
            var signed = new SignedCms(
                new ContentInfo(
                    IdPkInitAuthData,
                    AuthPack.Encode().Encode()
                )
            );

            var signer = new CmsSigner(PKCert);
            if (!VerifyCerts)
                signer.IncludeOption =
                    X509IncludeOption
                        .EndCertOnly; // only the end certificate is included in the X.509 chain information.
            signed.ComputeSignature(signer, false);

            return AsnElt.Make(AsnElt.SEQUENCE,
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, AsnElt.MakeBlob(signed.Encode())));
        }
    }
}