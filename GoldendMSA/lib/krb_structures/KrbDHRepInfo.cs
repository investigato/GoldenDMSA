using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Asn1;

namespace GoldendMSA.lib
{
    public class KrbDHRepInfo
    {
        public KrbDHRepInfo(AsnElt asnElt)
        {
            if (asnElt.TagValue != AsnElt.SEQUENCE) throw new ArgumentException("Expected SEQUENCE for type DHRepInfo");

            foreach (var seq in asnElt.Sub)
                switch (seq.TagValue)
                {
                    case 0: //dhSignedData
                        DHSignedData = seq.GetOctetString();
                        var cms = new SignedCms();
                        cms.Decode(DHSignedData);

                        try
                        {
                            cms.CheckSignature(true);
                        }
                        catch (CryptographicException)
                        {
                            Console.WriteLine("[!] DHRepInfo Signature Not Valid! - Do you even care?");
                        }

                        KDCDHKeyInfo = new KrbKDCDHKeyInfo(AsnElt.Decode(cms.ContentInfo.Content));
                        break;

                    case 1: //serverDHNonce
                        ServerDHNonce = seq.GetOctetString();
                        break;
                }
        }

        public byte[] ServerDHNonce { get; private set; }
        public byte[] DHSignedData { get; }
        public KrbKDCDHKeyInfo KDCDHKeyInfo { get; private set; }
    }
}