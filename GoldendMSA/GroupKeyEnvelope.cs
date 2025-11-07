using System;
using System.Text;

namespace GoldendMSA
{
    public class GroupKeyEnvelope
    {
        public GroupKeyEnvelope()
        {
        }

        public GroupKeyEnvelope(byte[] gkeBytes)
        {
            Version = BitConverter.ToInt32(gkeBytes, 0);
            Reserved = BitConverter.ToInt32(gkeBytes, 4);
            IsPublicKey = BitConverter.ToInt32(gkeBytes, 8);
            L0Index = BitConverter.ToInt32(gkeBytes, 12);
            L1Index = BitConverter.ToInt32(gkeBytes, 16);
            L2Index = BitConverter.ToInt32(gkeBytes, 20);
            var temp = new byte[16];
            Array.Copy(gkeBytes, 24, temp, 0, 16);
            RootKeyIdentifier = new Guid(temp);
            CbKdfAlgorithm = BitConverter.ToInt32(gkeBytes, 40);
            CbKdfParameters = BitConverter.ToInt32(gkeBytes, 44);
            CbSecretAgreementAlgorithm = BitConverter.ToInt32(gkeBytes, 48);
            CbSecretAgreementParameters = BitConverter.ToInt32(gkeBytes, 52);
            PrivateKeyLength = BitConverter.ToInt32(gkeBytes, 56);
            PublicKeyLength = BitConverter.ToInt32(gkeBytes, 60);
            CbL1Key = BitConverter.ToInt32(gkeBytes, 64);
            CbL2Key = BitConverter.ToInt32(gkeBytes, 68);
            CbDomainName = BitConverter.ToInt32(gkeBytes, 72);
            CbForestName = BitConverter.ToInt32(gkeBytes, 76);

            var curIndex = 80;
            KdfAlgorithm = Encoding.Unicode.GetString(gkeBytes, curIndex, CbKdfAlgorithm);

            curIndex += CbKdfAlgorithm;
            Array.Copy(gkeBytes, curIndex, KdfParameters, 0, CbKdfParameters);

            curIndex += CbKdfParameters;
            SecretAgreementAlgorithm = Encoding.Unicode.GetString(gkeBytes, curIndex, CbSecretAgreementAlgorithm);

            curIndex += CbSecretAgreementAlgorithm;
            Array.Copy(gkeBytes, curIndex, SecretAgreementParameters, 0, CbSecretAgreementParameters);

            curIndex += CbSecretAgreementParameters;
            DomainName = Encoding.Unicode.GetString(gkeBytes, curIndex, CbDomainName);

            curIndex += CbDomainName;
            ForestName = Encoding.Unicode.GetString(gkeBytes, curIndex, CbForestName);

            if (CbL1Key > 0)
                Array.Copy(gkeBytes, curIndex + CbForestName, L1Key, 0, CbL1Key);
            else
                L1Key = null;

            if (CbL2Key > 0)
                Array.Copy(gkeBytes, curIndex + CbForestName + CbL1Key, L2Key, 0, CbL2Key);
            else
                L2Key = null;
        }

        public int Version { get; set; }
        public int Reserved { get; set; }
        public int IsPublicKey { get; set; }
        public int L0Index { get; set; }
        public int L1Index { get; set; }
        public int L2Index { get; set; }
        public Guid RootKeyIdentifier { get; set; }
        public int CbKdfAlgorithm { get; set; }
        public int CbKdfParameters { get; set; }
        public int CbSecretAgreementAlgorithm { get; set; }
        public int CbSecretAgreementParameters { get; set; }
        public int PrivateKeyLength { get; set; }
        public int PublicKeyLength { get; set; }
        public int CbL1Key { get; set; }
        public int CbL2Key { get; set; }
        public int CbDomainName { get; set; }
        public int CbForestName { get; set; }
        public string KdfAlgorithm { get; set; }
        public byte[] KdfParameters { get; set; }
        public string SecretAgreementAlgorithm { get; set; }
        public byte[] SecretAgreementParameters { get; set; }
        public string DomainName { get; set; }
        public string ForestName { get; set; }
        public byte[] L1Key { get; set; } // 64 in size
        public byte[] L2Key { get; set; } // 64 in size


        public byte[] Serialize()
        {
            var gkeSize = 80 + CbKdfAlgorithm + CbKdfParameters + CbSecretAgreementAlgorithm +
                          CbSecretAgreementParameters + CbDomainName + CbForestName + CbL1Key + CbL2Key;
            var gkeBytes = new byte[gkeSize];

            BitConverter.GetBytes(Version).CopyTo(gkeBytes, 0);
            BitConverter.GetBytes(Reserved).CopyTo(gkeBytes, 4);
            BitConverter.GetBytes(IsPublicKey).CopyTo(gkeBytes, 8);
            BitConverter.GetBytes(L0Index).CopyTo(gkeBytes, 12);
            BitConverter.GetBytes(L1Index).CopyTo(gkeBytes, 16);
            BitConverter.GetBytes(L2Index).CopyTo(gkeBytes, 20);
            RootKeyIdentifier.ToByteArray().CopyTo(gkeBytes, 24);
            BitConverter.GetBytes(CbKdfAlgorithm).CopyTo(gkeBytes, 40);
            BitConverter.GetBytes(CbKdfParameters).CopyTo(gkeBytes, 44);
            BitConverter.GetBytes(CbSecretAgreementAlgorithm).CopyTo(gkeBytes, 48);
            BitConverter.GetBytes(CbSecretAgreementParameters).CopyTo(gkeBytes, 52);
            BitConverter.GetBytes(PrivateKeyLength).CopyTo(gkeBytes, 56);
            BitConverter.GetBytes(PublicKeyLength).CopyTo(gkeBytes, 60);
            BitConverter.GetBytes(CbL1Key).CopyTo(gkeBytes, 64);
            BitConverter.GetBytes(CbL2Key).CopyTo(gkeBytes, 68);
            BitConverter.GetBytes(CbDomainName).CopyTo(gkeBytes, 72);
            BitConverter.GetBytes(CbForestName).CopyTo(gkeBytes, 76);
            Encoding.Unicode.GetBytes(KdfAlgorithm).CopyTo(gkeBytes, 80);

            var curIndex = 80 + CbKdfAlgorithm;
            KdfParameters.CopyTo(gkeBytes, curIndex);

            curIndex += CbKdfParameters;
            Encoding.Unicode.GetBytes(SecretAgreementAlgorithm).CopyTo(gkeBytes, curIndex);

            curIndex += CbSecretAgreementAlgorithm;
            SecretAgreementParameters.CopyTo(gkeBytes, curIndex);

            curIndex += CbSecretAgreementParameters;
            Encoding.Unicode.GetBytes(DomainName).CopyTo(gkeBytes, curIndex);

            curIndex += CbDomainName;
            Encoding.Unicode.GetBytes(ForestName).CopyTo(gkeBytes, curIndex);

            curIndex += CbForestName;
            L1Key.CopyTo(gkeBytes, curIndex);

            curIndex += CbL1Key;
            L1Key.CopyTo(gkeBytes, curIndex);

            return gkeBytes;
        }

        public string ToBase64String()
        {
            return Convert.ToBase64String(Serialize());
        }
    }
}