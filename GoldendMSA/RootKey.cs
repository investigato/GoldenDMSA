using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Text;

namespace GoldendMSA
{
    public class RootKey
    {
        private static readonly string[] KdsRootKeyAttributes =
        {
            "msKds-SecretAgreementParam", "msKds-RootKeyData",
            "msKds-KDFParam", "msKds-KDFAlgorithmID",
            "msKds-CreateTime", "msKds-UseStartTime",
            "msKds-Version", "msKds-DomainID",
            "cn", "msKds-PrivateKeyLength",
            "msKds-PublicKeyLength",
            "msKds-SecretAgreementAlgorithmID"
        };

        public static int KdsRootKeyDataSizeDefault = 64;

        private RootKey(SearchResult sr)
        {
            MsKdsVersion = (int)sr.Properties["msKds-Version"][0];
            Cn = Guid.Parse(sr.Properties["cn"][0].ToString());
            ProbReserved = 0;
            MsKdsVersion2 = (int)sr.Properties["msKds-Version"][0];
            ProbReserved2 = 0;
            MsKdsKdfAlgorithmId = sr.Properties["msKds-KDFAlgorithmID"][0].ToString();
            MsKdsKdfParam = (byte[])sr.Properties["msKds-KDFParam"][0];
            KdfParamSize = MsKdsKdfParam.Length;
            ProbReserved3 = 0;
            KdsSecretAgreementAlgorithmId = sr.Properties["msKds-SecretAgreementAlgorithmID"][0].ToString();
            KdsSecretAgreementParam = (byte[])sr.Properties["msKds-SecretAgreementParam"][0];
            SecretAlgoritmParamSize = KdsSecretAgreementParam.Length;
            PrivateKeyLength = (int)sr.Properties["msKds-PrivateKeyLength"][0];
            PublicKeyLength = (int)sr.Properties["msKds-PublicKeyLength"][0];
            ProbReserved4 = 0;
            ProbReserved5 = 0;
            ProbReserved6 = 0;
            Flag = 1;
            Flag2 = 1;
            KdsDomainId = sr.Properties["msKds-DomainID"][0].ToString();
            KdsCreateTime = (long)sr.Properties["msKds-CreateTime"][0];
            KdsUseStartTime = (long)sr.Properties["msKds-UseStartTime"][0];
            ProbReserved7 = 0;
            KdsRootKeyDataSize = 64;
            KdsRootKeyData = (byte[])sr.Properties["msKds-RootKeyData"][0];
        }

        public RootKey(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found", filePath);

            var lines = File.ReadAllLines(filePath);
            MsKdsVersion = int.Parse(lines[0]);
            Cn = Guid.Parse(lines[1]);
            ProbReserved = 0;
            MsKdsVersion2 = int.Parse(lines[0]);
            ProbReserved2 = 0;
            MsKdsKdfAlgorithmId = lines[2];
            MsKdsKdfParam = Convert.FromBase64String(lines[3]);
            KdfParamSize = MsKdsKdfParam.Length;
            ProbReserved3 = 0;
            KdsSecretAgreementAlgorithmId = lines[4];
            KdsSecretAgreementParam = Convert.FromBase64String(lines[5]);
            SecretAlgoritmParamSize = KdsSecretAgreementParam.Length;
            PrivateKeyLength = int.Parse(lines[6]);
            PublicKeyLength = int.Parse(lines[7]);
            ProbReserved4 = 0;
            ProbReserved5 = 0;
            ProbReserved6 = 0;
            Flag = 1;
            Flag2 = 1;
            KdsDomainId = lines[8];
            KdsCreateTime = long.Parse(lines[9]);
            KdsUseStartTime = long.Parse(lines[10]);
            ProbReserved7 = 0;
            KdsRootKeyDataSize = 64;
            KdsRootKeyData = Convert.FromBase64String(lines[11]);
        }

        public RootKey(byte[] rootKeyBytes)
        {
            var trackSize = 32;
            MsKdsVersion = BitConverter.ToInt32(rootKeyBytes, 0);
            var temp = new byte[16];
            Array.Copy(rootKeyBytes, 4, temp, 0, 16);
            Cn = new Guid(temp);
            ProbReserved = BitConverter.ToInt32(rootKeyBytes, 20);
            MsKdsVersion2 = BitConverter.ToInt32(rootKeyBytes, 24);
            ProbReserved2 = BitConverter.ToInt32(rootKeyBytes, 28);
            var msKdfAlgorithmIDSize = BitConverter.ToInt32(rootKeyBytes, trackSize);
            MsKdsKdfAlgorithmId = Encoding.Unicode.GetString(rootKeyBytes, trackSize + 4, msKdfAlgorithmIDSize);
            KdfParamSize = BitConverter.ToInt32(rootKeyBytes, trackSize + msKdfAlgorithmIDSize + 4);
            if (KdfParamSize > 0)
            {
                MsKdsKdfParam = new byte[KdfParamSize];
                Array.Copy(rootKeyBytes, trackSize + msKdfAlgorithmIDSize + 8, MsKdsKdfParam, 0, KdfParamSize);
            }
            else
            {
                MsKdsKdfParam = null;
            }

            trackSize += msKdfAlgorithmIDSize + KdfParamSize + 8;

            ProbReserved3 = BitConverter.ToInt32(rootKeyBytes, trackSize);
            trackSize += 4;

            var kdsSecretAgreementAlgorithmIdSize = BitConverter.ToInt32(rootKeyBytes, trackSize);
            KdsSecretAgreementAlgorithmId =
                Encoding.Unicode.GetString(rootKeyBytes, trackSize + 4, kdsSecretAgreementAlgorithmIdSize);
            SecretAlgoritmParamSize =
                BitConverter.ToInt32(rootKeyBytes, trackSize + kdsSecretAgreementAlgorithmIdSize + 4);
            if (SecretAlgoritmParamSize > 0)
            {
                KdsSecretAgreementParam = new byte[SecretAlgoritmParamSize];
                Array.Copy(rootKeyBytes, trackSize + msKdfAlgorithmIDSize + 8, KdsSecretAgreementParam, 0,
                    SecretAlgoritmParamSize);
            }
            else
            {
                KdsSecretAgreementParam = null;
            }

            trackSize += kdsSecretAgreementAlgorithmIdSize + SecretAlgoritmParamSize + 8;

            PrivateKeyLength = BitConverter.ToInt32(rootKeyBytes, trackSize);
            PublicKeyLength = BitConverter.ToInt32(rootKeyBytes, trackSize + 4);
            ProbReserved4 = BitConverter.ToInt32(rootKeyBytes, trackSize + 8);
            ProbReserved5 = BitConverter.ToInt32(rootKeyBytes, trackSize + 12);
            ProbReserved6 = BitConverter.ToInt32(rootKeyBytes, trackSize + 16);
            Flag = BitConverter.ToInt64(rootKeyBytes, trackSize + 20);
            Flag2 = BitConverter.ToInt64(rootKeyBytes, trackSize + 28);
            trackSize += 36;

            var kdsDomainIdSize = BitConverter.ToInt32(rootKeyBytes, trackSize);
            KdsDomainId = Encoding.Unicode.GetString(rootKeyBytes, trackSize + 4, kdsDomainIdSize);
            trackSize += kdsDomainIdSize + 4;

            KdsCreateTime = BitConverter.ToInt64(rootKeyBytes, trackSize);
            KdsUseStartTime = BitConverter.ToInt64(rootKeyBytes, trackSize + 8);
            ProbReserved7 = BitConverter.ToInt64(rootKeyBytes, trackSize + 16);
            KdsRootKeyDataSize = BitConverter.ToInt64(rootKeyBytes, trackSize + 24);
            if (KdsRootKeyDataSize > 0)
            {
                KdsRootKeyData = new byte[KdsRootKeyDataSize];
                Array.Copy(rootKeyBytes, trackSize + 32, KdsRootKeyData, 0, KdsRootKeyDataSize);
            }
            else
            {
                KdsRootKeyData = null;
            }
        }

        protected RootKey(RootKey rk)
        {
            MsKdsVersion = rk.MsKdsVersion;
            Cn = rk.Cn;
            ProbReserved = 0;
            MsKdsVersion2 = rk.MsKdsVersion;
            ProbReserved2 = 0;
            MsKdsKdfAlgorithmId = rk.MsKdsKdfAlgorithmId;
            MsKdsKdfParam = rk.MsKdsKdfParam.ToArray();
            KdfParamSize = rk.KdfParamSize;
            ProbReserved3 = rk.ProbReserved3;
            KdsSecretAgreementAlgorithmId = rk.KdsSecretAgreementAlgorithmId;
            KdsSecretAgreementParam = rk.KdsSecretAgreementParam.ToArray();
            SecretAlgoritmParamSize = rk.SecretAlgoritmParamSize;
            PrivateKeyLength = rk.PrivateKeyLength;
            PublicKeyLength = rk.PublicKeyLength;
            ProbReserved4 = rk.ProbReserved4;
            ProbReserved5 = rk.ProbReserved5;
            ProbReserved6 = rk.ProbReserved6;
            Flag = rk.Flag;
            Flag2 = rk.Flag2;
            KdsDomainId = rk.KdsDomainId;
            KdsCreateTime = rk.KdsCreateTime;
            KdsUseStartTime = rk.KdsUseStartTime;
            ProbReserved7 = rk.ProbReserved7;
            KdsRootKeyDataSize = rk.KdsRootKeyDataSize;
            KdsRootKeyData = rk.KdsRootKeyData.ToArray();
        }

        public int MsKdsVersion { get; set; }
        public Guid Cn { get; set; }
        public int ProbReserved { get; set; }
        public int MsKdsVersion2 { get; set; }
        public int ProbReserved2 { get; set; }
        public string MsKdsKdfAlgorithmId { get; set; }
        public byte[] MsKdsKdfParam { get; set; }
        public int KdfParamSize { get; set; }
        public int ProbReserved3 { get; set; }
        public string KdsSecretAgreementAlgorithmId { get; set; }
        public byte[] KdsSecretAgreementParam { get; set; }
        public int SecretAlgoritmParamSize { get; set; }
        public int PrivateKeyLength { get; set; }
        public int PublicKeyLength { get; set; }
        public int ProbReserved4 { get; set; }
        public int ProbReserved5 { get; set; }
        public int ProbReserved6 { get; set; }
        public long Flag { get; set; }
        public long Flag2 { get; set; }
        public string KdsDomainId { get; set; }
        public long KdsCreateTime { get; set; }
        public long KdsUseStartTime { get; set; }
        public long ProbReserved7 { get; set; }
        public long KdsRootKeyDataSize { get; set; }
        public byte[] KdsRootKeyData { get; set; }

        public static RootKey GetRootKeyByGuid(string forestName, Guid rootKeyId)
        {
            using (var rootDse = LdapUtils.GetRootDse(forestName))
            {
                var searchBase = rootDse.Properties["configurationNamingContext"].Value.ToString();
                var ldapFilter = $"(&(objectClass=msKds-ProvRootKey)(cn={rootKeyId}))";

                //Console.WriteLine($"searchBase={searchBase}; ldapFilter={ldapFilter}");

                var results = LdapUtils.FindInConfigPartition(forestName, ldapFilter, KdsRootKeyAttributes);

                if (results == null || results.Count == 0)
                    return null;

                return new RootKey(results[0]);
            }
        }

        public static IEnumerable<RootKey> GetAllRootKeys(string forestName)
        {
            using (var rootDse = LdapUtils.GetRootDse(forestName))
            {
                var searchBase = rootDse.Properties["configurationNamingContext"].Value.ToString();
                var ldapFilter = "(objectClass=msKds-ProvRootKey)";

                var results = LdapUtils.FindInConfigPartition(forestName, ldapFilter, KdsRootKeyAttributes);

                if (results == null || results.Count == 0)
                    yield break;

                foreach (SearchResult sr in results)
                {
                    RootKey rk = null;
                    try
                    {
                        rk = new RootKey(sr);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"WARNING: {sr.Properties["distinguishedName"][0]}: {ex.Message}");
                    }

                    if (rk != null)
                        yield return rk;
                }
            }
        }

        protected byte[] Serialize()
        {
            var trackSize = 36;
            long rootKeySize = 124 + Encoding.Unicode.GetByteCount(MsKdsKdfAlgorithmId) + MsKdsKdfParam.Length +
                               KdsSecretAgreementParam.Length
                               + Encoding.Unicode.GetByteCount(KdsSecretAgreementAlgorithmId) +
                               Encoding.Unicode.GetByteCount(KdsDomainId) + KdsRootKeyData.Length;
            var rootKeyBytes = new byte[rootKeySize];
            BitConverter.GetBytes(MsKdsVersion).CopyTo(rootKeyBytes, 0);
            Cn.ToByteArray().CopyTo(rootKeyBytes, 4);
            BitConverter.GetBytes(ProbReserved).CopyTo(rootKeyBytes, 20);
            BitConverter.GetBytes(MsKdsVersion2).CopyTo(rootKeyBytes, 24);
            BitConverter.GetBytes(ProbReserved2).CopyTo(rootKeyBytes, 28);

            var msKdsKdfAlgorithmIdBytes = Encoding.Unicode.GetBytes(MsKdsKdfAlgorithmId);
            BitConverter.GetBytes(msKdsKdfAlgorithmIdBytes.Length).CopyTo(rootKeyBytes, 32);
            msKdsKdfAlgorithmIdBytes.CopyTo(rootKeyBytes, trackSize);
            BitConverter.GetBytes(KdfParamSize).CopyTo(rootKeyBytes, trackSize + msKdsKdfAlgorithmIdBytes.Length);
            MsKdsKdfParam.CopyTo(rootKeyBytes, trackSize + 4 + msKdsKdfAlgorithmIdBytes.Length);
            trackSize += MsKdsKdfParam.Length + msKdsKdfAlgorithmIdBytes.Length + 4;

            BitConverter.GetBytes(ProbReserved3).CopyTo(rootKeyBytes, trackSize);
            trackSize += 4;

            var kdsSecretAgreementAlgorithmIdBytes = Encoding.Unicode.GetBytes(KdsSecretAgreementAlgorithmId);
            BitConverter.GetBytes(kdsSecretAgreementAlgorithmIdBytes.Length).CopyTo(rootKeyBytes, trackSize);
            kdsSecretAgreementAlgorithmIdBytes.CopyTo(rootKeyBytes, trackSize + 4);
            BitConverter.GetBytes(SecretAlgoritmParamSize).CopyTo(rootKeyBytes,
                trackSize + 4 + Encoding.Unicode.GetByteCount(KdsSecretAgreementAlgorithmId));
            KdsSecretAgreementParam.CopyTo(rootKeyBytes,
                trackSize + Encoding.Unicode.GetByteCount(KdsSecretAgreementAlgorithmId) + 8);
            trackSize += KdsSecretAgreementParam.Length + Encoding.Unicode.GetByteCount(KdsSecretAgreementAlgorithmId) +
                         8;

            BitConverter.GetBytes(PrivateKeyLength).CopyTo(rootKeyBytes, trackSize);
            BitConverter.GetBytes(PublicKeyLength).CopyTo(rootKeyBytes, trackSize + 4);
            BitConverter.GetBytes(ProbReserved4).CopyTo(rootKeyBytes, trackSize + 8);
            BitConverter.GetBytes(ProbReserved5).CopyTo(rootKeyBytes, trackSize + 12);
            BitConverter.GetBytes(ProbReserved6).CopyTo(rootKeyBytes, trackSize + 16);
            BitConverter.GetBytes(Flag).CopyTo(rootKeyBytes, trackSize + 20);
            BitConverter.GetBytes(Flag2).CopyTo(rootKeyBytes, trackSize + 28);
            trackSize += 36;

            var kdsDomainIdBytes = Encoding.Unicode.GetBytes(KdsDomainId);
            BitConverter.GetBytes(kdsDomainIdBytes.Length).CopyTo(rootKeyBytes, trackSize);
            kdsDomainIdBytes.CopyTo(rootKeyBytes, trackSize + 4);
            trackSize += Encoding.Unicode.GetByteCount(KdsDomainId) + 4;

            BitConverter.GetBytes(KdsCreateTime).CopyTo(rootKeyBytes, trackSize);
            BitConverter.GetBytes(KdsUseStartTime).CopyTo(rootKeyBytes, trackSize + 8);
            BitConverter.GetBytes(ProbReserved7).CopyTo(rootKeyBytes, trackSize + 16);
            BitConverter.GetBytes(KdsRootKeyDataSize).CopyTo(rootKeyBytes, trackSize + 24);
            KdsRootKeyData.CopyTo(rootKeyBytes, trackSize + 32);

            return rootKeyBytes;
        }

        public string ToBase64String()
        {
            return Convert.ToBase64String(Serialize());
        }

        public override string ToString()
        {
            var result = $"Guid:\t\t{Cn}{Environment.NewLine}";
            result += $"Base64 blob:\t{ToBase64String()}{Environment.NewLine}";
            result += $"----------------------------------------------{Environment.NewLine}";

            return result;
        }
    }
}