using System;
using System.Security.Principal;
using System.Text;

namespace GoldendMSA
{
    public class MsdsManagedPasswordId
    {
        public MsdsManagedPasswordId(byte[] pwdBlob)
        {
            MsdsManagedPasswordIdBytes = pwdBlob;

            Version = BitConverter.ToInt32(pwdBlob, 0);
            Reserved = BitConverter.ToInt32(pwdBlob, 4);
            IsPublicKey = BitConverter.ToInt32(pwdBlob, 8);
            L0Index = BitConverter.ToInt32(pwdBlob, 12);
            L1Index = BitConverter.ToInt32(pwdBlob, 16);
            L2Index = BitConverter.ToInt32(pwdBlob, 20);
            var temp = new byte[16];
            Array.Copy(pwdBlob, 24, temp, 0, 16);
            RootKeyIdentifier = new Guid(temp);
            CbUnknown = BitConverter.ToInt32(pwdBlob, 40);
            CbDomainName = BitConverter.ToInt32(pwdBlob, 44);
            CbForestName = BitConverter.ToInt32(pwdBlob, 48);
            if (CbUnknown > 0)
            {
                Unknown = new byte[CbUnknown];
                Array.Copy(pwdBlob, 52, Unknown, 0, CbUnknown);
            }
            else
            {
                Unknown = null;
            }

            DomainName = Encoding.Unicode.GetString(pwdBlob, 52 + CbUnknown, CbDomainName);
            ForestName = Encoding.Unicode.GetString(pwdBlob, 52 + CbDomainName + CbUnknown, CbForestName);
        }

        public byte[] MsdsManagedPasswordIdBytes { get; private set; }

        public int Version { get; set; }
        public int Reserved { get; set; }
        public int IsPublicKey { get; set; }
        public int L0Index { get; set; }
        public int L1Index { get; set; }
        public int L2Index { get; set; }
        public Guid RootKeyIdentifier { get; set; }
        public int CbUnknown { get; set; }
        public int CbDomainName { get; set; }
        public int CbForestName { get; set; }
        public byte[] Unknown { get; set; }
        public string DomainName { get; set; }
        public string ForestName { get; set; }


        public static MsdsManagedPasswordId GetManagedPasswordIdBySid(string domainName, SecurityIdentifier sid)
        {
            string[] attributes = { "msds-ManagedPasswordID" };
            var ldapFilter = $"(objectSID={sid})";

            var results = LdapUtils.FindInDomain(domainName, ldapFilter, attributes);

            if (results == null || results.Count == 0)
                return null;

            if (!results[0].Properties.Contains("msds-ManagedPasswordID"))
                return null;

            var pwdIdBlob = (byte[])results[0].Properties["msds-ManagedPasswordID"][0];

            return new MsdsManagedPasswordId(pwdIdBlob);
        }
    }
}