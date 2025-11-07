using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;

namespace GoldendMSA
{
    public sealed class GmsaAccount
    {
        private static readonly string[] GmsaRequiredLdapAttributes =
            { "msds-ManagedPasswordID", "samAccountName", "objectSid", "samAccountName", "distinguishedName" };

        private static readonly string MsdsManagedPasswordIdAttributeName = "msds-ManagedPasswordID";
        private static readonly string IsGmsaAccountLdapFilter = "(objectCategory=msDS-GroupManagedServiceAccount)";


        private GmsaAccount(
            string samAccountName,
            string dn,
            SecurityIdentifier sid,
            MsdsManagedPasswordId pwdId)
        {
            DistinguishedName = dn;
            ManagedPasswordId = pwdId;
            Sid = sid;
            SamAccountName = samAccountName;
        }

        public string DistinguishedName { get; private set; }

        private string SamAccountName { get; }
        private SecurityIdentifier Sid { get; }
        private MsdsManagedPasswordId ManagedPasswordId { get; }

        /// <summary>
        ///     Returns GMSA account information given its SID
        /// </summary>
        /// <param name="domainFqdn">FQDN of the domain to search</param>
        /// <param name="sid">The SID of the GMSA</param>
        /// <returns></returns>
        public static GmsaAccount GetGmsaAccountBySid(string domainFqdn, SecurityIdentifier sid)
        {
            if (sid is null)
                throw new ArgumentNullException(nameof(sid));

            if (domainFqdn is null)
                throw new ArgumentNullException(nameof(domainFqdn));

            var ldapFilter = $"(&{IsGmsaAccountLdapFilter}(objectsid={sid}))";
            var results = LdapUtils.FindInDomain(domainFqdn, ldapFilter, GmsaRequiredLdapAttributes);

            if (results == null || results.Count == 0)
                return null;

            return GetGmsaFromSearchResult(results[0]);
        }

        /// <summary>
        ///     Returns all GMSA account in domain
        /// </summary>
        /// <param name="domainFqdn">FQDN of the domain to search</param>
        /// <returns></returns>
        public static IEnumerable<GmsaAccount> FindAllGmsaAccountsInDomain(string domainFqdn)
        {
            if (string.IsNullOrEmpty(domainFqdn))
                throw new ArgumentException($"'{nameof(domainFqdn)}' cannot be null or empty.", nameof(domainFqdn));

            var results = LdapUtils.FindInDomain(domainFqdn, IsGmsaAccountLdapFilter, GmsaRequiredLdapAttributes);

            if (results == null)
                yield break;

            foreach (SearchResult sr in results)
            {
                GmsaAccount gmsa = null;
                try
                {
                    gmsa = GetGmsaFromSearchResult(sr);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"WARNING: {sr.Properties["distinguishedName"][0]}: {ex.Message}");
                }

                if (gmsa != null)
                    yield return gmsa;
            }
        }

        private static GmsaAccount GetGmsaFromSearchResult(SearchResult sr)
        {
            if (sr is null) throw new ArgumentNullException(nameof(sr));

            foreach (var attr in GmsaRequiredLdapAttributes)
                if (!sr.Properties.Contains(attr))
                    throw new KeyNotFoundException($"Attribute {attr} was not found");

            var dn = sr.Properties["distinguishedName"][0].ToString();

            var pwdBlob = (byte[])sr.Properties[MsdsManagedPasswordIdAttributeName][0];
            var pwdId = new MsdsManagedPasswordId(pwdBlob);

            var sid = new SecurityIdentifier((byte[])sr.Properties["objectSid"][0], 0);

            var samId = sr.Properties["samAccountName"][0].ToString();

            return new GmsaAccount(samId, dn, sid, pwdId);
        }


        public override string ToString()
        {
            var result = $"sAMAccountName:\t\t{SamAccountName}{Environment.NewLine}";
            result += $"objectSid:\t\t\t{Sid}{Environment.NewLine}";
            result += $"rootKeyGuid:\t\t{ManagedPasswordId.RootKeyIdentifier}{Environment.NewLine}";
            result +=
                $"msds-ManagedPasswordID:\t{Convert.ToBase64String(ManagedPasswordId.MsdsManagedPasswordIdBytes)}{Environment.NewLine}";
            result += $"----------------------------------------------{Environment.NewLine}";

            return result;
        }
    }
}