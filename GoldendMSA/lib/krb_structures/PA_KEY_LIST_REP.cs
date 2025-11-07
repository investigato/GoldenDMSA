using Asn1;

namespace GoldendMSA.lib
{
    public class PA_KEY_LIST_REP
    {
        // KERB-KEY-LIST-REP ::= SEQUENCE OF EncryptionKey

        public PA_KEY_LIST_REP(AsnElt body)
        {
            encryptionKey = new EncryptionKey(body);
        }

        public EncryptionKey encryptionKey { get; set; }
    }
}