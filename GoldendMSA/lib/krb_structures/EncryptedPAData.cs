using System;
using Asn1;

namespace GoldendMSA.lib
{
    public class EncryptedPAData
    {
        public EncryptedPAData(AsnElt body)
        {
            // Get padata-type and padata-value
            foreach (var s in body.Sub[0].Sub)
                switch (s.TagValue)
                {
                    case 1:
                        keytype = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 2:
                        keyvalue = s.Sub[0].GetOctetString();
                        break;
                }

            // Decode the KEY-LIST-REP 
            if (keytype == (int)Interop.PADATA_TYPE.KEY_LIST_REP)
            {
                var ae = AsnElt.Decode(keyvalue);
                PA_KEY_LIST_REP = new PA_KEY_LIST_REP(ae);
            }

            // Decode the DMSA_KEY_PACKAGE
            if (keytype == (int)Interop.PADATA_TYPE.DMSA_KEY_PACKAGE)
            {
                var ae = AsnElt.Decode(keyvalue);
                PA_DMSA_KEY_PACKAGE = new PA_DMSA_KEY_PACKAGE(ae);
            }
        }

        public int keytype { get; set; }

        public byte[] keyvalue { get; set; }

        public PA_KEY_LIST_REP PA_KEY_LIST_REP { get; set; }

        public PA_DMSA_KEY_PACKAGE PA_DMSA_KEY_PACKAGE { get; set; }
    }
}