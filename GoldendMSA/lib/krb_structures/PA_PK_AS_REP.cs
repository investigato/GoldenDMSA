using System;
using Asn1;

namespace GoldendMSA.lib
{
    public class PA_PK_AS_REP
    {
        public PA_PK_AS_REP(AsnElt asnElt)
        {
            if (asnElt.TagClass != AsnElt.CONTEXT || asnElt.Sub.Length > 1)
                throw new ArgumentException("Expected CONTEXT with CHOICE for PA-PK-AS-REP");

            switch (asnElt.TagValue)
            {
                case 0: //dhInfo
                    DHRepInfo = new KrbDHRepInfo(asnElt.Sub[0]);
                    break;

                case 1: //encKeyPack: TODO
                    break;

                default:
                    throw new ArgumentException("Unexpected CHOICE value for PA-PK-AS-REP");
            }
        }

        public KrbDHRepInfo DHRepInfo { get; private set; }
    }
}