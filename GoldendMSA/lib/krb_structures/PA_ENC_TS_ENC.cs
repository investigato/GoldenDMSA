using System;
using Asn1;

namespace GoldendMSA.lib
{
    //PA-ENC-TS-ENC   ::= SEQUENCE {
    //        patimestamp[0]               KerberosTime, -- client's time
    //        pausec[1]                    INTEGER OPTIONAL
    //}

    public class PA_ENC_TS_ENC
    {
        public PA_ENC_TS_ENC()
        {
            patimestamp = DateTime.UtcNow;
        }

        public DateTime patimestamp { get; set; }

        public AsnElt Encode()
        {
            var patimestampAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, patimestamp.ToString("yyyyMMddHHmmssZ"));
            var patimestampSeq = AsnElt.Make(AsnElt.SEQUENCE, patimestampAsn);
            patimestampSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, patimestampSeq);

            var totalSeq = AsnElt.Make(AsnElt.SEQUENCE, patimestampSeq);

            return totalSeq;
        }
    }
}