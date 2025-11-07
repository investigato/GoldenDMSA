using System.Collections.Generic;
using Asn1;

namespace GoldendMSA.lib
{
    //EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
    //        ticket-info     [0] SEQUENCE OF KrbCredInfo,
    //        nonce           [1] UInt32 OPTIONAL,
    //        timestamp       [2] KerberosTime OPTIONAL,
    //        usec            [3] Microseconds OPTIONAL,
    //        s-address       [4] HostAddress OPTIONAL,
    //        r-address       [5] HostAddress OPTIONAL
    //}

    public class EncKrbCredPart
    {
        public EncKrbCredPart()
        {
            // TODO: defaults for creation
            ticket_info = new List<KrbCredInfo>();
        }

        public List<KrbCredInfo> ticket_info { get; set; }

        public AsnElt Encode()
        {
            // ticket-info     [0] SEQUENCE OF KrbCredInfo
            //  assume just one ticket-info for now
            //  TODO: handle multiple ticket-infos
            var infoAsn = ticket_info[0].Encode();
            var seq1 = AsnElt.Make(AsnElt.SEQUENCE, infoAsn);
            var seq2 = AsnElt.Make(AsnElt.SEQUENCE, seq1);
            seq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, seq2);

            var totalSeq = AsnElt.Make(AsnElt.SEQUENCE, seq2);
            var totalSeq2 = AsnElt.Make(AsnElt.SEQUENCE, totalSeq);
            totalSeq2 = AsnElt.MakeImplicit(AsnElt.APPLICATION, 29, totalSeq2);

            return totalSeq2;
        }
    }
}