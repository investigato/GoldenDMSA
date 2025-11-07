using System.Collections.Generic;
using Asn1;

namespace GoldendMSA.lib
{
    public class KRB_CRED
    {
        //KRB-CRED::= [APPLICATION 22] SEQUENCE {
        //    pvno[0] INTEGER(5),
        //    msg-type[1] INTEGER(22),
        //    tickets[2] SEQUENCE OF Ticket,
        //    enc-part[3] EncryptedData -- EncKrbCredPart
        //}

        public KRB_CRED()
        {
            // defaults for creation
            pvno = 5;
            msg_type = 22;

            tickets = new List<Ticket>();

            enc_part = new EncKrbCredPart();
        }

        public long pvno { get; set; }

        public long msg_type { get; set; }

        //public Ticket[] tickets { get; set; }
        public List<Ticket> tickets { get; set; }

        public EncKrbCredPart enc_part { get; set; }

        public byte[] RawBytes { get; set; }

        public AsnElt Encode()
        {
            // pvno            [0] INTEGER (5)
            var pvnoAsn = AsnElt.MakeInteger(pvno);
            var pvnoSeq = AsnElt.Make(AsnElt.SEQUENCE, pvnoAsn);
            pvnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, pvnoSeq);


            // msg-type        [1] INTEGER (22)
            var msg_typeAsn = AsnElt.MakeInteger(msg_type);
            var msg_typeSeq = AsnElt.Make(AsnElt.SEQUENCE, msg_typeAsn);
            msg_typeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, msg_typeSeq);


            // tickets         [2] SEQUENCE OF Ticket
            //  TODO: encode/handle multiple tickets!
            var ticketAsn = tickets[0].Encode();
            var ticketSeq = AsnElt.Make(AsnElt.SEQUENCE, ticketAsn);
            var ticketSeq2 = AsnElt.Make(AsnElt.SEQUENCE, ticketSeq);
            ticketSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, ticketSeq2);


            // enc-part        [3] EncryptedData -- EncKrbCredPart
            var enc_partAsn = enc_part.Encode();
            var blob = AsnElt.MakeBlob(enc_partAsn.Encode());

            var blobSeq = AsnElt.Make(AsnElt.SEQUENCE, blob);
            blobSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, blobSeq);

            // etype == 0 -> no encryption
            var etypeAsn = AsnElt.MakeInteger(0);
            var etypeSeq = AsnElt.Make(AsnElt.SEQUENCE, etypeAsn);
            etypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, etypeSeq);

            var infoSeq = AsnElt.Make(AsnElt.SEQUENCE, etypeSeq, blobSeq);
            var infoSeq2 = AsnElt.Make(AsnElt.SEQUENCE, infoSeq);
            infoSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, infoSeq2);


            // all the components
            var total = AsnElt.Make(AsnElt.SEQUENCE, pvnoSeq, msg_typeSeq, ticketSeq2, infoSeq2);

            // tag the final total ([APPLICATION 22])
            var final = AsnElt.Make(AsnElt.SEQUENCE, total);
            final = AsnElt.MakeImplicit(AsnElt.APPLICATION, 22, final);

            return final;
        }
    }
}