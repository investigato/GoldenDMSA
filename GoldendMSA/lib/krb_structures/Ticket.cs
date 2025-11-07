using System;
using System.Text;
using Asn1;

namespace GoldendMSA.lib
{
    public class Ticket
    {
        //Ticket::= [APPLICATION 1] SEQUENCE {
        //        tkt-vno[0] INTEGER(5),
        //        realm[1] Realm,
        //        sname[2] PrincipalName,
        //        enc-part[3] EncryptedData -- EncTicketPart
        //}


        public Ticket(AsnElt body)
        {
            foreach (var s in body.Sub)
                switch (s.TagValue)
                {
                    case 0:
                        tkt_vno = Convert.ToInt32(s.Sub[0].GetInteger());
                        break;
                    case 1:
                        realm = Encoding.UTF8.GetString(s.Sub[0].GetOctetString());
                        break;
                    case 2:
                        sname = new PrincipalName(s.Sub[0]);
                        break;
                    case 3:
                        enc_part = new EncryptedData(s.Sub[0]);
                        break;
                }
        }


        public int tkt_vno { get; set; }

        public string realm { get; set; }

        public PrincipalName sname { get; set; }

        public EncryptedData enc_part { get; set; }

        public AsnElt Encode()
        {
            // tkt-vno         [0] INTEGER (5)
            var tkt_vnoAsn = AsnElt.MakeInteger(tkt_vno);
            var tkt_vnoSeq = AsnElt.Make(AsnElt.SEQUENCE, tkt_vnoAsn);
            tkt_vnoSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, tkt_vnoSeq);


            // realm           [1] Realm
            var realmAsn = AsnElt.MakeString(AsnElt.UTF8String, realm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, realmAsn);
            var realmAsnSeq = AsnElt.Make(AsnElt.SEQUENCE, realmAsn);
            realmAsnSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, realmAsnSeq);


            // sname           [2] PrincipalName
            var snameAsn = sname.Encode();
            snameAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, snameAsn);


            // enc-part        [3] EncryptedData -- EncTicketPart
            var enc_partAsn = enc_part.Encode();
            var enc_partSeq = AsnElt.Make(AsnElt.SEQUENCE, enc_partAsn);
            enc_partSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, enc_partSeq);


            var totalSeq = AsnElt.Make(AsnElt.SEQUENCE, tkt_vnoSeq, realmAsnSeq, snameAsn, enc_partSeq);
            var totalSeq2 = AsnElt.Make(AsnElt.SEQUENCE, totalSeq);
            totalSeq2 = AsnElt.MakeImplicit(AsnElt.APPLICATION, 1, totalSeq2);

            return totalSeq2;
        }
    }
}