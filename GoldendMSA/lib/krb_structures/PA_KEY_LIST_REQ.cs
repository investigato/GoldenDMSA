using Asn1;

namespace GoldendMSA.lib
{
    internal class PA_KEY_LIST_REQ
    {
        public int Enctype { get; set; }
        // KERB-KEY-LIST-REQ::= SEQUENCE OF Int32 -- encryption type -- 

        public AsnElt Encode()
        {
            var enctypeAsn = AsnElt.MakeInteger(Enctype);
            var enctypeSeq = AsnElt.Make(AsnElt.SEQUENCE, enctypeAsn);
            return enctypeSeq;
        }
    }
}