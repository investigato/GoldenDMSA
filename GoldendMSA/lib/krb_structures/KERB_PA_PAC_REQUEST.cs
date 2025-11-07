using Asn1;

namespace GoldendMSA.lib
{
    //KERB-PA-PAC-REQUEST ::= SEQUENCE { 
    //    include-pac[0] BOOLEAN --If TRUE, and no pac present, include PAC.
    //                           --If FALSE, and PAC present, remove PAC
    //}

    public class KERB_PA_PAC_REQUEST
    {
        public KERB_PA_PAC_REQUEST(bool pac = true)
        {
            // default -> include PAC
            include_pac = pac;
        }

        public KERB_PA_PAC_REQUEST(AsnElt value)
        {
            include_pac = value.Sub[0].Sub[0].GetBoolean();
        }

        public bool include_pac { get; set; }

        public AsnElt Encode()
        {
            AsnElt ret;

            if (include_pac)
                ret = AsnElt.MakeBlob(new byte[] { 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01 });
            else
                ret = AsnElt.MakeBlob(new byte[] { 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00 });

            var seq = AsnElt.Make(AsnElt.SEQUENCE, ret);

            return seq;
        }
    }
}