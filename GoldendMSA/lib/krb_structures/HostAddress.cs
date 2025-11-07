using System.Text;
using Asn1;

namespace GoldendMSA.lib
{
    //Hostname::= SEQUENCE {
    //        name-type[0] Int32,
    //        name-string[1] SEQUENCE OF KerberosString
    //}

    public class HostAddress
    {
        public HostAddress(string hostName)
        {
            // create with hostname
            addr_type = Interop.HostAddressType.ADDRTYPE_NETBIOS;

            // setup padding
            var numSpaces = 16 - hostName.Length % 16;
            hostName = hostName.PadRight(hostName.Length + numSpaces);

            addr_string = hostName.ToUpper();
        }


        public HostAddress(AsnElt body)
        {
            foreach (var s in body.Sub)
                switch (s.TagValue)
                {
                    case 0:
                        addr_type = (Interop.HostAddressType)s.Sub[0].GetInteger();
                        break;
                    case 1:
                        addr_string = Encoding.UTF8.GetString(s.Sub[0].GetOctetString());
                        break;
                }
        }

        public Interop.HostAddressType addr_type { get; set; }

        public string addr_string { get; set; }

        public AsnElt Encode()
        {
            // addr-type[0] Int32
            // addr-string[1] OCTET STRING
            var addrTypeElt = AsnElt.MakeInteger((long)addr_type);
            var addrTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, addrTypeElt);
            addrTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, addrTypeSeq);

            var addrStringElt = AsnElt.MakeString(AsnElt.TeletexString, addr_string);
            addrStringElt = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.OCTET_STRING, addrStringElt);
            var addrStringSeq = AsnElt.Make(AsnElt.SEQUENCE, addrStringElt);
            addrStringSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, addrStringSeq);

            var seq = AsnElt.Make(AsnElt.SEQUENCE, addrTypeSeq, addrStringSeq);

            return seq;
        }
    }
}