using System;
using System.Runtime.InteropServices;

namespace GoldendMSA.lib
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID : IEquatable<LUID>
    {
        public UInt32 LowPart;
        public Int32 HighPart;

        public static implicit operator ulong(LUID luid)
        {
            // enable casting to a ulong
            var value = (ulong)luid.HighPart << 32;
            return value + luid.LowPart;
        }

        public bool Equals(LUID other)
        {
            return LowPart == other.LowPart && HighPart == other.HighPart;
        }

        public override bool Equals(object obj)
        {
            return obj is LUID other && Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((int)LowPart * 397) ^ HighPart;
            }
        }
    }
}