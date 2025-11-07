using System;

namespace GoldendMSA
{
    public class KdsUtils
    {
        public static readonly long KeyCycleDuration = 360000000000;

        public static void GetCurrentIntervalId(
            long kdsKeyCycleDuration, // 360000000000
            int someFlag, // 0
            ref int l0KeyId,
            ref int l1KeyId,
            ref int l2KeyId)
        {
            var currentTime = DateTime.Now.ToFileTimeUtc();
            if (someFlag != 0) currentTime += 3000000000;
            var temp = (int)(currentTime / kdsKeyCycleDuration);
            l0KeyId = temp / 1024;
            l1KeyId = (temp / 32) & 31;
            l2KeyId = temp & 31;
        }
    }
}