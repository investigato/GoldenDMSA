using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using GoldendMSA.Unsafe;

namespace GoldendMSA
{
    public static class GmsaPassword
    {
        private static readonly byte[] DefaultGmsaSecurityDescriptor =
        {
            0x1, 0x0, 0x4, 0x80, 0x30, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x0, 0x1C, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x14, 0x0, 0x9F, 0x1, 0x12, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x9,
            0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x12, 0x0, 0x0, 0x0
        };


        public static byte[] GetPassword( // GetPasswordBasedOnTimeStamp
            SecurityIdentifier sid,
            RootKey rootKey,
            MsdsManagedPasswordId pwdId,
            string domainName,
            string forestName)
        {
            int l0KeyId = 0, l1KeyId = 0, l2KeyId = 0;

            KdsUtils.GetCurrentIntervalId(KdsUtils.KeyCycleDuration, 0, ref l0KeyId, ref l1KeyId, ref l2KeyId);

            GetKey.GetSidKeyLocal(
                DefaultGmsaSecurityDescriptor,
                DefaultGmsaSecurityDescriptor.Length,
                rootKey,
                l0KeyId, l1KeyId, l2KeyId,
                0,
                domainName, forestName,
                out var gke,
                out var gkeSize);

            var passwordBlobSize = 256;
            var sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            var pwdBlob = GenerateGmsaPassowrd(
                gke, gkeSize,
                pwdId.MsdsManagedPasswordIdBytes,
                sidBytes,
                IntPtr.Zero, IntPtr.Zero,
                passwordBlobSize);

            return pwdBlob;
        }

        private static void ParseSidKeyResult(
            GroupKeyEnvelope gke,
            int gkeSize,
            byte[] msdsManagedPasswordId,
            out byte[] l1Key,
            ref int l1KeyIdDiff,
            ref int newL1KeyId,
            out byte[] l2Key,
            ref int l2KeyIdDiff,
            ref int newL2KeyId,
            out byte[] publicKey)
        {
            if (newL2KeyId < 0) throw new ArgumentOutOfRangeException(nameof(newL2KeyId));
            newL2KeyId = 31;
            if (msdsManagedPasswordId != null)
            {
                var managedPasswordId = new MsdsManagedPasswordId(msdsManagedPasswordId);
                l1KeyIdDiff = gke.L1Index - managedPasswordId.L1Index;
                l2KeyIdDiff = 32 - managedPasswordId.L2Index;
                if (gke.CbL2Key > 0)
                {
                    l1KeyIdDiff--;
                    if (l1KeyIdDiff > 0) newL1KeyId = gke.L1Index - 2;
                    if (gke.L1Index <= managedPasswordId.L1Index)
                    {
                        l2KeyIdDiff = gke.L2Index - managedPasswordId.L2Index;
                        if (l2KeyIdDiff > 0) newL2KeyId = gke.L2Index - 1;
                    }
                }
                else if (l1KeyIdDiff > 0)
                {
                    newL1KeyId = gke.L1Index - 1;
                }
            }
            else if (gke.L2Index == 0)
            {
                l2KeyIdDiff = 1;
            }

            if (gke.CbL1Key > 0)
                l1Key = gke.L1Key.ToArray();
            else
                l1Key = null;
            if (gke.CbL2Key > 0)
                l2Key = gke.L2Key.ToArray();
            else
                l2Key = null;
            publicKey = null;
        }

        private static void ClientComputeL2Key(
            GroupKeyEnvelope gke,
            byte[] msdsManagedPasswordIdBytes,
            string kdfAlgorithmId,
            byte[] l1Key,
            ref byte[] l2Key,
            int l1KeyDiff,
            int newL1KeyId,
            int l2KeyDiff,
            int newL2KeyId)
        {
            var msdsManagedPasswordId = new MsdsManagedPasswordId(msdsManagedPasswordIdBytes);
            var rootKeyGuid = gke.RootKeyIdentifier.ToByteArray();
            byte[] kdfParam = null;

            if (gke.CbKdfParameters > 0)
                kdfParam = gke.KdfParameters.ToArray();

            uint errCode = 0;

            if (l1KeyDiff > 0)
            {
                errCode = KdsCli.GenerateKDFContext(
                    rootKeyGuid, gke.L0Index,
                    newL1KeyId, 0xffffffff,
                    1,
                    out var kdfContextL1,
                    out var kdfContextSizeL1,
                    out var kdfContextFlagL1);

                if (errCode != 0)
                    throw new Exception(
                        $"{nameof(ClientComputeL2Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");


                var kdfContextArrL1 = new byte[kdfContextSizeL1];
                Marshal.Copy(kdfContextL1, kdfContextArrL1, 0, kdfContextSizeL1);

                errCode = KdsCli.GenerateDerivedKey(
                    kdfAlgorithmId, kdfParam,
                    gke.CbKdfParameters, l1Key,
                    64, kdfContextArrL1,
                    kdfContextSizeL1, ref kdfContextFlagL1,
                    null, 0,
                    l1KeyDiff, l1Key,
                    RootKey.KdsRootKeyDataSizeDefault, 0);

                if (errCode != 0)
                    throw new Exception(
                        $"{nameof(ClientComputeL2Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");
            }

            if ((msdsManagedPasswordIdBytes == null || gke.L1Index <= msdsManagedPasswordId.L1Index) &&
                gke.CbL2Key != 0)
                l1Key = l2Key;

            if (l2KeyDiff > 0)
            {
                long something;
                if (msdsManagedPasswordIdBytes == null)
                    something = gke.L1Index;
                else
                    something = msdsManagedPasswordId.L1Index;

                errCode = KdsCli.GenerateKDFContext(
                    rootKeyGuid, gke.L0Index,
                    something, newL2KeyId,
                    2,
                    out var kdfContextL2,
                    out var kdfContextSizeL2,
                    out var kdfContextFlagL2);

                if (errCode != 0)
                    throw new Exception(
                        $"{nameof(ClientComputeL2Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");


                var kdfContextArrL2 = new byte[kdfContextSizeL2];
                Marshal.Copy(kdfContextL2, kdfContextArrL2, 0, kdfContextSizeL2);

                if (l2Key == null)
                    l2Key = new byte[RootKey.KdsRootKeyDataSizeDefault];

                errCode = KdsCli.GenerateDerivedKey(
                    kdfAlgorithmId, kdfParam,
                    gke.CbKdfParameters, l1Key,
                    64, kdfContextArrL2,
                    kdfContextSizeL2, ref kdfContextFlagL2,
                    null, 0,
                    l2KeyDiff, l2Key,
                    RootKey.KdsRootKeyDataSizeDefault, 0);

                if (errCode != 0)
                    throw new Exception(
                        $"{nameof(ClientComputeL2Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");
            }
        }

        private static byte[] GenerateGmsaPassowrd(
            GroupKeyEnvelope gke,
            int gkeSize,
            byte[] msdsManagedPasswordId,
            byte[] sid,
            IntPtr outOpt,
            IntPtr outOptSize,
            int pwdBlobSize)
        {
            byte[] kdfParam = null;
            int newL1KeyId = 0, newL2KeyId = 0, l1KeyDiff = 0, l2KeyDiff = 0, flag = 0;
            var labelStr = "GMSA PASSWORD\x0";
            var label = Encoding.Unicode.GetBytes(labelStr);
            var pwdBlob = new byte[pwdBlobSize];

            ParseSidKeyResult(
                gke, gkeSize,
                msdsManagedPasswordId,
                out var l1Key, ref l1KeyDiff, ref newL1KeyId,
                out var l2Key, ref l2KeyDiff, ref newL2KeyId,
                out var publicKey);

            if (l1KeyDiff > 0 || l2KeyDiff > 0)
                ClientComputeL2Key(gke, msdsManagedPasswordId, gke.KdfAlgorithm, l1Key, ref l2Key, l1KeyDiff,
                    newL1KeyId, l2KeyDiff, newL2KeyId);
            if (gke.CbKdfParameters > 0) kdfParam = gke.KdfParameters;

            var errCode = KdsCli.GenerateDerivedKey(
                gke.KdfAlgorithm, kdfParam,
                gke.CbKdfParameters, l2Key,
                64, sid,
                sid.Length,
                ref flag,
                label, 28,
                1,
                pwdBlob, pwdBlobSize,
                0); // 28 is hardcoded in the dll, should be label.Length

            if (errCode != 0)
                throw new Exception(
                    $"{nameof(GenerateGmsaPassowrd)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");

            return pwdBlob;
        }
    }
}