using System;
using System.Linq;
using System.Runtime.InteropServices;
using GoldendMSA.Unsafe;

namespace GoldendMSA
{
    public static class GetKey
    {
        public static void GetSidKeyLocal(
            byte[] securityDescriptor,
            int sDSize,
            RootKey rootKey,
            int l0KeyId,
            int l1KeyId,
            int l2KeyId,
            int accessCheckFailed,
            string domainName,
            string forestName,
            out GroupKeyEnvelope gke,
            out int gkeSize)
        {
            var l0Key = ComputeL0Key(rootKey, l0KeyId);

            ComputeSidPrivateKey(
                l0Key,
                securityDescriptor, sDSize,
                l1KeyId,
                l2KeyId,
                accessCheckFailed,
                out var l1Key,
                out var l2Key);

            // There is another function that is being called if AccessCheckFailed != 0  which is ComputePublicKey - should not be relevant for us
            var guidExists =
                rootKey.Cn == Guid.Empty ? 0 : 1; // we should get if we have this root key id.

            FormatReturnBlob(
                l0Key,
                guidExists,
                l1Key, l1KeyId,
                l2Key, l2KeyId,
                null, 0,
                domainName, forestName,
                out gke,
                out gkeSize);
        }

        private static L0Key ComputeL0Key(
            RootKey rootKey,
            int l0KeyId)
        {
            var rootKeyGuid = rootKey.Cn.ToByteArray();

            var errCode = KdsCli.GenerateKDFContext(
                rootKeyGuid, l0KeyId,
                0xffffffff, 0xffffffff,
                0,
                out var kdfContextPtr,
                out var kdfContextSize,
                out var kdfContextFlag);

            if (errCode != 0)
                throw new Exception(
                    $"{nameof(ComputeL0Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");

            var kdfContext = new byte[kdfContextSize];
            Marshal.Copy(kdfContextPtr, kdfContext, 0, kdfContextSize);

            var generateDerivedKey = new byte[RootKey.KdsRootKeyDataSizeDefault];
            var labelSize = 0;

            errCode = KdsCli.GenerateDerivedKey(
                rootKey.MsKdsKdfAlgorithmId,
                rootKey.MsKdsKdfParam,
                rootKey.KdfParamSize,
                rootKey.KdsRootKeyData,
                rootKey.KdsRootKeyDataSize,
                kdfContext, kdfContextSize,
                ref kdfContextFlag,
                null, labelSize, // this will always be null
                1, generateDerivedKey,
                RootKey.KdsRootKeyDataSizeDefault, 0);

            if (errCode != 0)
                throw new Exception(
                    $"{nameof(ComputeL0Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");

            var l0Key = new L0Key(rootKey, l0KeyId, generateDerivedKey);

            return l0Key;
        }

        private static void GenerateL1Key(
            byte[] securityDescriptor,
            int sDSize,
            L0Key l0Key,
            int l1KeyId,
            out byte[] derivedKey,
            out byte[] derivedKey2)
        {
            var rootKeyGuid = l0Key.Cn.ToByteArray();
            derivedKey = new byte[RootKey.KdsRootKeyDataSizeDefault];
            derivedKey2 = null;

            var errCode = KdsCli.GenerateKDFContext(
                rootKeyGuid, (int)l0Key.L0KeyId,
                0x1f, 0xffffffff, 1,
                out var kdfContextPtr,
                out var kdfContextSize,
                out var kdfContextFlag);

            if (errCode != 0)
                throw new Exception(
                    $"{nameof(GenerateL1Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");

            var kdfContextModifiedSize = kdfContextSize + sDSize;
            var kdfContextModified = new byte[kdfContextModifiedSize];

            Marshal.Copy(kdfContextPtr, kdfContextModified, 0, kdfContextSize);
            Array.Copy(securityDescriptor, 0, kdfContextModified, kdfContextSize, sDSize);

            errCode = KdsCli.GenerateDerivedKey(
                l0Key.MsKdsKdfAlgorithmId,
                l0Key.MsKdsKdfParam,
                l0Key.KdfParamSize,
                l0Key.KdsRootKeyData,
                64,
                kdfContextModified, kdfContextModifiedSize,
                ref kdfContextFlag,
                null, 0, 1,
                derivedKey,
                RootKey.KdsRootKeyDataSizeDefault, 0);

            if (errCode != 0)
                throw new Exception(
                    $"{nameof(GenerateL1Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");

            // This section will be used if 0<L1KeyID<31
            byte[] generatedDerivedKey;
            var kdfContext = new byte[kdfContextSize];
            Marshal.Copy(kdfContextPtr, kdfContext, 0, kdfContextSize);

            if (l1KeyId != 31)
            {
                kdfContext[kdfContextFlag] = (byte)(kdfContext[kdfContextFlag] - 1);
                generatedDerivedKey = derivedKey.ToArray();

                errCode = KdsCli.GenerateDerivedKey(
                    l0Key.MsKdsKdfAlgorithmId, l0Key.MsKdsKdfParam,
                    l0Key.KdfParamSize, generatedDerivedKey,
                    64, kdfContext,
                    kdfContextSize, ref kdfContextFlag,
                    null, 0,
                    31 - l1KeyId, derivedKey,
                    RootKey.KdsRootKeyDataSizeDefault, 0);

                if (errCode != 0)
                    throw new Exception(
                        $"{nameof(GenerateL1Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");
            }

            if (l1KeyId > 0)
            {
                kdfContext[kdfContextFlag] = (byte)(l1KeyId - 1);
                derivedKey2 = new byte[RootKey.KdsRootKeyDataSizeDefault];
                generatedDerivedKey = derivedKey.ToArray();

                errCode = KdsCli.GenerateDerivedKey(
                    l0Key.MsKdsKdfAlgorithmId, l0Key.MsKdsKdfParam,
                    l0Key.KdfParamSize, generatedDerivedKey,
                    64, kdfContext,
                    kdfContextSize, ref kdfContextFlag,
                    null, 0,
                    1, derivedKey2,
                    RootKey.KdsRootKeyDataSizeDefault, 0);

                if (errCode != 0)
                    throw new Exception(
                        $"{nameof(GenerateL1Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");
            }
        }

        private static void GenerateL2Key(
            L0Key l0Key,
            byte[] l1DerivedKey,
            int l1KeyId,
            int l2KeyId,
            out int flagKdfContext,
            out byte[] derivedKey)
        {
            var rootKeyGuid = l0Key.Cn.ToByteArray();

            derivedKey = new byte[RootKey.KdsRootKeyDataSizeDefault];

            var errCode = KdsCli.GenerateKDFContext(
                rootKeyGuid, (int)l0Key.L0KeyId,
                l1KeyId, 0x1f,
                2,
                out var kdfContextPtr,
                out var kdfContextSize,
                out flagKdfContext);

            if (errCode != 0)
                throw new Exception(
                    $"{nameof(GenerateL2Key)}:: {nameof(KdsCli.GenerateKDFContext)} failed with error code {errCode}");

            var kdfContext = new byte[kdfContextSize];
            Marshal.Copy(kdfContextPtr, kdfContext, 0, kdfContextSize);

            var someFlag = 32 - l2KeyId;

            errCode = KdsCli.GenerateDerivedKey(
                l0Key.MsKdsKdfAlgorithmId, l0Key.MsKdsKdfParam,
                l0Key.KdfParamSize, l1DerivedKey,
                64, kdfContext,
                kdfContextSize, ref flagKdfContext,
                null, 0,
                someFlag, derivedKey,
                RootKey.KdsRootKeyDataSizeDefault, 0);

            if (errCode != 0)
                throw new Exception(
                    $"{nameof(GenerateL2Key)}:: {nameof(KdsCli.GenerateDerivedKey)} failed with error code {errCode}");
        }

        private static void ComputeSidPrivateKey(
            L0Key l0Key,
            byte[] securityDescriptor,
            int sDSize,
            int l1KeyId,
            int l2KeyId,
            int accessCheckFailed,
            out byte[] l1Key,
            out byte[] l2Key)
        {
            GenerateL1Key(securityDescriptor, sDSize, l0Key, l1KeyId, out var l1KeyFirst, out var l2KeySecond);

            if (l2KeyId == 31 && accessCheckFailed == 0)
            {
                l1Key = l1KeyFirst.ToArray();
                l2Key = null;
                return;
            }

            GenerateL2Key(l0Key, l1KeyFirst, l1KeyId, l2KeyId, out var flag, out l2Key);

            if (l1KeyId > 0)
                l1Key = l2KeySecond.ToArray();
            else
                l1Key = null;
        }

        private static void FormatReturnBlob(
            L0Key l0Key,
            int guidExists,
            byte[] l1Key,
            int l1KeyId,
            byte[] l2Key,
            int l2KeyId,
            byte[] publicKey,
            int publicKeySize,
            string domainName,
            string forestName,
            out GroupKeyEnvelope gke,
            out int gkeSize
        )
        {
            gke = new GroupKeyEnvelope
            {
                Version = 1,
                Reserved = 1263748171,
                L0Index = (int)l0Key.L0KeyId,
                L1Index = l1KeyId,
                L2Index = l2KeyId,
                RootKeyIdentifier = l0Key.Cn,
                CbKdfAlgorithm = l0Key.MsKdsKdfAlgorithmId.Length * 2 + 2,
                CbKdfParameters = l0Key.KdfParamSize,
                CbSecretAgreementAlgorithm = l0Key.KdsSecretAgreementAlgorithmId.Length * 2 + 2,
                CbSecretAgreementParameters = l0Key.SecretAlgoritmParamSize,
                PrivateKeyLength = l0Key.PrivateKeyLength,
                PublicKeyLength = l0Key.PublicKeyLength,
                CbDomainName = domainName.Length * 2 + 2,
                CbForestName = forestName.Length * 2 + 2,
                KdfAlgorithm = l0Key.MsKdsKdfAlgorithmId,
                KdfParameters = l0Key.MsKdsKdfParam.ToArray(),
                SecretAgreementAlgorithm = l0Key.KdsSecretAgreementAlgorithmId,
                SecretAgreementParameters = l0Key.KdsSecretAgreementParam.ToArray(),
                DomainName = domainName,
                ForestName = forestName
            };

            var firstKeySize = 64;
            var secondKeySize = 64;

            if (publicKey != null)
            {
                secondKeySize = publicKeySize;
                firstKeySize = 0;
            }
            else if (l2KeyId == 31)
            {
                secondKeySize = 0;
            }
            else
            {
                if (l1KeyId == 0) firstKeySize = 0;
            }

            gke.CbL1Key = firstKeySize;
            gke.CbL2Key = secondKeySize;
            var isPublicKey = 0;
            gke.L1Key = null;
            gke.L2Key = null;
            if (publicKey != null) isPublicKey |= 1;
            isPublicKey |= 2;
            gke.IsPublicKey = isPublicKey;

            if (firstKeySize != 0) gke.L1Key = l1Key.ToArray();

            if (secondKeySize != 0)
            {
                if (publicKey != null)
                    gke.L2Key = publicKey.ToArray();
                else
                    gke.L2Key = l2Key.ToArray();
            }

            gkeSize = 80 + gke.CbKdfAlgorithm +
                      gke.CbKdfParameters + gke.CbSecretAgreementAlgorithm +
                      gke.CbSecretAgreementParameters +
                      gke.CbDomainName + gke.CbForestName +
                      gke.CbL1Key + gke.CbL2Key;
        }
    }
}