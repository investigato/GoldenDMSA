namespace GoldendMSA
{
    /// <summary>
    ///     This class comes from ComputeL0Key function inside KdsSvc.dll.
    ///     It takes a RootKey structure, adds a field in the begining (L0KeyID) and modifies the KdsRootKeyData field with a
    ///     value from GenerateDerivedKey.
    /// </summary>
    public sealed class L0Key : RootKey
    {
        public L0Key(RootKey rootKey, long l0KeyId, byte[] derivedKey)
            : base(rootKey)
        {
            L0KeyId = l0KeyId;
            KdsRootKeyData = derivedKey;
        }

        public long L0KeyId { get; set; }
    }
}