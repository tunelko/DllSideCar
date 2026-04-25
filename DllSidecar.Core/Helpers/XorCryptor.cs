namespace DllSidecar.Core.Helpers;

public static class XorCryptor
{
    public static byte[] Encrypt(string plaintext, byte key)
    {
        var result = new byte[plaintext.Length];
        for (int i = 0; i < plaintext.Length; i++)
            result[i] = (byte)(plaintext[i] ^ key);
        return result;
    }

    public static string ToHexArray(byte[] data)
        => string.Join(", ", data.Select(b => $"0x{b:X2}"));
}
