using System.Security.Cryptography;

namespace DllSidecar.Core.Helpers;

public static class XorCryptor
{
    public static byte[] Encrypt(string plaintext, byte[] key)
    {
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key must contain at least one byte.", nameof(key));
        var result = new byte[plaintext.Length];
        for (int i = 0; i < plaintext.Length; i++)
            result[i] = (byte)(plaintext[i] ^ key[i % key.Length]);
        return result;
    }

    public static byte[] RandomKey(int length)
    {
        if (length < 1) throw new ArgumentOutOfRangeException(nameof(length));
        return RandomNumberGenerator.GetBytes(length);
    }

    public static string ToHexArray(byte[] data)
        => string.Join(", ", data.Select(b => $"0x{b:X2}"));
}
