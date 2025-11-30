using System.Security.Cryptography;

namespace DESApp.Services
{
    public static class Aes192Helper
    {
        public static byte[] EncryptBlock(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.KeySize = 192;
            aes.Key = key.Length >= 24 ? key[..24] : PadKey(key, 24);
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        public static byte[] DecryptBlock(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.KeySize = 192;
            aes.Key = key.Length >= 24 ? key[..24] : PadKey(key, 24);
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }

        private static byte[] PadKey(byte[] key, int length)
        {
            byte[] padded = new byte[length];
            for (int i = 0; i < length; i++) padded[i] = key[i % key.Length];
            return padded;
        }
    }
}
