using System;
using System.Text;
using System.Security.Cryptography;

namespace DESApp.Services
{
    public class Aes192Service : ICryptoService
    {
        public string Encrypt(string plainText, byte[] key, Encoding encoding)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentException("Plain text cannot be null or empty", nameof(plainText));

            var plainBytes = encoding.GetBytes(plainText);
            int blockCount = (int)Math.Ceiling(plainBytes.Length / 16.0);
            byte[] padded = new byte[blockCount * 16];
            Array.Copy(plainBytes, padded, plainBytes.Length);

            using var ms = new System.IO.MemoryStream();
            for (int i = 0; i < blockCount; i++)
            {
                var block = new byte[16];
                Array.Copy(padded, i * 16, block, 0, 16);
                var encrypted = Aes192Helper.EncryptBlock(block, key);
                ms.Write(encrypted, 0, encrypted.Length);
            }

            return Convert.ToBase64String(ms.ToArray());
        }

        public string Decrypt(string base64Package, byte[] key, Encoding encoding)
        {
            if (string.IsNullOrEmpty(base64Package))
                throw new ArgumentException("Cipher text cannot be null or empty", nameof(base64Package));

            var cipherBytes = Convert.FromBase64String(base64Package);
            if (cipherBytes.Length % 16 != 0)
                throw new ArgumentException("Cipher length must be multiple of 16 bytes", nameof(base64Package));

            using var ms = new System.IO.MemoryStream();
            for (int i = 0; i < cipherBytes.Length / 16; i++)
            {
                var block = new byte[16];
                Array.Copy(cipherBytes, i * 16, block, 0, 16);
                var decrypted = Aes192Helper.DecryptBlock(block, key);
                ms.Write(decrypted, 0, decrypted.Length);
            }

            var raw = ms.ToArray();
            int trim = raw.Length;
            while (trim > 0 && raw[trim - 1] == 0) trim--;
            return encoding.GetString(raw, 0, trim);
        }
    }
}
