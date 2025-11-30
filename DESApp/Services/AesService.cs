using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

namespace DESApp.Services
{
    public class AesService : ICryptoService
    {
        private static readonly int KeySizeBits = 256; // AES-256
        private static readonly int IvSizeBytes = 16;  // 128-bit block size
        public List<string> ProcessSteps { get; private set; } = new(); // lưu quá trình mô phỏng

        // ============================================================
        // 🔐 1. MÃ HÓA
        // ============================================================
        public string Encrypt(string plainText, byte[] key, Encoding encoding)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (encoding == null) throw new ArgumentNullException(nameof(encoding));
            if (key.Length != KeySizeBits / 8)
                throw new ArgumentException("AES-256 requires a 32-byte (256-bit) key.", nameof(key));

            byte[] plainBytes = encoding.GetBytes(plainText ?? string.Empty);

            using var aes = Aes.Create();
            aes.KeySize = KeySizeBits;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateIV();

            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length);

            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
            {
                cs.Write(plainBytes, 0, plainBytes.Length);
                cs.FlushFinalBlock();
            }

            // Hiển thị quá trình mô phỏng
            SimulateProcess(plainBytes, key, aes.IV, true);

            return Convert.ToBase64String(ms.ToArray());
        }

        // ============================================================
        // 🔓 2. GIẢI MÃ
        // ============================================================
        public string Decrypt(string base64Cipher, byte[] key, Encoding encoding)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (encoding == null) throw new ArgumentNullException(nameof(encoding));
            if (base64Cipher == null) throw new ArgumentNullException(nameof(base64Cipher));
            if (key.Length != KeySizeBits / 8)
                throw new ArgumentException("AES-256 requires a 32-byte (256-bit) key.", nameof(key));

            byte[] fullCipher = Convert.FromBase64String(base64Cipher);
            if (fullCipher.Length < IvSizeBytes)
                throw new CryptographicException("Cipher text is too short to contain IV.");

            byte[] iv = new byte[IvSizeBytes];
            Buffer.BlockCopy(fullCipher, 0, iv, 0, IvSizeBytes);

            byte[] cipherBytes = new byte[fullCipher.Length - IvSizeBytes];
            Buffer.BlockCopy(fullCipher, IvSizeBytes, cipherBytes, 0, cipherBytes.Length);

            using var aes = Aes.Create();
            aes.KeySize = KeySizeBits;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(new MemoryStream(cipherBytes), aes.CreateDecryptor(), CryptoStreamMode.Read))
            {
                cs.CopyTo(ms);
            }

            byte[] plainBytes = ms.ToArray();

            // Hiển thị mô phỏng giải mã
            SimulateProcess(plainBytes, key, iv, false);

            return encoding.GetString(plainBytes);
        }

        // ============================================================
        // 🧩 3. SINH KHÓA NGẪU NHIÊN
        // ============================================================
        public static byte[] GenerateRandomKey()
        {
            using var rng = RandomNumberGenerator.Create();
            byte[] key = new byte[32]; // 256-bit
            rng.GetBytes(key);
            return key;
        }

        public static string GenerateRandomKeyBase64()
        {
            var key = GenerateRandomKey();
            return Convert.ToBase64String(key);
        }

        // ============================================================
        // 🧠 4. MÔ PHỎNG QUÁ TRÌNH MÃ HÓA/GIẢI MÃ
        // ============================================================
        private void SimulateProcess(byte[] data, byte[] key, byte[] iv, bool isEncrypt)
        {
            ProcessSteps.Clear();
            ProcessSteps.Add(isEncrypt ? "=== AES-256 ENCRYPTION PROCESS ===" : "=== AES-256 DECRYPTION PROCESS ===");

            ProcessSteps.Add($"Key (256-bit): {BitConverter.ToString(key).Replace("-", " ")}");
            ProcessSteps.Add($"IV (128-bit): {BitConverter.ToString(iv).Replace("-", " ")}");

            if (isEncrypt)
            {
                ProcessSteps.Add("1️⃣ SubBytes: Thay thế từng byte bằng S-Box.");
                ProcessSteps.Add("2️⃣ ShiftRows: Dịch trái từng hàng trong ma trận trạng thái.");
                ProcessSteps.Add("3️⃣ MixColumns: Kết hợp các byte trong mỗi cột (trừ vòng cuối).");
                ProcessSteps.Add("4️⃣ AddRoundKey: XOR với round key.");
                ProcessSteps.Add("➡️ Lặp lại 14 vòng cho AES-256.");
                ProcessSteps.Add($"Cipher (mã hóa xong): {BitConverter.ToString(data).Replace("-", " ")}");
            }
            else
            {
                ProcessSteps.Add("1️⃣ AddRoundKey: XOR với round key của vòng cuối.");
                ProcessSteps.Add("2️⃣ InvMixColumns, InvShiftRows, InvSubBytes: thực hiện ngược quá trình.");
                ProcessSteps.Add("➡️ Lặp lại 14 vòng ngược để khôi phục dữ liệu gốc.");
                ProcessSteps.Add($"Plain (giải mã xong): {BitConverter.ToString(data).Replace("-", " ")}");
            }

            ProcessSteps.Add("=== PROCESS COMPLETE ===");
        }

        public string GetProcessText()
        {
            return string.Join(Environment.NewLine, ProcessSteps);
        }
    }
}
