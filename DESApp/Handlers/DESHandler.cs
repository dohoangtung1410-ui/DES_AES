using System;
using System.Text;
using DESApp.Services;

namespace DESApp.Handlers
{
    public class DesHandler : IEncryptionHandler
    {
        public string AlgorithmName => "DES";
        
        public string GetKeyHint() => "DES: 8 bytes";

        public byte[] Encrypt(byte[] plaintext, byte[] key, Encoding encoder, StringBuilder processSb)
        {
            processSb.AppendLine($"📝 Plaintext đã nhập: {Encoding.UTF8.GetString(plaintext)}");
            processSb.AppendLine($"🔑 Key đã nhập: {Convert.ToBase64String(key)}");
            processSb.AppendLine();
            processSb.AppendLine($"Block size (bytes): 8");

            // Key info
            if (key.Length < 8)
            {
                processSb.AppendLine($"**Key adjustment note**: Input key with {key.Length} bytes — TỰ ĐỘNG lặp (repeat) để đủ 8 bytes.");
                key = ResizeKey(key, 8);
            }
            processSb.AppendLine($"Key length: {key.Length} bytes");
            processSb.AppendLine();

            // 1. Plaintext info
            processSb.AppendLine("1️⃣ Plaintext → bytes:");
            processSb.AppendLine($"   Length: {plaintext.Length} bytes");
            processSb.AppendLine($"   Bytes (hex): {BitConverter.ToString(plaintext).Replace("-", " ")}");
            processSb.AppendLine();

            // 2. PKCS7 Padding
            int padLength = 8 - (plaintext.Length % 8);
            if (padLength == 0) padLength = 8;

            byte[] padded = new byte[plaintext.Length + padLength];
            SafeBufferCopy(plaintext, padded, 0, 0, plaintext.Length);
            
            for (int i = plaintext.Length; i < padded.Length; i++)
            {
                padded[i] = (byte)padLength;
            }

            processSb.AppendLine($"2️⃣ PKCS#7 padding (pad length = {padLength}):");
            processSb.AppendLine($"   Padded length: {padded.Length} bytes");
            processSb.AppendLine($"   Padded bytes (hex): {BitConverter.ToString(padded).Replace("-", " ")}");
            processSb.AppendLine();

            // 3. Split into blocks and process each
            int blockCount = padded.Length / 8;
            processSb.AppendLine($"3️⃣ Chia bản rõ thành {blockCount} block (64-bit mỗi block)");
            processSb.AppendLine();

            byte[] finalCipher = new byte[padded.Length];

            for (int blockIndex = 0; blockIndex < blockCount; blockIndex++)
            {
                int sourceIndex = blockIndex * 8;
                
                if (!CheckBounds(padded, sourceIndex, 8))
                {
                    processSb.AppendLine($"❌ LỖI: Block {blockIndex + 1} vượt quá giới hạn mảng!");
                    throw new ArgumentException("Block vượt quá giới hạn mảng");
                }

                byte[] block = new byte[8];
                SafeBufferCopy(padded, block, sourceIndex, 0, 8);

                processSb.AppendLine($"--- 🧩 BLOCK {blockIndex + 1} ---");
                processSb.AppendLine($"Input Block (hex): {BitConverter.ToString(block).Replace("-", " ")}");

                // Get DES simulation details
                string desProcess = CryptoSimulators.SimulateDesEncryptBlock(block, key);
                processSb.AppendLine(desProcess);

                // Actually encrypt the block
                byte[] encryptedBlock = CryptoSimulators.PublicDesEncryptBlockBytes(block, key);
                
                if (CheckBounds(finalCipher, sourceIndex, 8))
                {
                    SafeBufferCopy(encryptedBlock, finalCipher, 0, sourceIndex, 8);
                }
                else
                {
                    processSb.AppendLine($"❌ LỖI: Không thể sao chép kết quả block {blockIndex + 1}");
                    throw new ArgumentException("Không thể sao chép kết quả");
                }

                processSb.AppendLine();
            }

            return finalCipher;
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] key, Encoding encoder, StringBuilder processSb)
        {
            processSb.AppendLine($"📝 Ciphertext đã nhập: {Convert.ToBase64String(ciphertext)}");
            processSb.AppendLine($"🔑 Key đã nhập: {Convert.ToBase64String(key)}");
            processSb.AppendLine();
            processSb.AppendLine($"Block size (bytes): 8");

            // Key info
            if (key.Length < 8)
            {
                processSb.AppendLine($"**Key adjustment note**: Input key with {key.Length} bytes — TỰ ĐỘNG lặp (repeat) để đủ 8 bytes.");
                key = ResizeKey(key, 8);
            }
            processSb.AppendLine($"Key length: {key.Length} bytes");
            processSb.AppendLine();

            // 1. Ciphertext info
            processSb.AppendLine("1️⃣ Ciphertext → bytes:");
            processSb.AppendLine($"   Length: {ciphertext.Length} bytes");
            processSb.AppendLine($"   Bytes (hex): {BitConverter.ToString(ciphertext).Replace("-", " ")}");
            processSb.AppendLine();

            // 2. Split into blocks and process each
            int blockCount = ciphertext.Length / 8;
            processSb.AppendLine($"2️⃣ Chia bản mã thành {blockCount} block (64-bit mỗi block)");
            processSb.AppendLine();

            if (ciphertext.Length % 8 != 0)
            {
                throw new ArgumentException("Ciphertext length không phải bội số của 8!");
            }

            byte[] finalPlain = new byte[ciphertext.Length];

            for (int blockIndex = 0; blockIndex < blockCount; blockIndex++)
            {
                int sourceIndex = blockIndex * 8;

                if (!CheckBounds(ciphertext, sourceIndex, 8))
                {
                    processSb.AppendLine($"❌ LỖI: Block {blockIndex + 1} vượt quá giới hạn dữ liệu!");
                    throw new ArgumentException("Block vượt quá giới hạn dữ liệu");
                }

                byte[] block = new byte[8];
                SafeBufferCopy(ciphertext, block, sourceIndex, 0, 8);

                processSb.AppendLine($"--- 🧩 BLOCK {blockIndex + 1} ---");
                processSb.AppendLine($"Input Block (hex): {BitConverter.ToString(block).Replace("-", " ")}");

                // Get DES decryption simulation details
                string desProcess = CryptoSimulators.SimulateDesDecryptBlock(block, key);
                processSb.AppendLine(desProcess);

                // Actually decrypt the block
                byte[] decryptedBlock = CryptoSimulators.PublicDesDecryptBlockBytes(block, key);
                
                if (CheckBounds(finalPlain, sourceIndex, 8))
                {
                    SafeBufferCopy(decryptedBlock, finalPlain, 0, sourceIndex, 8);
                }
                else
                {
                    processSb.AppendLine($"❌ LỖI: Không thể sao chép kết quả block {blockIndex + 1}");
                    throw new ArgumentException("Không thể sao chép kết quả");
                }

                processSb.AppendLine();
            }

            // Remove padding
            if (finalPlain.Length == 0)
                return finalPlain;

            int padLength = finalPlain[finalPlain.Length - 1];
            if (padLength > 0 && padLength <= 8 && padLength <= finalPlain.Length)
            {
                byte[] unpadded = new byte[finalPlain.Length - padLength];
                SafeBufferCopy(finalPlain, unpadded, 0, 0, unpadded.Length);
                return unpadded;
            }

            return finalPlain;
        }

        private byte[] ResizeKey(byte[] key, int desiredLength)
        {
            byte[] result = new byte[desiredLength];
            for (int i = 0; i < desiredLength; i++)
            {
                result[i] = key[i % key.Length];
            }
            return result;
        }

        private bool CheckBounds(byte[] array, int startIndex, int length)
        {
            return startIndex >= 0 && length >= 0 && (startIndex + length) <= array.Length;
        }

        private void SafeBufferCopy(byte[] source, byte[] destination, int sourceIndex, int destinationIndex, int length)
        {
            if (!CheckBounds(source, sourceIndex, length) || !CheckBounds(destination, destinationIndex, length))
            {
                throw new ArgumentException("Buffer copy out of bounds");
            }
            Buffer.BlockCopy(source, sourceIndex, destination, destinationIndex, length);
        }
    }
}