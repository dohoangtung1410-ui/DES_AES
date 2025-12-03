using System;
using System.Text;
using System.Security.Cryptography;
using System.Linq;
using System.Collections.Generic;
using DESApp.Data;

namespace DESApp.Handlers
{
    public class Aes128Handler : IEncryptionHandler
    {
        public string AlgorithmName => "AES-128";

        public string GetKeyHint() => "AES-128: Nhập bao nhiêu ký tự cũng được, tự động thêm '.' nếu thiếu";

        // --- S-box (AES) ---
        private static readonly byte[] SBOX = new byte[256]
        {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0x93,0x72,0x60,
    0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,
    0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,
    0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,
    0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,
    0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,
    0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,
    0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,
    0xbb,0x16,0x7d,0x24,0x3b,0x1c,0x5f,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,
    0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,
    0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,
    0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,
    0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,
    0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,
    0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,
        };

        // Inverse S-box (AES)
        private static readonly byte[] INV_SBOX = new byte[256]
        {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
        };

        // Rcon (AES) - note: first element unused, start at index 1
        private static readonly byte[] RCON = new byte[11]
        {
            0x00, // placeholder for index 0
            0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
        };

        public byte[] Encrypt(byte[] plaintext, byte[] key, Encoding encoder, StringBuilder processSb)
        {
            var startTime = DateTime.Now;

            string plaintextStr = encoder.GetString(plaintext);
            // plaintextStr = DecodeEscapedString(plaintextStr); // 👈 xử lý escape
            plaintext = encoder.GetBytes(plaintextStr);

            processSb.AppendLine("=== QUÁ TRÌNH MÃ HÓA AES-128 ===");
            processSb.AppendLine($"Encoding: {encoder.EncodingName}");
            processSb.AppendLine($"Key Length: 16 bytes (128 bits)");
            processSb.AppendLine($"📝 Plaintext đã nhập: {encoder.GetString(plaintext)}");
            processSb.AppendLine($"🔑 Key đã nhập: {encoder.GetString(key)}");
            processSb.AppendLine();

            // ==================== Tiền xử lý bản rõ ====================
            processSb.AppendLine("===================== TIỀN XỬ LÝ BẢN RÕ ====================");
            List<byte[]> plaintextSegments = PreprocessPlaintext(plaintext, processSb, encoder);
            processSb.AppendLine();

            // ==================== Tiền xử lý khóa ====================
            processSb.AppendLine("===================== TIỀN XỬ LÝ KHÓA ====================");
            byte[] processedKey = PreprocessKey(key, 16, encoder, processSb);
            processSb.AppendLine();

            // ==================== Quá trình sinh khóa ====================
            processSb.AppendLine("===================== QUÁ TRÌNH SINH KHÓA ====================");
            // Sinh round keys thực tế và hiển thị chi tiết
            byte[][] roundKeys = KeyExpansion(processedKey, processSb);
            processSb.AppendLine();

            byte[] encryptedResult = new byte[0];

            // ==================== Mã hóa từng đoạn ====================
            for (int segmentIndex = 0; segmentIndex < plaintextSegments.Count; segmentIndex++)
            {
                processSb.AppendLine($"===================== MÃ HÓA ĐOẠN {segmentIndex + 1} ====================");

                byte[] segment = plaintextSegments[segmentIndex];

                // 1. Plaintext info
                processSb.AppendLine($"1️⃣ Plaintext đoạn {segmentIndex + 1} → bytes:");
                processSb.AppendLine($"   Length: {segment.Length} bytes");
                processSb.AppendLine($"   Bytes (hex): {BitConverter.ToString(segment).Replace("-", " ")}");
                processSb.AppendLine($"   Bytes (binary): {BytesToBinaryString(segment)}");
                processSb.AppendLine();

                // 2. Padding info
                processSb.AppendLine($"2️⃣ PKCS7 padding đoạn {segmentIndex + 1}:");
                processSb.AppendLine($"   Input length: {segment.Length} bytes");
                int paddedLength = ((segment.Length / 16) + 1) * 16;
                int padBytes = paddedLength - segment.Length;
                processSb.AppendLine($"   Padded length: {paddedLength} bytes");
                processSb.AppendLine($"   Pad bytes: {padBytes} bytes (value: 0x{padBytes:X2})");

                // Tạo padded data
                byte[] paddedData = new byte[paddedLength];
                Array.Copy(segment, 0, paddedData, 0, segment.Length);
                for (int i = segment.Length; i < paddedLength; i++)
                {
                    paddedData[i] = (byte)padBytes;
                }
                processSb.AppendLine($"   Padded data (hex): {BitConverter.ToString(paddedData).Replace("-", " ")}");
                processSb.AppendLine();

                // 3. Chia blocks
                int blockCount = paddedData.Length / 16;
                processSb.AppendLine($"3️⃣ Chia bản rõ thành {blockCount} block (128-bit mỗi block)");
                processSb.AppendLine();

                // 4. Mã hóa với chi tiết từng bước
                byte[] encryptedSegment = EncryptAes128StepByStep(paddedData, processedKey, roundKeys, processSb, segmentIndex + 1);

                // Thêm vào kết quả
                byte[] temp = new byte[encryptedResult.Length + encryptedSegment.Length];
                Array.Copy(encryptedResult, 0, temp, 0, encryptedResult.Length);
                Array.Copy(encryptedSegment, 0, temp, encryptedResult.Length, encryptedSegment.Length);
                encryptedResult = temp;

                processSb.AppendLine($"✅ Mã đoạn {segmentIndex + 1}: {BitConverter.ToString(encryptedSegment).Replace("-", " ")}");
                processSb.AppendLine();


            }

            var endTime = DateTime.Now;
            var duration = (endTime - startTime).TotalMilliseconds;

            processSb.AppendLine("===================== BẢN MÃ HÓA ====================");
            for (int i = 0; i < plaintextSegments.Count; i++)
            {
                int startIndex = i * (plaintextSegments[i].Length + (16 - (plaintextSegments[i].Length % 16)) % 16);
                int length = (plaintextSegments[i].Length + (16 - (plaintextSegments[i].Length % 16)) % 16);
                byte[] segmentCipher = new byte[length];
                Array.Copy(encryptedResult, startIndex, segmentCipher, 0, length);
                processSb.AppendLine($"Mã đoạn {i + 1}: {BitConverter.ToString(segmentCipher).Replace("-", " ")}");
            }
            processSb.AppendLine($"Bản mã hoá: {BitConverter.ToString(encryptedResult).Replace("-", " ")}");
            processSb.AppendLine();

            var record = new BenchmarkRecord
            {
                Algorithm = this.AlgorithmName,  // Sử dụng thuộc tính AlgorithmName
                Operation = "Encrypt",
                KeySize = key.Length,
                DataSize = plaintext.Length,
                TimeMs = duration,  // Sử dụng duration đã tính
                Timestamp = DateTime.Now
            };

            // Đảm bảo đã thêm using DESApp.Data; ở đầu file
            BenchmarkDatabase.Insert(record);

            processSb.AppendLine("=== KẾT THÚC MÃ HÓA AES-128 ===");
            processSb.AppendLine($"⏱ Encryption completed in {duration}ms");
            processSb.AppendLine();
            processSb.AppendLine($"→ Cipher (Base64): {Convert.ToBase64String(encryptedResult)}");

            return encryptedResult;
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] key, Encoding encoder, StringBuilder processSb)
        {
            var startTime = DateTime.Now;

            processSb.AppendLine("=== QUÁ TRÌNH GIẢI MÃ AES-128 ===");
            processSb.AppendLine($"Encoding: {encoder.EncodingName}");
            processSb.AppendLine($"Key Length: 16 bytes (128 bits)");
            processSb.AppendLine($"📝 Ciphertext đã nhập: {Convert.ToBase64String(ciphertext)}");
            processSb.AppendLine($"🔑 Key đã nhập: {encoder.GetString(key)}");
            processSb.AppendLine();

            // ==================== Tiền xử lý khóa ====================
            processSb.AppendLine("===================== TIỀN XỬ LÝ KHÓA ====================");
            byte[] processedKey = PreprocessKey(key, 16, encoder, processSb);
            processSb.AppendLine();

            // ==================== Quá trình sinh khóa ====================
            processSb.AppendLine("===================== QUÁ TRÌNH SINH KHÓA ====================");
            byte[][] roundKeys = KeyExpansion(processedKey, processSb);
            processSb.AppendLine();

            // ==================== Giải mã từng đoạn ====================
            processSb.AppendLine("===================== GIẢI MÃ TỪNG ĐOẠN ====================");

            // 1. Ciphertext info
            processSb.AppendLine("1️⃣ Ciphertext → bytes:");
            processSb.AppendLine($"   Length: {ciphertext.Length} bytes");
            processSb.AppendLine($"   Bytes (hex): {BitConverter.ToString(ciphertext).Replace("-", " ")}");
            processSb.AppendLine($"   Bytes (binary): {BytesToBinaryString(ciphertext)}");
            processSb.AppendLine();

            // 2. Chia blocks
            int blockCount = ciphertext.Length / 16;
            processSb.AppendLine($"2️⃣ Chia ciphertext thành {blockCount} block (128-bit mỗi block)");
            processSb.AppendLine();

            // 3. Giải mã với chi tiết từng bước
            byte[] decryptedData = DecryptAes128StepByStep(ciphertext, processedKey, roundKeys, processSb);

            var endTime = DateTime.Now;
            var duration = (endTime - startTime).TotalMilliseconds;

            BenchmarkDatabase.Insert(new BenchmarkRecord
            {
                Algorithm = "AES-128",
                Operation = "Encrypt",
                KeySize = 128,
                DataSize = ciphertext.Length,
                TimeMs = duration,
                Timestamp = DateTime.Now
            });

            processSb.AppendLine("=== KẾT THÚC GIẢI MÃ AES-128 ===");
            processSb.AppendLine($"⏱ Decryption completed in {duration}ms");
            processSb.AppendLine();
            processSb.AppendLine($"→ Plaintext: {Encoding.UTF8.GetString(decryptedData)}");

            return decryptedData;

        }

        private List<byte[]> PreprocessPlaintext(byte[] plaintext, StringBuilder sb, Encoding encoder)
        {
            List<byte[]> segments = new List<byte[]>();
            sb.AppendLine("====================TIEN XU BAN RO=================");
            sb.AppendLine("Ban ro chia lam cac doan sau:");
            sb.AppendLine();

            // Chuyển về string trước để xử lý đúng encoding
            string plaintextStr = encoder.GetString(plaintext);

            // Chia string thành 2 đoạn (không chia byte array trực tiếp)
            int midPoint = plaintextStr.Length / 2;

            string segment1Str = plaintextStr.Substring(0, midPoint);
            string segment2Str = plaintextStr.Substring(midPoint);

            byte[] segment1 = encoder.GetBytes(segment1Str);
            byte[] segment2 = encoder.GetBytes(segment2Str);

            segments.Add(segment1);
            segments.Add(segment2);

            sb.AppendLine("Doan 1: " + segment1Str);
            sb.AppendLine("Doan 2: " + segment2Str);
            sb.AppendLine();
            sb.AppendLine("H_doan 1: " + BitConverter.ToString(segment1).Replace("-", " "));
            sb.AppendLine("H_doan 2: " + BitConverter.ToString(segment2).Replace("-", " "));

            sb.AppendLine();

            return segments;
        }

        private byte[] PreprocessKey(byte[] key, int desiredLength, Encoding encoder, StringBuilder sb)
        {
            sb.AppendLine("Khoá ban đầu: " + encoder.GetString(key));
            sb.AppendLine($"H_khoá: {BitConverter.ToString(key).Replace("-", " ")}");

            byte[] processedKey = HandleKeyFlexible(key, desiredLength, encoder, sb);

            sb.AppendLine("Khoá sau xử lý: " + encoder.GetString(processedKey));
            sb.AppendLine($"H_khoá sau xử lý: {BitConverter.ToString(processedKey).Replace("-", " ")}");

            return processedKey;
        }

        private string DecodeEscapedString(string input)
        {
            return input
                .Replace("\\n", "\n")
                .Replace("\\r", "\r")
                .Replace("\\t", "\t")
                .Replace("\\\\", "\\")
                .Replace("\\\"", "\"")
                .Replace("\\'", "'");
        }

        private byte[] EncryptAes128StepByStep(byte[] data, byte[] key, byte[][] roundKeys, StringBuilder processSb, int segmentNumber)
        {
            try
            {
                processSb.AppendLine($"5️⃣ QUÁ TRÌNH MÃ HÓA AES-128 CHI TIẾT (ĐOẠN {segmentNumber}):");
                processSb.AppendLine($"   Số vòng (rounds): 10 + 1 vòng đầu (AddRoundKey)");
                processSb.AppendLine();

                using (var aes = Aes.Create())
                {
                    aes.KeySize = 128;
                    aes.Key = key;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;

                    byte[] result = new byte[data.Length];

                    // Xử lý từng block
                    for (int blockIndex = 0; blockIndex < data.Length; blockIndex += 16)
                    {
                        byte[] block = new byte[16];
                        Array.Copy(data, blockIndex, block, 0, 16);

                        processSb.AppendLine($"--- 🧩 BLOCK {blockIndex / 16 + 1} (ĐOẠN {segmentNumber}) ---");
                        processSb.AppendLine($"Input Block (hex): {BitConverter.ToString(block).Replace("-", " ")}");

                        DisplayStateMatrix(block, "STATE BAN ĐẦU", processSb);

                        // Mô phỏng từng vòng mã hóa sử dụng roundKeys thực tế
                        byte[] tempState = (byte[])block.Clone();
                        SimulateEncryptionRounds(tempState, roundKeys, processSb);


                        // Mã hóa thực tế
                        using (var encryptor = aes.CreateEncryptor())
                        {
                            encryptor.TransformBlock(block, 0, 16, result, blockIndex);
                        }

                        processSb.AppendLine($"Cipher Block (hex): {BitConverter.ToString(result, blockIndex, 16).Replace("-", " ")}");
                        DisplayStateMatrix(result.Skip(blockIndex).Take(16).ToArray(), "STATE SAU MÃ HÓA", processSb);
                        processSb.AppendLine();
                    }

                    return result;
                }
            }
            catch (Exception ex)
            {
                processSb.AppendLine($"❌ Lỗi khi mã hóa AES-128: {ex.Message}");
                throw;
            }
        }

        private byte[] DecryptAes128StepByStep(byte[] ciphertext, byte[] key, byte[][] roundKeys, StringBuilder processSb)
        {
            try
            {
                processSb.AppendLine("3️⃣ QUÁ TRÌNH GIẢI MÃ AES-128 CHI TIẾT:");
                processSb.AppendLine($"   Số vòng (rounds): 10 + 1 vòng cuối (AddRoundKey)");
                processSb.AppendLine();

                using (var aes = Aes.Create())
                {
                    aes.KeySize = 128;
                    aes.Key = key;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;

                    byte[] result = new byte[ciphertext.Length];

                    // Xử lý từng block
                    for (int blockIndex = 0; blockIndex < ciphertext.Length; blockIndex += 16)
                    {
                        byte[] block = new byte[16];
                        Array.Copy(ciphertext, blockIndex, block, 0, 16);

                        processSb.AppendLine($"--- 🧩 BLOCK {blockIndex / 16 + 1} ---");
                        processSb.AppendLine($"Input Cipher Block (hex): {BitConverter.ToString(block).Replace("-", " ")}");

                        DisplayStateMatrix(block, "CIPHERTEXT STATE", processSb);

                        // Mô phỏng từng vòng giải mã (dùng roundKeys)
                        byte[] tempState = (byte[])block.Clone();
                        SimulateDecryptionRounds(tempState, roundKeys, processSb);


                        // Giải mã thực tế
                        using (var decryptor = aes.CreateDecryptor())
                        {
                            decryptor.TransformBlock(block, 0, 16, result, blockIndex);
                        }

                        processSb.AppendLine($"Decrypted Block (hex): {BitConverter.ToString(result, blockIndex, 16).Replace("-", " ")}");
                        DisplayStateMatrix(result.Skip(blockIndex).Take(16).ToArray(), "STATE SAU GIẢI MÃ", processSb);
                        processSb.AppendLine();
                    }

                    // Xử lý padding sau khi giải mã - SỬA LẠI PHẦN NÀY
                    processSb.AppendLine("4️⃣ XỬ LÝ PADDING SAU GIẢI MÃ:");

                    // Kiểm tra padding theo chuẩn PKCS7
                    int paddingLength = result[result.Length - 1];
                    bool validPadding = false;

                    if (paddingLength > 0 && paddingLength <= 16)
                    {
                        validPadding = true;
                        // Kiểm tra tất cả các byte padding
                        for (int i = result.Length - paddingLength; i < result.Length; i++)
                        {
                            if (result[i] != paddingLength)
                            {
                                validPadding = false;
                                break;
                            }
                        }
                    }

                    if (validPadding)
                    {
                        processSb.AppendLine($"   Phát hiện padding hợp lệ: {paddingLength} bytes (value: 0x{paddingLength:X2})");
                        processSb.AppendLine($"   Dữ liệu trước khi remove padding: {BitConverter.ToString(result).Replace("-", " ")}");

                        byte[] withoutPadding = new byte[result.Length - paddingLength];
                        Array.Copy(result, 0, withoutPadding, 0, withoutPadding.Length);

                        processSb.AppendLine($"   Dữ liệu sau khi remove padding: {BitConverter.ToString(withoutPadding).Replace("-", " ")}");

                        // SỬA PHẦN HIỂN THỊ PLAINTEXT - THỬ NHIỀU ENCODING
                        processSb.AppendLine("   Plaintext cuối cùng:");
                        processSb.AppendLine($"     - Bytes (hex): {BitConverter.ToString(withoutPadding).Replace("-", " ").ToLower()}");

                        // Thử các encoding khác nhau
                        TryMultipleEncodings(withoutPadding, processSb);

                        processSb.AppendLine($"   ✅ Giải mã thành công");
                        result = withoutPadding;
                    }
                    else
                    {
                        processSb.AppendLine($"   Padding không hợp lệ (last byte: 0x{result[result.Length - 1]:X2})");
                        processSb.AppendLine($"   ❌ Có thể key sai hoặc dữ liệu bị hỏng");
                        processSb.AppendLine($"   Dữ liệu thô: {BitConverter.ToString(result).Replace("-", " ")}");

                        // Vẫn thử hiển thị với các encoding
                        TryMultipleEncodings(result, processSb);
                    }



                    processSb.AppendLine();

                    return result;
                }
            }
            catch (Exception ex)
            {
                processSb.AppendLine($"❌ Lỗi khi giải mã AES-128: {ex.Message}");
                throw;
            }
        }

        private void TryMultipleEncodings(byte[] data, StringBuilder sb)
        {
            if (data == null || data.Length == 0) return;

            // Danh sách các encoding cần thử với kiểm tra an toàn
            var encodings = new List<(string Name, Encoding Encoding)>();

            // Các encoding luôn khả dụng
            encodings.Add(("UTF-8", Encoding.UTF8));
            encodings.Add(("ASCII", Encoding.ASCII));
            encodings.Add(("Unicode (UTF-16LE)", Encoding.Unicode));
            encodings.Add(("UTF-32", Encoding.UTF32));

            // Thử thêm các encoding khác nếu khả dụng
            try
            {
                encodings.Add(("Windows-1252", Encoding.GetEncoding(1252)));
            }
            catch { /* Không khả dụng */ }

            try
            {
                encodings.Add(("ISO-8859-1", Encoding.GetEncoding(28591)));
            }
            catch { /* Không khả dụng */ }

            foreach (var enc in encodings)
            {
                try
                {
                    string decoded = enc.Encoding.GetString(data);

                    // Kiểm tra xem string có hợp lệ không
                    if (!string.IsNullOrEmpty(decoded) && !ContainsInvalidChars(decoded))
                    {
                        sb.AppendLine($"     - {enc.Name}: {decoded}");
                    }
                }
                catch
                {
                    // Bỏ qua encoding không hỗ trợ hoặc lỗi decode
                }
            }
        }

        private bool ContainsInvalidChars(string text)
        {
            foreach (char c in text)
            {
                // Các ký tự control không phải whitespace thông thường
                if (char.IsControl(c) && c != '\n' && c != '\r' && c != '\t' && c != '\b')
                    return true;
            }
            return false;
        }

        private void SimulateEncryptionRounds(byte[] block, byte[][] roundKeys, StringBuilder sb)
        {
            sb.AppendLine("=== QUÁ TRÌNH 10 VÒNG MÃ HÓA (SỬ DỤNG ROUND KEYS THỰC) ===");

            // Vòng 0: AddRoundKey đầu tiên (round 0)
            sb.AppendLine("🎯 VÒNG 0 - Initial AddRoundKey:");
            sb.AppendLine($"   - XOR state với Round Key 0");
            DisplayStateMatrix(block, "TRƯỚC AddRoundKey", sb);
            SimulateAddRoundKey(block, roundKeys[0], sb);
            DisplayStateMatrix(block, "SAU AddRoundKey", sb);
            sb.AppendLine();

            for (int round = 1; round <= 10; round++)
            {
                sb.AppendLine($"🎯 VÒNG {round}:");

                // SubBytes
                sb.AppendLine($"  1. SubBytes:");
                sb.AppendLine($"     - Thay thế từng byte qua S-box");
                sb.AppendLine($"     - Ánh xạ phi tuyến để chống cryptanalysis");
                SimulateSubBytes(block);
                DisplayStateMatrix(block, "SAU SubBytes", sb);

                // ShiftRows
                sb.AppendLine($"  2. ShiftRows:");
                sb.AppendLine($"     - Hàng 0: không dịch");
                sb.AppendLine($"     - Hàng 1: dịch trái 1 byte");
                sb.AppendLine($"     - Hàng 2: dịch trái 2 byte");
                sb.AppendLine($"     - Hàng 3: dịch trái 3 byte");
                SimulateShiftRows(block);
                DisplayStateMatrix(block, "SAU ShiftRows", sb);

                // MixColumns (trừ vòng cuối)
                if (round < 10)
                {
                    sb.AppendLine($"  3. MixColumns:");
                    sb.AppendLine($"     - Nhân ma trận với ma trận MixColumns cố định");
                    sb.AppendLine($"     - Trộn dữ liệu giữa các cột");
                    SimulateMixColumns(block);
                    DisplayStateMatrix(block, "SAU MixColumns", sb);
                }
                else
                {
                    sb.AppendLine($"  3. MixColumns: BỎ QUA (vòng cuối)");
                }

                // AddRoundKey
                sb.AppendLine($"  4. AddRoundKey (Round {round}):");
                sb.AppendLine($"     - XOR state với round key {round}");
                sb.AppendLine($"     - Round key được sinh từ Key Expansion");
                DisplayRoundKeyMatrix(roundKeys[round], sb, $"ROUND KEY {round}");
                SimulateAddRoundKey(block, roundKeys[round], sb);
                DisplayStateMatrix(block, "SAU AddRoundKey", sb);
                sb.AppendLine("─────────────────────────────────────────");
            }
        }

        private void SimulateDecryptionRounds(byte[] block, byte[][] roundKeys, StringBuilder sb)
        {
            sb.AppendLine("=== QUÁ TRÌNH 10 VÒNG GIẢI MÃ (SỬ DỤNG ROUND KEYS THỰC) ===");

            byte[] state = (byte[])block.Clone();

            for (int round = 10; round >= 1; round--)
            {
                sb.AppendLine($"🎯 VÒNG {11 - round} (Round Key {round}):");

                // AddRoundKey (ngược) - XOR với round key hiện tại
                sb.AppendLine($"  1. AddRoundKey (Round {round}):");
                sb.AppendLine($"     - XOR state với round key {round}");
                DisplayStateMatrix(state, "TRƯỚC AddRoundKey", sb);
                SimulateAddRoundKey(state, roundKeys[round], sb);
                DisplayStateMatrix(state, "SAU AddRoundKey", sb);

                // MixColumns (ngược - trừ vòng đầu)
                if (round < 10)
                {
                    sb.AppendLine($"  2. InvMixColumns:");
                    sb.AppendLine($"     - Nhân ma trận với ma trận InvMixColumns");
                    sb.AppendLine($"     - Hoàn tác phép trộn cột");
                    SimulateInvMixColumns(state);
                    DisplayStateMatrix(state, "SAU InvMixColumns", sb);
                }
                else
                {
                    sb.AppendLine($"  2. InvMixColumns: BỎ QUA (vòng đầu giải mã)");
                }

                // ShiftRows (ngược)
                sb.AppendLine($"  3. InvShiftRows:");
                sb.AppendLine($"     - Hàng 0: không dịch");
                sb.AppendLine($"     - Hàng 1: dịch phải 1 byte");
                sb.AppendLine($"     - Hàng 2: dịch phải 2 byte");
                sb.AppendLine($"     - Hàng 3: dịch phải 3 byte");
                SimulateInvShiftRows(state);
                DisplayStateMatrix(state, "SAU InvShiftRows", sb);

                // SubBytes (ngược)
                sb.AppendLine($"  4. InvSubBytes:");
                sb.AppendLine($"     - Thay thế từng byte qua Inverse S-box");
                sb.AppendLine($"     - Hoàn tác ánh xạ phi tuyến");
                SimulateInvSubBytes(state);
                DisplayStateMatrix(state, "SAU InvSubBytes", sb);

                sb.AppendLine("─────────────────────────────────────────");
            }

            // Vòng cuối: AddRoundKey đầu tiên (ngược)
            sb.AppendLine("🎯 VÒNG 10 - Final AddRoundKey (Round Key 0):");
            sb.AppendLine($"   - XOR state với Round Key 0");
            DisplayStateMatrix(state, "TRƯỚC AddRoundKey", sb);
            SimulateAddRoundKey(state, roundKeys[0], sb);
            DisplayStateMatrix(state, "SAU AddRoundKey", sb);

            // Copy final state back to block (so DisplayStateMatrix in caller shows correct)
            Array.Copy(state, 0, block, 0, 16);
            sb.AppendLine();
        }

        private void DisplayKeyExpansion(byte[] key, StringBuilder sb, bool forEncryption)
        {
            // This method is kept for compatibility but KeyExpansion creates and prints details.
            sb.AppendLine($"🔑 KEY EXPANSION CHO {(forEncryption ? "MÃ HÓA" : "GIẢI MÃ")} - SINH 11 ROUND KEYS:");
            sb.AppendLine("(Từ 128-bit key ban đầu sinh ra 11 round keys 128-bit)");
            sb.AppendLine();

            // KeyExpansion already prints details; call it with a temp StringBuilder if needed.
            KeyExpansion(key, sb);
        }

        // --- Key Expansion implementation: returns 11 round keys (each 16 bytes) and prints steps to sb ---
        private byte[][] KeyExpansion(byte[] key, StringBuilder sb)
        {
            // key: 16 bytes
            sb.AppendLine("🔑 BẮT ĐẦU KEY EXPANSION (128-bit key → 44 words → 11 round keys)");
            sb.AppendLine($"Key gốc (hex): {BitConverter.ToString(key).Replace("-", " ")}");
            DisplayKeyMatrix(key, sb);

            // W will contain 44 words (4 bytes each)
            byte[,] W = new byte[44, 4];

            // Initialize W[0..3] from the key
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    W[i, j] = key[i * 4 + j];
                }
            }

            // Print initial words
            for (int i = 0; i < 4; i++)
            {
                sb.AppendLine($"W[{i}]: {WordToHex(W, i)}");
            }
            sb.AppendLine();

            for (int i = 4; i < 44; i++)
            {
                byte[] temp = new byte[4];
                for (int t = 0; t < 4; t++) temp[t] = W[i - 1, t];

                if (i % 4 == 0)
                {
                    // RotWord
                    byte[] rot = RotWord(temp);
                    sb.AppendLine($"RotWord(W[{i - 1}]): {BytesToHex(rot)}");

                    // SubWord
                    byte[] sub = SubWord(rot);
                    sb.AppendLine($"SubWord(RotWord): {BytesToHex(sub)}");

                    // Rcon
                    byte r = RCON[i / 4];
                    sb.AppendLine($"Rcon[{i / 4}] = 0x{r:X2}");

                    // temp = SubWord(rot) XOR [Rcon,0,0,0]
                    temp[0] = (byte)(sub[0] ^ r);
                    temp[1] = (byte)(sub[1]);
                    temp[2] = (byte)(sub[2]);
                    temp[3] = (byte)(sub[3]);

                    sb.AppendLine($"Temp after SubWord ^ Rcon: {BytesToHex(temp)}");

                    // W[i] = W[i-4] XOR temp
                    for (int t = 0; t < 4; t++)
                    {
                        W[i, t] = (byte)(W[i - 4, t] ^ temp[t]);
                    }
                }
                else
                {
                    // W[i] = W[i-4] XOR W[i-1]
                    for (int t = 0; t < 4; t++)
                    {
                        W[i, t] = (byte)(W[i - 4, t] ^ W[i - 1, t]);
                    }
                }

                sb.AppendLine($"W[{i}]: {WordToHex(W, i)}");
            }

            // Build 11 round keys (each 16 bytes)
            byte[][] roundKeys = new byte[11][];
            for (int round = 0; round <= 10; round++)
            {
                roundKeys[round] = new byte[16];
                for (int c = 0; c < 4; c++)
                {
                    for (int r = 0; r < 4; r++)
                    {
                        // word index = round*4 + c; byte index in word = r
                        roundKeys[round][r + 4 * c] = W[round * 4 + c, r];
                    }
                }

                sb.AppendLine();
                sb.AppendLine($"--- Round Key {round} ---");
                DisplayRoundKeyMatrix(roundKeys[round], sb, $"ROUND KEY {round}");
            }

            sb.AppendLine("🔑 KẾT THÚC KEY EXPANSION");
            sb.AppendLine();

            return roundKeys;
        }

        // Helpers for KeyExpansion
        private static byte[] RotWord(byte[] word)
        {
            return new byte[] { word[1], word[2], word[3], word[0] };
        }

        private static byte[] SubWord(byte[] word)
        {
            byte[] res = new byte[4];
            for (int i = 0; i < 4; i++) res[i] = INV_SBOX[word[i]];
            return res;
        }

        private static string BytesToHex(byte[] b)
        {
            return BitConverter.ToString(b).Replace("-", " ");
        }

        private static string WordToHex(byte[,] W, int idx)
        {
            byte[] w = new byte[4];
            for (int i = 0; i < 4; i++) w[i] = W[idx, i];
            return BytesToHex(w);
        }

        private void DisplayRoundKeyMatrix(byte[] key, StringBuilder sb, string title)
        {
            sb.AppendLine($"   📦 {title}:");
            sb.AppendLine("       C0    C1    C2    C3");
            sb.AppendLine("       ---   ---   ---   ---");
            for (int row = 0; row < 4; row++)
            {
                sb.Append($"   R{row} | ");
                for (int col = 0; col < 4; col++)
                {
                    int index = row + col * 4;
                    sb.Append($"{key[index]:X2}   ");
                }
                sb.AppendLine();
            }
            sb.AppendLine();
        }

        // --- Các phương thức mô phỏng biến đổi (giữ nguyên nhưng AddRoundKey dùng roundKey thực) ---
        private void SimulateSubBytes(byte[] state)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] = SBOX[state[i]];
            }
        }

        private void SimulateInvSubBytes(byte[] state)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] = INV_SBOX[state[i]];
            }
        }

        private void SimulateShiftRows(byte[] state)
        {
            byte[] temp = new byte[16];
            Array.Copy(state, temp, 16);

            // Row 0 (indexes 0,4,8,12) no shift
            state[0] = temp[0]; state[4] = temp[4]; state[8] = temp[8]; state[12] = temp[12];

            // Row 1 (1,5,9,13) shift left 1
            state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];

            // Row 2 (2,6,10,14) shift left 2
            state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];

            // Row 3 (3,7,11,15) shift left 3
            state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];
        }

        private void SimulateInvShiftRows(byte[] state)
        {
            byte[] temp = new byte[16];
            Array.Copy(state, temp, 16);

            // Row 0 no shift
            state[0] = temp[0]; state[4] = temp[4]; state[8] = temp[8]; state[12] = temp[12];

            // Row 1 shift right 1
            state[1] = temp[13]; state[5] = temp[1]; state[9] = temp[5]; state[13] = temp[9];

            // Row 2 shift right 2
            state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];

            // Row 3 shift right 3
            state[3] = temp[7]; state[7] = temp[11]; state[11] = temp[15]; state[15] = temp[3];
        }

        private void SimulateMixColumns(byte[] state)
        {
            for (int i = 0; i < 4; i++)
            {
                byte a0 = state[i * 4];
                byte a1 = state[i * 4 + 1];
                byte a2 = state[i * 4 + 2];
                byte a3 = state[i * 4 + 3];

                state[i * 4] = (byte)(GMul(a0, 0x02) ^ GMul(a1, 0x03) ^ a2 ^ a3);
                state[i * 4 + 1] = (byte)(a0 ^ GMul(a1, 0x02) ^ GMul(a2, 0x03) ^ a3);
                state[i * 4 + 2] = (byte)(a0 ^ a1 ^ GMul(a2, 0x02) ^ GMul(a3, 0x03));
                state[i * 4 + 3] = (byte)(GMul(a0, 0x03) ^ a1 ^ a2 ^ GMul(a3, 0x02));
            }
        }

        private void SimulateInvMixColumns(byte[] state)
        {
            for (int i = 0; i < 4; i++)
            {
                byte a0 = state[i * 4];
                byte a1 = state[i * 4 + 1];
                byte a2 = state[i * 4 + 2];
                byte a3 = state[i * 4 + 3];

                state[i * 4] = (byte)(GMul(a0, 0x0e) ^ GMul(a1, 0x0b) ^ GMul(a2, 0x0d) ^ GMul(a3, 0x09));
                state[i * 4 + 1] = (byte)(GMul(a0, 0x09) ^ GMul(a1, 0x0e) ^ GMul(a2, 0x0b) ^ GMul(a3, 0x0d));
                state[i * 4 + 2] = (byte)(GMul(a0, 0x0d) ^ GMul(a1, 0x09) ^ GMul(a2, 0x0e) ^ GMul(a3, 0x0b));
                state[i * 4 + 3] = (byte)(GMul(a0, 0x0b) ^ GMul(a1, 0x0d) ^ GMul(a2, 0x09) ^ GMul(a3, 0x0e));
            }
        }

        private byte GMul(byte a, byte b)
        {
            byte p = 0;
            byte counter;
            byte hi_bit_set;
            for (counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                    p ^= a;
                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                    a ^= 0x1b;
                b >>= 1;
            }
            return p;
        }

        private void SimulateAddRoundKey(byte[] state, byte[] roundKey, StringBuilder sb)
        {
            sb.AppendLine($"     (Apply RoundKey) XOR with:");
            sb.AppendLine($"     {BitConverter.ToString(roundKey).Replace("-", " ")}");
            for (int i = 0; i < 16; i++)
            {
                state[i] ^= roundKey[i];
            }
        }

        // Keep a simple simulate for older usage compatibility (not used anymore)
        private void SimulateAddRoundKey(byte[] state, int round)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] ^= (byte)(round * 0x11 + i);
            }
        }

        private byte[] HandleKeyFlexible(byte[] inputKey, int desiredLength, Encoding encoder, StringBuilder sb)
        {
            const char PADDING_CHAR = '.';

            sb.AppendLine("=== 🔑 XỬ LÝ KHÓA LINH HOẠT ===");
            sb.AppendLine($"Key gốc (hex): {BitConverter.ToString(inputKey).Replace("-", " ")}");
            sb.AppendLine($"Key gốc (binary): {BytesToBinaryString(inputKey)}");
            sb.AppendLine($"Key gốc (string): '{encoder.GetString(inputKey)}'");
            sb.AppendLine($"Độ dài key gốc: {inputKey.Length} bytes");
            sb.AppendLine($"Yêu cầu: {desiredLength} bytes");
            sb.AppendLine();

            byte[] finalKey = new byte[desiredLength];
            byte paddingByte = encoder.GetBytes(new char[] { PADDING_CHAR })[0];

            if (inputKey.Length < desiredLength)
            {
                Buffer.BlockCopy(inputKey, 0, finalKey, 0, inputKey.Length);
                for (int i = inputKey.Length; i < desiredLength; i++)
                {
                    finalKey[i] = paddingByte;
                }
                sb.AppendLine($"🔄 Đã thêm {desiredLength - inputKey.Length} byte padding ('{PADDING_CHAR}')");
            }
            else if (inputKey.Length > desiredLength)
            {
                Buffer.BlockCopy(inputKey, 0, finalKey, 0, desiredLength);
                sb.AppendLine($"🔄 Đã cắt bớt từ {inputKey.Length} xuống {desiredLength} bytes");
            }
            else
            {
                finalKey = inputKey;
                sb.AppendLine($"✅ Key có độ dài hợp lệ - không cần điều chỉnh");
            }

            sb.AppendLine();
            sb.AppendLine($"🔹 Key cuối cùng (hex): {BitConverter.ToString(finalKey).Replace("-", " ")}");
            sb.AppendLine($"🔹 Key cuối cùng (binary): {BytesToBinaryString(finalKey)}");
            sb.AppendLine($"🔹 Key cuối cùng (string): \"{encoder.GetString(finalKey)}\"");
            sb.AppendLine($"🔹 Độ dài key: {finalKey.Length} bytes ({finalKey.Length * 8} bits)");

            DisplayKeyMatrix(finalKey, sb);
            sb.AppendLine("===========================================");
            sb.AppendLine();

            return finalKey;
        }

        private void DisplayKeyMatrix(byte[] key, StringBuilder sb)
        {
            sb.AppendLine();
            sb.AppendLine("🧮 MA TRẬN KHÓA AES-128 (4x4 - Column Major):");
            sb.AppendLine();

            sb.AppendLine("       C0    C1    C2    C3     |    Binary");
            sb.AppendLine("       ---   ---   ---   ---    |    ------");

            for (int row = 0; row < 4; row++)
            {
                sb.Append($"R{row} | ");
                for (int col = 0; col < 4; col++)
                {
                    int index = row + col * 4;
                    sb.Append($"{key[index]:X2}   ");
                }

                sb.Append("  |  ");
                for (int col = 0; col < 4; col++)
                {
                    int index = row + col * 4;
                    sb.Append($"{Convert.ToString(key[index], 2).PadLeft(8, '0')} ");
                }
                sb.AppendLine();
            }
        }

        private void DisplayStateMatrix(byte[] state, string title, StringBuilder sb)
        {
            if (state.Length != 16) return;

            sb.AppendLine($"   📊 {title}:");
            sb.AppendLine("       C0    C1    C2    C3     |    Hex    |    Binary");
            sb.AppendLine("       ---   ---   ---   ---    |    ---    |    ------");

            for (int row = 0; row < 4; row++)
            {
                sb.Append($"   R{row} | ");
                for (int col = 0; col < 4; col++)
                {
                    int index = row + col * 4;
                    sb.Append($"{state[index]:X2}   ");
                }

                sb.Append("  |  ");
                for (int col = 0; col < 4; col++)
                {
                    int index = row + col * 4;
                    sb.Append($"{state[index]:X2} ");
                }

                sb.Append("  |  ");
                for (int col = 0; col < 4; col++)
                {
                    int index = row + col * 4;
                    sb.Append($"{Convert.ToString(state[index], 2).PadLeft(8, '0')} ");
                }
                sb.AppendLine();
            }
            sb.AppendLine();
        }

        private string BytesToBinaryString(byte[] bytes)
        {
            return string.Join(" ", bytes.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));
        }
    }
}
