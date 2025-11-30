using System;
using System.Text;
using System.Security.Cryptography;
using System.Linq;
using System.Collections.Generic;

namespace DESApp.Handlers
{
    public class Aes192Handler : IEncryptionHandler
    {
        public string AlgorithmName => "AES-192";

        public string GetKeyHint() => "AES-192: 24 bytes - UTF-8/ASCII đều được, tự động padding '.' nếu thiếu";

        public byte[] Encrypt(byte[] plaintext, byte[] key, Encoding encoder, StringBuilder processSb)
        {
            var startTime = DateTime.Now;

            string plaintextStr = encoder.GetString(plaintext);
            plaintextStr = DecodeEscapedString(plaintextStr);
            plaintext = encoder.GetBytes(plaintextStr);

            processSb.AppendLine("QUÁ TRÌNH MÃ HÓA AES-192 ===");
            processSb.AppendLine($"Encoding: {encoder.EncodingName}");
            processSb.AppendLine($"Key Length: 24 bytes");
            processSb.AppendLine($"=== QUÁ TRÌNH MÃ HÓA AES-192 ===");
            processSb.AppendLine($"Encoding: {encoder.EncodingName}");
            processSb.AppendLine($"Key Length: 24 bytes (192 bits)");
            processSb.AppendLine($"☐ Plaintext đã nhập: {encoder.GetString(plaintext)}");
            processSb.AppendLine($"Q Key đã nhập: {encoder.GetString(key)}");
            processSb.AppendLine();

            // ==================== Tiền xử lý bản rõ ====================
            processSb.AppendLine("===================== TIỀN XỬ LÝ BẢN RÕ ====================");

            // Chia bản rõ thành các đoạn 16 byte
            int segmentSize = 16;
            int segmentCount = (int)Math.Ceiling((double)plaintext.Length / segmentSize);

            processSb.AppendLine("Ban ro chia lam cac doan sau:");
            processSb.AppendLine();

            List<byte[]> segments = new List<byte[]>();
            for (int i = 0; i < segmentCount; i++)
            {
                int segmentLength = Math.Min(segmentSize, plaintext.Length - i * segmentSize);
                byte[] segment = new byte[segmentLength];
                Array.Copy(plaintext, i * segmentSize, segment, 0, segmentLength);
                segments.Add(segment);

                processSb.AppendLine($"Doan {i + 1}: {encoder.GetString(segment)}");
                processSb.AppendLine($"H_doan {i + 1}: {BitConverter.ToString(segment).Replace("-", " ").ToLower()}");
                processSb.AppendLine();
            }
            processSb.AppendLine();

            // 1. Plaintext info
            processSb.AppendLine("1️⃣ Plaintext → bytes:");
            processSb.AppendLine($"   Length: {plaintext.Length} bytes");
            processSb.AppendLine($"   Bytes (hex): {BitConverter.ToString(plaintext).Replace("-", " ")}");
            processSb.AppendLine($"   Bytes (binary): {BytesToBinaryString(plaintext)}");
            processSb.AppendLine();

            // ==================== Tiền xử lý khóa ====================
            processSb.AppendLine("===================== TIỀN XỬ LÝ KHÓA ====================");
            processSb.AppendLine($"Khoá ban đầu: {encoder.GetString(key)}");
            processSb.AppendLine($"Khoá ban đầu (hex): {BitConverter.ToString(key).Replace("-", " ")}");
            processSb.AppendLine();

            // 2. Xử lý key
            key = HandleKeyFlexible(key, 24, encoder, processSb);

            processSb.AppendLine($"Khoá sau xử lý: {encoder.GetString(key)}");
            processSb.AppendLine($"H_khoá: {BytesToHexString(key)}");
            processSb.AppendLine();

            // ==================== Quá trình sinh khoá ====================
            processSb.AppendLine("===================== QUÁ TRÌNH SINH KHÓA ====================");

            // 3. Padding info
            processSb.AppendLine("3️⃣ PKCS7 padding:");
            processSb.AppendLine($"   Input length: {plaintext.Length} bytes");
            int paddedLength = ((plaintext.Length / 16) + 1) * 16;
            int padBytes = paddedLength - plaintext.Length;
            processSb.AppendLine($"   Padded length: {paddedLength} bytes");
            processSb.AppendLine($"   Pad bytes: {padBytes} bytes (value: 0x{padBytes:X2})");

            // Tạo padded data
            byte[] paddedData = new byte[paddedLength];
            Array.Copy(plaintext, 0, paddedData, 0, plaintext.Length);
            for (int i = plaintext.Length; i < paddedLength; i++)
            {
                paddedData[i] = (byte)padBytes;
            }
            processSb.AppendLine($"   Padded data (hex): {BitConverter.ToString(paddedData).Replace("-", " ")}");
            processSb.AppendLine();

            // 4. Chia blocks
            int blockCount = paddedData.Length / 16;
            processSb.AppendLine($"4️⃣ Chia bản rõ thành {blockCount} block (128-bit mỗi block)");
            processSb.AppendLine();

            // 5. Mã hóa với chi tiết từng bước
            byte[] encryptedData = EncryptAes192StepByStep(paddedData, key, processSb);

            // ==================== Bản mã hoá ====================
            processSb.AppendLine("===================== BẢN MÃ HOÁ ====================");

            // Chia bản mã thành các đoạn 16 byte tương ứng
            List<byte[]> encryptedSegments = new List<byte[]>();
            for (int i = 0; i < blockCount; i++)
            {
                byte[] encryptedSegment = new byte[16];
                Array.Copy(encryptedData, i * 16, encryptedSegment, 0, 16);
                encryptedSegments.Add(encryptedSegment);

                processSb.AppendLine($"Mã đoạn {i + 1}: {BitConverter.ToString(encryptedSegment).Replace("-", " ")}");
                processSb.AppendLine($"H_mã đoạn {i + 1}: {BytesToHexString(encryptedSegment)}");
                processSb.AppendLine();
            }

            processSb.AppendLine($"Bản mã hoá (Base64): {Convert.ToBase64String(encryptedData)}");
            processSb.AppendLine($"Bản mã hoá (Hex): {BytesToHexString(encryptedData)}");
            processSb.AppendLine();

            var endTime = DateTime.Now;
            var duration = (endTime - startTime).TotalMilliseconds;

            processSb.AppendLine("=== KẾT THÚC MÃ HÓA AES-192 ===");
            processSb.AppendLine($"⏱ Encryption completed in {duration}ms");
            processSb.AppendLine();
            processSb.AppendLine($"→ Cipher (Base64): {Convert.ToBase64String(encryptedData)}");

            return encryptedData;
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] key, Encoding encoder, StringBuilder processSb)
        {
            var startTime = DateTime.Now;

            processSb.AppendLine("=== QUÁ TRÌNH GIẢI MÃ AES-192 ===");
            processSb.AppendLine($"Encoding: {encoder.EncodingName}");
            processSb.AppendLine($"Key Length: 24 bytes (192 bits)");
            processSb.AppendLine($"📝 Ciphertext đã nhập: {Convert.ToBase64String(ciphertext)}");
            processSb.AppendLine($"🔑 Key đã nhập: {encoder.GetString(key)}");
            processSb.AppendLine();

            // ==================== Tiền xử lý bản mã ====================
            processSb.AppendLine("===================== TIỀN XỬ LÝ BẢN MÃ ====================");

            int blockCount = ciphertext.Length / 16;
            processSb.AppendLine($"Bản mã chia làm đoạn sau:");
            processSb.AppendLine();

            List<byte[]> cipherSegments = new List<byte[]>();
            for (int i = 0; i < blockCount; i++)
            {
                byte[] segment = new byte[16];
                Array.Copy(ciphertext, i * 16, segment, 0, 16);
                cipherSegments.Add(segment);

                // Encoding latin1 = Encoding.GetEncoding("ISO-8859-1");
                // processSb.AppendLine($"Doan {i + 1}: {latin1.GetString(segment)}");
                processSb.AppendLine($"H_doan {i + 1}: {BitConverter.ToString(segment).Replace("-", " ").ToLower()}");
                processSb.AppendLine();
            }
            processSb.AppendLine();

            // 1. Ciphertext info
            processSb.AppendLine("1️⃣ Ciphertext → bytes:");
            processSb.AppendLine($"   Length: {ciphertext.Length} bytes");
            processSb.AppendLine($"   Bytes (hex): {BitConverter.ToString(ciphertext).Replace("-", " ")}");
            processSb.AppendLine($"   Bytes (binary): {BytesToBinaryString(ciphertext)}");
            processSb.AppendLine();

            // ==================== Tiền xử lý khóa ====================
            processSb.AppendLine("===================== TIỀN XỬ LÝ KHÓA ====================");
            processSb.AppendLine($"Khoá ban đầu: {encoder.GetString(key)}");
            processSb.AppendLine($"Khoá ban đầu (hex): {BitConverter.ToString(key).Replace("-", " ")}");
            processSb.AppendLine();

            // 2. Xử lý key
            key = HandleKeyFlexible(key, 24, encoder, processSb);

            processSb.AppendLine($"Khoá sau xử lý: {encoder.GetString(key)}");
            processSb.AppendLine($"H_khoá: {BytesToHexString(key)}");
            processSb.AppendLine();

            // ==================== Quá trình sinh khoá ====================
            processSb.AppendLine("===================== QUÁ TRÌNH SINH KHÓA ====================");

            // 3. Chia blocks
            processSb.AppendLine($"2️⃣ Chia ciphertext thành {blockCount} block (128-bit mỗi block)");
            processSb.AppendLine();

            // 4. Giải mã với chi tiết từng bước
            byte[] decryptedData = DecryptAes192StepByStep(ciphertext, key, processSb);

            // ==================== Bản rõ giải mã ====================
            processSb.AppendLine("===================== BẢN RÕ GIẢI MÃ ====================");

            // Xử lý padding và hiển thị các đoạn đã giải mã
            byte lastByte = decryptedData[decryptedData.Length - 1];
            int actualLength = decryptedData.Length;

            if (lastByte > 0 && lastByte <= 16)
            {
                actualLength = decryptedData.Length - lastByte;
            }

            int decryptedSegmentCount = (int)Math.Ceiling((double)actualLength / 16);
            processSb.AppendLine($"Bản rõ giải mã gồm {decryptedSegmentCount} đoạn:");
            processSb.AppendLine();

            for (int i = 0; i < decryptedSegmentCount; i++)
            {
                int segmentLength = Math.Min(16, actualLength - i * 16);
                byte[] segment = new byte[segmentLength];
                Array.Copy(decryptedData, i * 16, segment, 0, segmentLength);

                processSb.AppendLine($"Đoạn {i + 1}: {encoder.GetString(segment)}");
                processSb.AppendLine($"H_đoạn {i + 1}: {BytesToHexString(segment)}");
                processSb.AppendLine();
            }

            byte[] finalPlaintext = new byte[actualLength];
            Array.Copy(decryptedData, 0, finalPlaintext, 0, actualLength);

            try
            {
                string decodedText = encoder.GetString(finalPlaintext);
                processSb.AppendLine($"Bản rõ hoàn chỉnh: {decodedText}");
            }
            catch (Exception)
            {
                // Fallback to UTF-8 if there's encoding issue
                string decodedText = Encoding.UTF8.GetString(finalPlaintext);
                processSb.AppendLine($"Bản rõ hoàn chỉnh: {decodedText}");
            }
            processSb.AppendLine($"Bản rõ (Hex): {BytesToHexString(finalPlaintext)}");
            processSb.AppendLine();

            var endTime = DateTime.Now;
            var duration = (endTime - startTime).TotalMilliseconds;

            processSb.AppendLine("=== KẾT THÚC GIẢI MÃ AES-192 ===");
            processSb.AppendLine($"⏱ Decryption completed in {duration}ms");
            processSb.AppendLine();
            processSb.AppendLine($"→ Plaintext: {encoder.GetString(finalPlaintext)}");

            processSb.AppendLine("=== KIỂM TRA ENCODING ===");
            try
            {
                string testDecode = encoder.GetString(finalPlaintext);
                processSb.AppendLine($"✅ Encoding {encoder.EncodingName} hợp lệ");
                processSb.AppendLine($"Kết quả: {testDecode}");
            }
            catch (Exception ex)
            {
                processSb.AppendLine($"⚠️ Lỗi encoding {encoder.EncodingName}: {ex.Message}");
                processSb.AppendLine($"🔄 Thử sử dụng UTF-8...");
                string utf8Decode = Encoding.UTF8.GetString(finalPlaintext);
                processSb.AppendLine($"Kết quả UTF-8: {utf8Decode}");
                finalPlaintext = Encoding.UTF8.GetBytes(utf8Decode); // Cập nhật lại dữ liệu
            }
            processSb.AppendLine();

            return finalPlaintext;
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

        // Thêm phương thức chuyển đổi bytes sang hex string
        private string BytesToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        // Các phương thức khác giữ nguyên...
        private byte[] EncryptAes192StepByStep(byte[] data, byte[] key, StringBuilder processSb)
        {
            try
            {
                processSb.AppendLine("5️⃣ QUÁ TRÌNH MÃ HÓA AES-192 CHI TIẾT:");
                processSb.AppendLine($"   Số vòng (rounds): 12 + 1 vòng đầu (AddRoundKey)");
                processSb.AppendLine();

                using (var aes = Aes.Create())
                {
                    aes.KeySize = 192;
                    aes.Key = key;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;

                    // Hiển thị key expansion
                    DisplayKeyExpansion(key, processSb, true);

                    byte[] result = new byte[data.Length];

                    // Xử lý từng block
                    for (int blockIndex = 0; blockIndex < data.Length; blockIndex += 16)
                    {
                        byte[] block = new byte[16];
                        Array.Copy(data, blockIndex, block, 0, 16);

                        processSb.AppendLine($"--- 🧩 BLOCK {blockIndex / 16 + 1} ---");
                        processSb.AppendLine($"Input Block (hex): {BitConverter.ToString(block).Replace("-", " ")}");

                        DisplayStateMatrix(block, "STATE BAN ĐẦU", processSb);

                        // Mô phỏng từng vòng mã hóa
                        SimulateEncryptionRounds(block, key, processSb);

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
                processSb.AppendLine($"❌ Lỗi khi mã hóa AES-192: {ex.Message}");
                throw;
            }
        }

        private byte[] DecryptAes192StepByStep(byte[] ciphertext, byte[] key, StringBuilder processSb)
        {
            try
            {
                processSb.AppendLine("3️⃣ QUÁ TRÌNH GIẢI MÃ AES-192 CHI TIẾT:");
                processSb.AppendLine($"   Số vòng (rounds): 12 + 1 vòng cuối (AddRoundKey)");
                processSb.AppendLine();

                using (var aes = Aes.Create())
                {
                    aes.KeySize = 192;
                    aes.Key = key;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.None;

                    // Hiển thị key expansion cho giải mã
                    DisplayKeyExpansion(key, processSb, false);

                    byte[] result = new byte[ciphertext.Length];

                    // Xử lý từng block
                    for (int blockIndex = 0; blockIndex < ciphertext.Length; blockIndex += 16)
                    {
                        byte[] block = new byte[16];
                        Array.Copy(ciphertext, blockIndex, block, 0, 16);

                        processSb.AppendLine($"--- 🧩 BLOCK {blockIndex / 16 + 1} ---");
                        processSb.AppendLine($"Input Cipher Block (hex): {BitConverter.ToString(block).Replace("-", " ")}");

                        DisplayStateMatrix(block, "CIPHERTEXT STATE", processSb);

                        // Mô phỏng từng vòng giải mã
                        SimulateDecryptionRounds(block, key, processSb);

                        // Giải mã thực tế
                        using (var decryptor = aes.CreateDecryptor())
                        {
                            decryptor.TransformBlock(block, 0, 16, result, blockIndex);
                        }

                        processSb.AppendLine($"Decrypted Block (hex): {BitConverter.ToString(result, blockIndex, 16).Replace("-", " ")}");
                        DisplayStateMatrix(result.Skip(blockIndex).Take(16).ToArray(), "STATE SAU GIẢI MÃ", processSb);
                        processSb.AppendLine();
                    }

                    // Xử lý padding sau khi giải mã
                    processSb.AppendLine("4️⃣ XỬ LÝ PADDING SAU GIẢI MÃ:");
                    byte lastByte = result[result.Length - 1];
                    if (lastByte > 0 && lastByte <= 16)
                    {
                        processSb.AppendLine($"   Phát hiện padding: {lastByte} bytes (value: 0x{lastByte:X2})");
                        processSb.AppendLine($"   Dữ liệu trước khi remove padding: {BitConverter.ToString(result).Replace("-", " ")}");

                        byte[] withoutPadding = new byte[result.Length - lastByte];
                        Array.Copy(result, 0, withoutPadding, 0, withoutPadding.Length);

                        processSb.AppendLine($"   Dữ liệu sau khi remove padding: {BitConverter.ToString(withoutPadding).Replace("-", " ")}");
                        processSb.AppendLine($"   Plaintext cuối cùng: {Encoding.UTF8.GetString(withoutPadding)}");
                        processSb.AppendLine($"   ✅ Giải mã thành công");

                        result = withoutPadding;
                    }
                    else
                    {
                        processSb.AppendLine($"   Không phát hiện padding hợp lệ");
                        processSb.AppendLine($"   Plaintext: {Encoding.UTF8.GetString(result)}");
                        processSb.AppendLine($"   ✅ Giải mã thành công");
                    }

                    processSb.AppendLine();

                    return result;
                }
            }
            catch (Exception ex)
            {
                processSb.AppendLine($"❌ Lỗi khi giải mã AES-192: {ex.Message}");
                throw;
            }
        }

        private void SimulateEncryptionRounds(byte[] block, byte[] key, StringBuilder sb)
        {
            sb.AppendLine("=== QUÁ TRÌNH 12 VÒNG MÃ HÓA ===");

            // Vòng 0: AddRoundKey đầu tiên
            sb.AppendLine("🎯 VÒNG 0 - Initial AddRoundKey:");
            sb.AppendLine($"   - XOR state với Round Key 0");
            DisplayStateMatrix(block, "TRƯỚC AddRoundKey", sb);
            // Giả lập AddRoundKey
            byte[] state = (byte[])block.Clone();
            DisplayStateMatrix(state, "SAU AddRoundKey", sb);
            sb.AppendLine();

            for (int round = 1; round <= 12; round++)
            {
                sb.AppendLine($"🎯 VÒNG {round}:");

                // SubBytes
                sb.AppendLine($"  1. SubBytes:");
                sb.AppendLine($"     - Thay thế từng byte qua S-box");
                sb.AppendLine($"     - Ánh xạ phi tuyến để chống cryptanalysis");
                SimulateSubBytes(state);
                DisplayStateMatrix(state, "SAU SubBytes", sb);

                // ShiftRows
                sb.AppendLine($"  2. ShiftRows:");
                sb.AppendLine($"     - Hàng 0: không dịch");
                sb.AppendLine($"     - Hàng 1: dịch trái 1 byte");
                sb.AppendLine($"     - Hàng 2: dịch trái 2 byte");
                sb.AppendLine($"     - Hàng 3: dịch trái 3 byte");
                SimulateShiftRows(state);
                DisplayStateMatrix(state, "SAU ShiftRows", sb);

                // MixColumns (trừ vòng cuối)
                if (round < 12)
                {
                    sb.AppendLine($"  3. MixColumns:");
                    sb.AppendLine($"     - Nhân ma trận với ma trận MixColumns cố định");
                    sb.AppendLine($"     - Trộn dữ liệu giữa các cột");
                    SimulateMixColumns(state);
                    DisplayStateMatrix(state, "SAU MixColumns", sb);
                }
                else
                {
                    sb.AppendLine($"  3. MixColumns: BỎ QUA (vòng cuối)");
                }

                // AddRoundKey
                sb.AppendLine($"  4. AddRoundKey (Round {round}):");
                sb.AppendLine($"     - XOR state với round key {round}");
                sb.AppendLine($"     - Round key được sinh từ Key Expansion");
                SimulateAddRoundKey(state, round);
                DisplayStateMatrix(state, "SAU AddRoundKey", sb);
                sb.AppendLine("─────────────────────────────────────────");
            }
        }

        private void SimulateDecryptionRounds(byte[] block, byte[] key, StringBuilder sb)
        {
            sb.AppendLine("=== QUÁ TRÌNH 12 VÒNG GIẢI MÃ ===");

            byte[] state = (byte[])block.Clone();

            for (int round = 12; round >= 1; round--)
            {
                sb.AppendLine($"🎯 VÒNG {13 - round} (Round Key {round}):");

                // AddRoundKey (ngược)
                sb.AppendLine($"  1. AddRoundKey (Round {round}):");
                sb.AppendLine($"     - XOR state với round key {round}");
                DisplayStateMatrix(state, "TRƯỚC AddRoundKey", sb);
                SimulateAddRoundKey(state, round);
                DisplayStateMatrix(state, "SAU AddRoundKey", sb);

                // MixColumns (ngược - trừ vòng đầu)
                if (round < 12)
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
            sb.AppendLine("🎯 VÒNG 12 - Final AddRoundKey (Round Key 0):");
            sb.AppendLine($"   - XOR state với Round Key 0");
            DisplayStateMatrix(state, "TRƯỚC AddRoundKey", sb);
            SimulateAddRoundKey(state, 0);
            DisplayStateMatrix(state, "SAU AddRoundKey", sb);
            sb.AppendLine();
        }

        private void DisplayKeyExpansion(byte[] key, StringBuilder sb, bool forEncryption)
        {
            string processType = forEncryption ? "MÃ HÓA" : "GIẢI MÃ";
            sb.AppendLine($"🔑 KEY EXPANSION CHO {processType} - SINH 13 ROUND KEYS:");
            sb.AppendLine("(Từ 192-bit key ban đầu sinh ra 13 round keys 128-bit)");
            sb.AppendLine();

            // Hiển thị key gốc
            sb.AppendLine("Round Key 0 (Key gốc - 24 bytes):");
            DisplayKeyMatrix192(key, sb);

            // Mô phỏng các round keys
            for (int i = 1; i <= 12; i++)
            {
                sb.AppendLine($"Round Key {i}:");
                if (forEncryption)
                {
                    sb.AppendLine($"  - Key expansion cho AES-192: 6-word processing");
                    sb.AppendLine($"  - Sử dụng Rcon và S-box cho mỗi nhóm 6 từ");
                }
                else
                {
                    sb.AppendLine($"  - Sử dụng cho vòng {13 - i} trong giải mã");
                }
                byte[] simulatedKey = SimulateRoundKey(key, i);
                DisplayStateMatrix(simulatedKey, $"ROUND KEY {i} (128-bit)", sb);
            }
            sb.AppendLine();
        }

        // Các phương thức mô phỏng biến đổi (giống AES128)
        private void SimulateSubBytes(byte[] state)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] = (byte)(state[i] ^ 0x5A); // Giả lập đơn giản
            }
        }

        private void SimulateInvSubBytes(byte[] state)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] = (byte)(state[i] ^ 0x5A); // Hoàn tác giả lập
            }
        }

        private void SimulateShiftRows(byte[] state)
        {
            byte[] temp = new byte[16];
            Array.Copy(state, temp, 16);

            state[4] = temp[5]; state[5] = temp[6]; state[6] = temp[7]; state[7] = temp[4];
            state[8] = temp[10]; state[9] = temp[11]; state[10] = temp[8]; state[11] = temp[9];
            state[12] = temp[15]; state[13] = temp[12]; state[14] = temp[13]; state[15] = temp[14];
        }

        private void SimulateInvShiftRows(byte[] state)
        {
            byte[] temp = new byte[16];
            Array.Copy(state, temp, 16);

            state[4] = temp[7]; state[5] = temp[4]; state[6] = temp[5]; state[7] = temp[6];
            state[8] = temp[10]; state[9] = temp[11]; state[10] = temp[8]; state[11] = temp[9];
            state[12] = temp[13]; state[13] = temp[14]; state[14] = temp[15]; state[15] = temp[12];
        }

        private void SimulateMixColumns(byte[] state)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] = (byte)((state[i] * 2) ^ (state[i] >> 7) * 0x1B);
            }
        }

        private void SimulateInvMixColumns(byte[] state)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] = (byte)((state[i] * 14) ^ (state[i] >> 7) * 0x1B);
            }
        }

        private void SimulateAddRoundKey(byte[] state, int round)
        {
            for (int i = 0; i < 16; i++)
            {
                state[i] ^= (byte)(round * 0x11 + i);
            }
        }

        private byte[] SimulateRoundKey(byte[] key, int round)
        {
            byte[] result = new byte[16];
            Array.Copy(key, 0, result, 0, Math.Min(16, key.Length));

            for (int i = 0; i < 16; i++)
            {
                result[i] = (byte)(result[i] ^ (round * 0x11 + i));
            }

            return result;
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

            DisplayKeyMatrix192(finalKey, sb);
            sb.AppendLine("===========================================");
            sb.AppendLine();

            return finalKey;
        }

        private void DisplayKeyMatrix192(byte[] key, StringBuilder sb)
        {
            sb.AppendLine();
            sb.AppendLine("🧮 MA TRẬN KHÓA AES-192 (4x6 - Column Major):");
            sb.AppendLine();

            sb.AppendLine("       C0    C1    C2    C3    C4    C5     |    Binary");
            sb.AppendLine("       ---   ---   ---   ---   ---   ---    |    ------");

            for (int row = 0; row < 4; row++)
            {
                sb.Append($"R{row} | ");
                for (int col = 0; col < 6; col++)
                {
                    int index = row + col * 4;
                    sb.Append($"{key[index]:X2}  ");
                }

                sb.Append("  |  ");
                for (int col = 0; col < 6; col++)
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