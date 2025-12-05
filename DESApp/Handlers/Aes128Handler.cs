using System;
using System.Text;
using System.Security.Cryptography;

namespace DESApp.Handlers
{
    public partial class Aes128Handler : IEncryptionHandler
    {
        // ========================================================================
        // SỬA LỖI CS0535: Bổ sung thuộc tính AlgorithmName
        // ========================================================================
        public string AlgorithmName => "AES-128";

        // ========================================================================
        // A. CÁC BẢNG TRA CỨU (LOOKUP TABLES)
        // ========================================================================

        private static readonly byte[] SBOX = new byte[256] {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        private static readonly byte[] INV_SBOX = new byte[256] {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };

        private static readonly byte[] Rcon = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        };

        // ========================================================================
        // B. CÁC HÀM CỦA INTERFACE
        // ========================================================================

        public string GetKeyHint()
        {
            return "Khóa AES-128 cần 16 bytes (16 ký tự ASCII hoặc UTF-8).";
        }

        public byte[] Encrypt(byte[] plaintext, byte[] key, Encoding encoder, StringBuilder sb)
        {
            if (key.Length != 16)
            {
                throw new ArgumentException($"Key AES-128 phải đúng 16 bytes. Hiện tại: {key.Length} bytes.");
            }

            // Padding dữ liệu (PKCS7)
            byte[] paddedData = PadDataPKCS7(plaintext);

            // Sinh khóa (Key Expansion) - Đã cập nhật truyền sb
            sb.AppendLine("🔑 BẮT ĐẦU SINH KHÓA VÒNG (Key Expansion)...");
            byte[][] roundKeys = KeyExpansion(key, sb); // <--- THAY ĐỔI Ở ĐÂY
            sb.AppendLine("✅ Đã sinh đủ 11 Round Keys.");

            // Gọi hàm xử lý chi tiết
            return EncryptAes128StepByStep(paddedData, key, roundKeys, sb, 0);
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] key, Encoding encoder, StringBuilder sb)
        {
            if (key.Length != 16)
            {
                throw new ArgumentException($"Key AES-128 phải đúng 16 bytes. Hiện tại: {key.Length} bytes.");
            }

            // Sinh khóa (Key Expansion) - Đã cập nhật truyền sb
            // Lưu ý: Decrypt vẫn cần chạy KeyExpansion xuôi chiều
            byte[][] roundKeys = KeyExpansion(key, sb); // <--- THAY ĐỔI Ở ĐÂY

            // Gọi hàm xử lý chi tiết
            byte[] decryptedPadded = DecryptAes128StepByStep(ciphertext, key, roundKeys, sb);

            // Gỡ Padding
            try
            {
                return UnpadDataPKCS7(decryptedPadded);
            }
            catch
            {
                sb.AppendLine("⚠️ CẢNH BÁO: Lỗi Padding sau khi giải mã. Trả về dữ liệu gốc.");
                return decryptedPadded;
            }
        }

        // ========================================================================
        // 1. QUÁ TRÌNH MÃ HÓA (ENCRYPT)
        // ========================================================================
        private byte[] EncryptAes128StepByStep(byte[] paddedData, byte[] key, byte[][] roundKeys, StringBuilder sb, int segmentIndex)
        {
            sb.AppendLine("====================Tiền xử bản rõ================");
            sb.AppendLine($"Bản rõ đã đệm (Hex): {BitConverter.ToString(paddedData).Replace("-", " ")}");
            sb.AppendLine($"Tổng kích thước: {paddedData.Length} bytes");

            sb.AppendLine("📦 Các block sau khi tách (mỗi block 16 bytes):");
            int totalBlocks = paddedData.Length / 16;

            for (int b = 0; b < totalBlocks; b++)
            {
                byte[] blk = new byte[16];
                Array.Copy(paddedData, b * 16, blk, 0, 16);
                sb.AppendLine($"   Block {b + 1}: {BitConverter.ToString(blk).Replace("-", " ")}");
            }

            // In từng block 16 byte sau padding
            int blockCount = paddedData.Length / 16;
            for (int idx = 0; idx < blockCount; idx++)
            {
                byte[] blk = new byte[16];
                Array.Copy(paddedData, idx * 16, blk, 0, 16);
                sb.AppendLine($"Block {idx + 1}: {BitConverter.ToString(blk).Replace("-", " ")}");
            }


            sb.AppendLine("\n====================Tiền xử khoá================");
            sb.AppendLine($"Khoá ban đầu (Hex): {BitConverter.ToString(key).Replace("-", " ")}");
            sb.AppendLine("⚡ XỬ LÝ: Sử dụng 11 Round Keys đã tạo.");

            byte[] encryptedData = new byte[paddedData.Length];

            for (int i = 0; i < paddedData.Length; i += 16)
            {
                int blockIndex = (i / 16) + 1;
                byte[] block = new byte[16];
                Array.Copy(paddedData, i, block, 0, 16);

                sb.AppendLine($"\n==================== BẮT ĐẦU MÃ HÓA BLOCK {blockIndex}/{totalBlocks} ====================");
                DrawAsciiMatrix(block, "TRẠNG THÁI ĐẦU VÀO (INPUT STATE)", sb);

                // --- ROUND 0: AddRoundKey ---
                sb.AppendLine("\n--- VÒNG 0: AddRoundKey (Cộng khóa vòng) ---");
                DrawAsciiMatrix(roundKeys[0], "Khóa vòng 0 (Round Key 0)", sb);
                LogXorDetails(block, roundKeys[0], sb);
                AddRoundKey(block, roundKeys[0]);
                DrawAsciiMatrix(block, "Kết quả sau Vòng 0", sb);

                // --- ROUND 1 -> 9 ---
                for (int round = 1; round <= 9; round++)
                {
                    sb.AppendLine($"\n🎯 --- VÒNG {round} (STANDARD ROUND) ---");

                    // 1. SubBytes
                    sb.AppendLine($"\n-- SubBytes (Thế byte - Vòng {round}) --");
                    SubBytes(block, sb, round);
                    DrawAsciiMatrix(block, "Kết quả sau SubBytes", sb);

                    // 2. ShiftRows
                    sb.AppendLine($"\n-- ShiftRows (Dịch hàng - Vòng {round}) --");
                    ShiftRows(block);
                    DrawAsciiMatrix(block, "Kết quả sau ShiftRows", sb);

                    // 3. MixColumns
                    sb.AppendLine($"\n-- MixColumns (Trộn cột - Vòng {round}) --");
                    MixColumns(block, sb, round);
                    DrawAsciiMatrix(block, "Kết quả sau MixColumns", sb);

                    // 4. AddRoundKey
                    sb.AppendLine($"\n-- AddRoundKey (Cộng khóa vòng {round}) --");
                    DrawAsciiMatrix(roundKeys[round], $"Khóa vòng {round}", sb);
                    LogXorDetails(block, roundKeys[round], sb);
                    AddRoundKey(block, roundKeys[round]);
                    DrawAsciiMatrix(block, "Kết quả sau AddRoundKey", sb);
                }

                // --- ROUND 10: Final Round ---
                sb.AppendLine("\n🏁 --- VÒNG 10 (FINAL ROUND - Không MixColumns) ---");

                sb.AppendLine("\n-- SubBytes (Thế byte cuối) --");
                SubBytes(block, sb, 10);
                DrawAsciiMatrix(block, "Kết quả sau SubBytes", sb);

                sb.AppendLine("\n-- ShiftRows (Dịch hàng cuối) --");
                ShiftRows(block);
                DrawAsciiMatrix(block, "Kết quả sau ShiftRows", sb);

                sb.AppendLine("\n-- AddRoundKey (Cộng khóa vòng 10) --");
                DrawAsciiMatrix(roundKeys[10], "Khóa vòng 10", sb);
                LogXorDetails(block, roundKeys[10], sb);
                AddRoundKey(block, roundKeys[10]);
                DrawAsciiMatrix(block, "TRẠNG THÁI CUỐI CÙNG (CIPHERTEXT)", sb);

                Array.Copy(block, 0, encryptedData, i, 16);
            }

            return encryptedData;
        }

        // ========================================================================
        // 2. QUÁ TRÌNH GIẢI MÃ (DECRYPT)
        // ========================================================================
        private byte[] DecryptAes128StepByStep(byte[] ciphertext, byte[] key, byte[][] roundKeys, StringBuilder sb)
        {
            sb.AppendLine("\n🔓 ==================== BẮT ĐẦU GIẢI MÃ ====================");
            byte[] decryptedData = new byte[ciphertext.Length];

            for (int i = 0; i < ciphertext.Length; i += 16)
            {
                int blockIndex = (i / 16) + 1;
                byte[] block = new byte[16];
                Array.Copy(ciphertext, i, block, 0, 16);

                sb.AppendLine($"\n--- 🧩 GIẢI MÃ BLOCK {blockIndex} ---");
                DrawAsciiMatrix(block, "CIPHERTEXT ĐẦU VÀO", sb);

                // --- ROUND 0 (Ngược): AddRoundKey 10 ---
                sb.AppendLine("\n🎯 VÒNG ĐẦU TIÊN (Inverse Round 0):");
                sb.AppendLine("   Action: AddRoundKey (XOR với Key 10)");
                DrawAsciiMatrix(roundKeys[10], "Round Key 10", sb);
                LogXorDetails(block, roundKeys[10], sb);
                AddRoundKey(block, roundKeys[10]);
                DrawAsciiMatrix(block, "Sau AddRoundKey (Bắt đầu giải mã)", sb);

                // --- ROUND 1 -> 9 (Ngược) ---
                for (int round = 9; round >= 1; round--)
                {
                    sb.AppendLine($"\n🎯 VÒNG {10 - round} (INVERSE ROUND):");

                    // 1. InvShiftRows
                    sb.AppendLine("\n-- InvShiftRows (Dịch hàng ngược) --");
                    InvShiftRows(block);
                    DrawAsciiMatrix(block, "Sau InvShiftRows", sb);

                    // 2. InvSubBytes
                    sb.AppendLine("\n-- InvSubBytes (Thế byte ngược S-Box) --");
                    InvSubBytes(block);
                    DrawAsciiMatrix(block, "Sau InvSubBytes", sb);

                    // 3. AddRoundKey
                    sb.AppendLine($"\n-- AddRoundKey (Cộng khóa vòng {round}) --");
                    DrawAsciiMatrix(roundKeys[round], $"Round Key {round}", sb);
                    LogXorDetails(block, roundKeys[round], sb);
                    AddRoundKey(block, roundKeys[round]);
                    DrawAsciiMatrix(block, "Sau AddRoundKey", sb);

                    // 4. InvMixColumns
                    sb.AppendLine("\n-- InvMixColumns (Trộn cột ngược) --");
                    InvMixColumns(block);
                    DrawAsciiMatrix(block, "Sau InvMixColumns", sb);
                }

                // --- ROUND CUỐI (Inverse Final Round) ---
                sb.AppendLine("\n🏁 VÒNG CUỐI CÙNG (Inverse Final Round):");

                sb.AppendLine("\n-- InvShiftRows --");
                InvShiftRows(block);
                DrawAsciiMatrix(block, "Sau InvShiftRows", sb);

                sb.AppendLine("\n-- InvSubBytes --");
                InvSubBytes(block);
                DrawAsciiMatrix(block, "Sau InvSubBytes", sb);

                sb.AppendLine("\n-- AddRoundKey (Key 0) --");
                DrawAsciiMatrix(roundKeys[0], "Round Key 0", sb);
                LogXorDetails(block, roundKeys[0], sb);
                AddRoundKey(block, roundKeys[0]);

                DrawAsciiMatrix(block, "KẾT QUẢ GIẢI MÃ (PLAINTEXT)", sb);
                Array.Copy(block, 0, decryptedData, i, 16);
            }

            return decryptedData;
        }

        // ========================================================================
        // 3. HÀM HỖ TRỢ HIỂN THỊ
        // ========================================================================

        private void DrawAsciiMatrix(byte[] state, string title, StringBuilder sb)
        {
            sb.AppendLine($"{title}:");
            sb.AppendLine("╔════════════════════════╗");
            for (int r = 0; r < 4; r++)
            {
                sb.Append("║ ");
                for (int c = 0; c < 4; c++)
                {
                    int index = r + (c * 4);
                    sb.Append($"{state[index]:X2} ");
                    if (c < 3) sb.Append("   ");
                }
                sb.AppendLine("║");
            }
            sb.AppendLine("╚════════════════════════╝");
        }

        private void LogXorDetails(byte[] state, byte[] key, StringBuilder sb)
        {
            sb.AppendLine("Thực hiện XOR với state hiện tại:");
            for (int r = 0; r < 4; r++)
            {
                sb.Append($"• Hàng {r}: ");
                string stateRowStr = "";
                string keyRowStr = "";
                string resultRowStr = "";

                for (int c = 0; c < 4; c++)
                {
                    int idx = r + (c * 4);
                    stateRowStr += $"{state[idx]:X2} ";
                    keyRowStr += $"{key[idx]:X2} ";
                    byte res = (byte)(state[idx] ^ key[idx]);
                    resultRowStr += $"{res:X2} ";
                }
                sb.AppendLine($"[{stateRowStr.Trim()}] ⊕ [{keyRowStr.Trim()}] = [{resultRowStr.Trim()}]");
            }
        }

        // ========================================================================
        // 4. CÁC HÀM XỬ LÝ TOÁN HỌC & LOGIC PHỤ TRỢ
        // ========================================================================

        private byte[] PadDataPKCS7(byte[] input)
        {
            int blockSize = 16;
            int paddingLength = blockSize - (input.Length % blockSize);
            byte[] padded = new byte[input.Length + paddingLength];
            Array.Copy(input, padded, input.Length);
            for (int i = input.Length; i < padded.Length; i++)
            {
                padded[i] = (byte)paddingLength;
            }
            return padded;
        }

        private byte[] UnpadDataPKCS7(byte[] input)
        {
            if (input == null || input.Length == 0) return input;
            int paddingLength = input[input.Length - 1];
            if (paddingLength < 1 || paddingLength > 16) return input;

            byte[] output = new byte[input.Length - paddingLength];
            Array.Copy(input, output, output.Length);
            return output;
        }

        private string FormatHex(byte b) => b.ToString("X2");

        private string FormatXor4Bytes(byte[] a, int aOffset, byte[] b, int bOffset)
        {
            // aOffset and bOffset are offsets to 4-byte words
            string[] pieces = new string[4];
            for (int i = 0; i < 4; i++)
            {
                byte ba = a[aOffset + i];
                byte bb = b[bOffset + i];
                byte r = (byte)(ba ^ bb);
                pieces[i] = $"{FormatHex(ba)}⊕{FormatHex(bb)}={FormatHex(r)}";
            }
            return string.Join(", ", pieces);
        }
        private byte[][] KeyExpansion(byte[] originalKey, StringBuilder sb)
        {
            byte[][] roundKeys = new byte[11][];

            // --- ROUND 0 (w[0], w[1], w[2], w[3]) ---
            roundKeys[0] = new byte[16];
            Array.Copy(originalKey, roundKeys[0], 16);

            sb.AppendLine("\n--- Round 0 (Key gốc) ---");
            sb.AppendLine($"w[00] = {BitConverter.ToString(originalKey, 0, 4).Replace("-", "")}");
            sb.AppendLine($"w[01] = {BitConverter.ToString(originalKey, 4, 4).Replace("-", "")}");
            sb.AppendLine($"w[02] = {BitConverter.ToString(originalKey, 8, 4).Replace("-", "")}");
            sb.AppendLine($"w[03] = {BitConverter.ToString(originalKey, 12, 4).Replace("-", "")}");

            byte[] temp = new byte[4];

            // --- TÍNH TOÁN CÁC ROUND TIẾP THEO (Round 1 -> 10) ---
            for (int i = 1; i <= 10; i++)
            {
                sb.AppendLine($"\n--- Sinh Round Key {i} (w[{i * 4}] -> w[{i * 4 + 3}]) ---");

                roundKeys[i] = new byte[16];

                // Lấy w[i-1] (từ cuối cùng của round trước) để tính g()
                Array.Copy(roundKeys[i - 1], 12, temp, 0, 4);
                string tempStart = BitConverter.ToString(temp).Replace("-", "");

                // 1. RotWord
                RotWord(temp);
                string afterRot = BitConverter.ToString(temp).Replace("-", "");

                // 2. SubWord
                SubWord(temp);
                string afterSub = BitConverter.ToString(temp).Replace("-", "");

                // 3. XOR với Rcon[i]
                temp[0] ^= Rcon[i];
                string afterRcon = BitConverter.ToString(temp).Replace("-", "");

                // In chi tiết hàm g()
                sb.AppendLine($"  ⚠️ Tính g(w[{i * 4 - 1}]):");
                sb.AppendLine($"     Input (w[{i * 4 - 1}]) : {tempStart}");
                sb.AppendLine($"     RotWord         : {afterRot}");
                sb.AppendLine($"     SubWord         : {afterSub}");
                sb.AppendLine($"     XOR Rcon[{i:D2}]    : {afterRcon}");

                // --- Tính từ đầu tiên của Block (cột 1) ---
                // w[i] = w[i-4] XOR g(w[i-1])
                for (int j = 0; j < 4; j++)
                {
                    roundKeys[i][j] = (byte)(roundKeys[i - 1][j] ^ temp[j]);
                }
                // Log chi tiết byte-by-byte
                string leftWord = BitConverter.ToString(roundKeys[i - 1], 0, 4).Replace("-", "");
                string gWord = BitConverter.ToString(temp).Replace("-", "");
                string resultWord = BitConverter.ToString(roundKeys[i], 0, 4).Replace("-", "");
                string xorDetail = FormatXor4Bytes(roundKeys[i - 1], 0, temp, 0);
                sb.AppendLine($"  👉 w[{i * 4:D2}] = w[{i * 4 - 4:D2}] ⊕ g() = {resultWord}");
                sb.AppendLine($"     Chi tiết: {BitConverter.ToString(roundKeys[i - 1], 0, 4).Replace("-", " ")} ⊕ {BitConverter.ToString(temp).Replace("-", " ")}");
                sb.AppendLine($"     Byte XOR: {xorDetail}");

                // --- Tính 3 từ còn lại trong Block ---
                // w[i+col] = w[i+col-4] XOR w[i+col-1]
                for (int col = 1; col < 4; col++)
                {
                    for (int row = 0; row < 4; row++)
                    {
                        roundKeys[i][col * 4 + row] = (byte)(roundKeys[i - 1][col * 4 + row] ^ roundKeys[i][(col - 1) * 4 + row]);
                    }

                    // Log kết quả từng từ (với chi tiết byte-by-byte)
                    int currentW = i * 4 + col;
                    string left = BitConverter.ToString(roundKeys[i - 1], col * 4, 4).Replace("-", "");
                    string right = BitConverter.ToString(roundKeys[i], (col - 1) * 4, 4).Replace("-", "");
                    string val = BitConverter.ToString(roundKeys[i], col * 4, 4).Replace("-", "");
                    string detail = FormatXor4Bytes(roundKeys[i - 1], col * 4, roundKeys[i], (col - 1) * 4);
                    sb.AppendLine($"  👉 w[{currentW:D2}] = w[{currentW - 4:D2}] ⊕ w[{currentW - 1:D2}] = {val}");
                    sb.AppendLine($"     Chi tiết: {BitConverter.ToString(roundKeys[i - 1], col * 4, 4).Replace("-", " ")} ⊕ {BitConverter.ToString(roundKeys[i], (col - 1) * 4, 4).Replace("-", " ")}");
                    sb.AppendLine($"     Byte XOR: {detail}");
                }

                sb.AppendLine($"✅ Round Key {i}: {BitConverter.ToString(roundKeys[i]).Replace("-", " ")}");
            }
            return roundKeys;
        }

        private void RotWord(byte[] word)
        {
            byte temp = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = temp;
        }

        private void SubWord(byte[] word)
        {
            for (int i = 0; i < 4; i++) word[i] = SBOX[word[i]];
        }

        private void AddRoundKey(byte[] state, byte[] roundKey)
        {
            for (int i = 0; i < 16; i++) state[i] ^= roundKey[i];
        }

        private void SubBytes(byte[] state, StringBuilder sb, int round)
        {
            sb.AppendLine($"\n--- VÒNG {round}: SUBBYTES ---");
            sb.AppendLine("Giải thích chi tiết:");

            for (int i = 0; i < 16; i++)
            {
                byte original = state[i];
                byte substituted = SBOX[original];

                int r = i % 4;
                int c = i / 4;

                sb.AppendLine($"- Vị trí [{r},{c}]: {original:X2} tra S-Box → {substituted:X2}");

                state[i] = substituted;
            }

            // In ma trận sau SubBytes
            sb.AppendLine("=> Ma trận trạng thái sau SubBytes:");
            for (int r = 0; r < 4; r++)
            {
                sb.Append("   ");
                for (int c = 0; c < 4; c++)
                {
                    sb.Append($"{state[c * 4 + r]:X2} ");
                }
                sb.AppendLine();
            }
        }



        private void InvSubBytes(byte[] state)
        {
            for (int i = 0; i < 16; i++) state[i] = INV_SBOX[state[i]];
        }

        private void ShiftRows(byte[] state)
        {
            byte temp = state[1];
            state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;

            temp = state[2]; state[2] = state[10]; state[10] = temp;
            temp = state[6]; state[6] = state[14]; state[14] = temp;

            temp = state[15];
            state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
        }

        private void InvShiftRows(byte[] state)
        {
            byte temp = state[13];
            state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;

            temp = state[2]; state[2] = state[10]; state[10] = temp;
            temp = state[6]; state[6] = state[14]; state[14] = temp;

            temp = state[3];
            state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
        }

        // Helper: xtime (nhân 2 trong GF(2^8))
        private byte XTime(byte x)
        {
            byte result = (byte)((x << 1) & 0xFF);
            if ((x & 0x80) != 0)
                result ^= 0x1B;
            return result;
        }

        // Nhân trong GF(2^8) nhưng AES chỉ cần 1,2,3 -> tối ưu cho 1/2/3
        private byte GfMul(byte factor, byte value)
        {
            factor &= 0xFF;
            switch (factor)
            {
                case 1:
                    return value;
                case 2:
                    return XTime(value);
                case 3:
                    return (byte)(XTime(value) ^ value);
                default:
                    // Nếu cần hỗ trợ tổng quát hơn, implement bằng thuật toán nhân đa thức
                    byte result = 0;
                    byte a = value;
                    byte b = factor;
                    while (b != 0)
                    {
                        if ((b & 1) != 0) result ^= a;
                        a = XTime(a);
                        b >>= 1;
                    }
                    return result;
            }
        }

        private void MixColumns(byte[] state, StringBuilder sb, int round)
        {
            sb.AppendLine($"\n--- VÒNG {round}: MIXCOLUMNS ---");
            sb.AppendLine("Ma trận nhân (AES):");
            sb.AppendLine("[02 03 01 01]");
            sb.AppendLine("[01 02 03 01]");
            sb.AppendLine("[01 01 02 03]");
            sb.AppendLine("[03 01 01 02]");
            sb.AppendLine("");

            for (int c = 0; c < 4; c++)
            {
                // Lấy cột c (column-major): bytes order [row0, row1, row2, row3]
                byte[] col = new byte[4];
                for (int r = 0; r < 4; r++)
                    col[r] = state[c * 4 + r];

                sb.AppendLine($"Tính toán cho Cột {c} - Input Column: [{col[0]:X2}, {col[1]:X2}, {col[2]:X2}, {col[3]:X2}]");

                // Tính từng ô theo ma trận
                // Row 0: 02*col0 ⊕ 03*col1 ⊕ 01*col2 ⊕ 01*col3
                byte a0 = GfMul(0x02, col[0]);
                byte b0 = GfMul(0x03, col[1]);
                byte c0 = GfMul(0x01, col[2]);
                byte d0 = GfMul(0x01, col[3]);
                byte res0 = (byte)(a0 ^ b0 ^ c0 ^ d0);
                sb.AppendLine($" Phép tính ô [0,{c}]: (02*{col[0]:X2}) ⊕ (03*{col[1]:X2}) ⊕ (01*{col[2]:X2}) ⊕ (01*{col[3]:X2})");
                sb.AppendLine($"  - 02*{col[0]:X2} = {a0:X2}");
                sb.AppendLine($"  - 03*{col[1]:X2} = {b0:X2}");
                sb.AppendLine($"  - 01*{col[2]:X2} = {c0:X2}");
                sb.AppendLine($"  - 01*{col[3]:X2} = {d0:X2}");
                sb.AppendLine($"  => XOR: {a0:X2} ⊕ {b0:X2} ⊕ {c0:X2} ⊕ {d0:X2} = {res0:X2}");
                sb.AppendLine("");

                // Row 1: 01*col0 ⊕ 02*col1 ⊕ 03*col2 ⊕ 01*col3
                byte a1 = GfMul(0x01, col[0]);
                byte b1 = GfMul(0x02, col[1]);
                byte c1 = GfMul(0x03, col[2]);
                byte d1 = GfMul(0x01, col[3]);
                byte res1 = (byte)(a1 ^ b1 ^ c1 ^ d1);
                sb.AppendLine($" Phép tính ô [1,{c}]: (01*{col[0]:X2}) ⊕ (02*{col[1]:X2}) ⊕ (03*{col[2]:X2}) ⊕ (01*{col[3]:X2})");
                sb.AppendLine($"  - 01*{col[0]:X2} = {a1:X2}");
                sb.AppendLine($"  - 02*{col[1]:X2} = {b1:X2}");
                sb.AppendLine($"  - 03*{col[2]:X2} = {c1:X2}");
                sb.AppendLine($"  - 01*{col[3]:X2} = {d1:X2}");
                sb.AppendLine($"  => XOR: {a1:X2} ⊕ {b1:X2} ⊕ {c1:X2} ⊕ {d1:X2} = {res1:X2}");
                sb.AppendLine("");

                // Row 2: 01*col0 ⊕ 01*col1 ⊕ 02*col2 ⊕ 03*col3
                byte a2 = GfMul(0x01, col[0]);
                byte b2 = GfMul(0x01, col[1]);
                byte c2 = GfMul(0x02, col[2]);
                byte d2 = GfMul(0x03, col[3]);
                byte res2 = (byte)(a2 ^ b2 ^ c2 ^ d2);
                sb.AppendLine($" Phép tính ô [2,{c}]: (01*{col[0]:X2}) ⊕ (01*{col[1]:X2}) ⊕ (02*{col[2]:X2}) ⊕ (03*{col[3]:X2})");
                sb.AppendLine($"  - 01*{col[0]:X2} = {a2:X2}");
                sb.AppendLine($"  - 01*{col[1]:X2} = {b2:X2}");
                sb.AppendLine($"  - 02*{col[2]:X2} = {c2:X2}");
                sb.AppendLine($"  - 03*{col[3]:X2} = {d2:X2}");
                sb.AppendLine($"  => XOR: {a2:X2} ⊕ {b2:X2} ⊕ {c2:X2} ⊕ {d2:X2} = {res2:X2}");
                sb.AppendLine("");

                // Row 3: 03*col0 ⊕ 01*col1 ⊕ 01*col2 ⊕ 02*col3
                byte a3 = GfMul(0x03, col[0]);
                byte b3 = GfMul(0x01, col[1]);
                byte c3 = GfMul(0x01, col[2]);
                byte d3 = GfMul(0x02, col[3]);
                byte res3 = (byte)(a3 ^ b3 ^ c3 ^ d3);
                sb.AppendLine($" Phép tính ô [3,{c}]: (03*{col[0]:X2}) ⊕ (01*{col[1]:X2}) ⊕ (01*{col[2]:X2}) ⊕ (02*{col[3]:X2})");
                sb.AppendLine($"  - 03*{col[0]:X2} = {a3:X2}");
                sb.AppendLine($"  - 01*{col[1]:X2} = {b3:X2}");
                sb.AppendLine($"  - 01*{col[2]:X2} = {c3:X2}");
                sb.AppendLine($"  - 02*{col[3]:X2} = {d3:X2}");
                sb.AppendLine($"  => XOR: {a3:X2} ⊕ {b3:X2} ⊕ {c3:X2} ⊕ {d3:X2} = {res3:X2}");
                sb.AppendLine("");

                // Ghi kết quả trở lại state (column-major)
                state[c * 4 + 0] = res0;
                state[c * 4 + 1] = res1;
                state[c * 4 + 2] = res2;
                state[c * 4 + 3] = res3;

                sb.AppendLine($"Kết quả Cột {c} sau MixColumns: [{res0:X2}, {res1:X2}, {res2:X2}, {res3:X2}]");
                sb.AppendLine(new string('-', 40));
            }

            // In ma trận trạng thái sau MixColumns (4x4)
            sb.AppendLine("=> Ma trận trạng thái sau MixColumns:");
            for (int r = 0; r < 4; r++)
            {
                sb.Append("   ");
                for (int c = 0; c < 4; c++)
                    sb.Append($"{state[c * 4 + r]:X2} ");
                sb.AppendLine();
            }
        }


        private void InvMixColumns(byte[] state)
        {
            byte[] t = (byte[])state.Clone();
            for (int i = 0; i < 16; i += 4)
            {
                state[i] = (byte)(GMul(t[i], 0x0e) ^ GMul(t[i + 1], 0x0b) ^ GMul(t[i + 2], 0x0d) ^ GMul(t[i + 3], 0x09));
                state[i + 1] = (byte)(GMul(t[i], 0x09) ^ GMul(t[i + 1], 0x0e) ^ GMul(t[i + 2], 0x0b) ^ GMul(t[i + 3], 0x0d));
                state[i + 2] = (byte)(GMul(t[i], 0x0d) ^ GMul(t[i + 1], 0x09) ^ GMul(t[i + 2], 0x0e) ^ GMul(t[i + 3], 0x0b));
                state[i + 3] = (byte)(GMul(t[i], 0x0b) ^ GMul(t[i + 1], 0x0d) ^ GMul(t[i + 2], 0x09) ^ GMul(t[i + 3], 0x0e));
            }
        }

        private byte GMul(byte a, byte b)
        {
            byte p = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0) p ^= a;
                bool hi = (a & 0x80) != 0;
                a <<= 1;
                if (hi) a ^= 0x1B;
                b >>= 1;
            }
            return p;
        }
    }
}