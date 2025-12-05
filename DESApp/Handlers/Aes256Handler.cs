using System;
using System.Text;
using System.Security.Cryptography;

namespace DESApp.Handlers
{
    public partial class Aes256Handler : IEncryptionHandler
    {
        public string AlgorithmName => "AES-256";

        // ===============================
        // AES S-BOX & INV S-BOX
        // (Giữ nguyên từ Aes128Handler)
        // ===============================

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
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1B, 0x36
        };

        public string GetKeyHint()
        {
            return "Khóa AES-256 cần 32 bytes (32 ký tự UTF-8).";
        }

        public byte[] Encrypt(byte[] plaintext, byte[] key, Encoding encoder, StringBuilder sb)
        {
            if (key.Length != 32)
                throw new ArgumentException($"Key AES-256 phải đúng 32 bytes. Hiện tại: {key.Length} bytes.");

            // Padding
            byte[] padded = PadDataPKCS7(plaintext);

            // Key Expansion (60 words → 15 round keys)
            sb.AppendLine("🔑 BẮT ĐẦU SINH KHÓA VÒNG (AES-256)...");
            byte[][] roundKeys = KeyExpansion256(key, sb);
            sb.AppendLine("✅ Đã sinh đủ 15 Round Keys.");

            // Encrypt
            return EncryptAes256Step(padded, roundKeys, sb);
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] key, Encoding encoder, StringBuilder sb)
        {
            if (key.Length != 32)
                throw new ArgumentException($"Key AES-256 phải đúng 32 bytes. Hiện tại: {key.Length} bytes.");

            byte[][] roundKeys = KeyExpansion256(key, sb);

            byte[] decrypted = DecryptAes256Step(ciphertext, roundKeys, sb);

            return UnpadDataPKCS7(decrypted);
        }

        // ============================================================
        // 🔥 PHẦN 1 — ENCRYPT (14 rounds)
        // ============================================================
        private byte[] EncryptAes256Step(byte[] padded, byte[][] roundKeys, StringBuilder sb)
        {
            int blocks = padded.Length / 16;
            byte[] output = new byte[padded.Length];

            for (int i = 0; i < padded.Length; i += 16)
            {
                int blockIndex = (i / 16) + 1;
                byte[] state = new byte[16];
                Array.Copy(padded, i, state, 0, 16);

                sb.AppendLine($"\n==================== BLOCK {blockIndex}/{blocks} ====================");

                // ROUND 0
                sb.AppendLine("\n--- ROUND 0: AddRoundKey ---");
                AddRoundKey(state, roundKeys[0]);

                // ROUND 1 → 13
                for (int r = 1; r <= 13; r++)
                {
                    sb.AppendLine($"\n--- ROUND {r} ---");
                    SubBytes(state);
                    ShiftRows(state);
                    MixColumns(state);
                    AddRoundKey(state, roundKeys[r]);
                }

                // ROUND 14 (final)
                sb.AppendLine("\n--- ROUND 14 (FINAL) ---");
                SubBytes(state);
                ShiftRows(state);
                AddRoundKey(state, roundKeys[14]);

                Array.Copy(state, 0, output, i, 16);
            }
            return output;
        }

        // ============================================================
        // 🔥 PHẦN 2 — DECRYPT (ngược 14 rounds)
        // ============================================================
        private byte[] DecryptAes256Step(byte[] ciphertext, byte[][] roundKeys, StringBuilder sb)
        {
            byte[] output = new byte[ciphertext.Length];

            for (int i = 0; i < ciphertext.Length; i += 16)
            {
                int block = (i / 16) + 1;
                byte[] state = new byte[16];
                Array.Copy(ciphertext, i, state, 0, 16);

                sb.AppendLine($"\n===== GIẢI MÃ BLOCK {block} =====");

                // Round 14
                AddRoundKey(state, roundKeys[14]);
                InvShiftRows(state);
                InvSubBytes(state);

                // Round 13 → 1
                for (int r = 13; r >= 1; r--)
                {
                    AddRoundKey(state, roundKeys[r]);
                    InvMixColumns(state);
                    InvShiftRows(state);
                    InvSubBytes(state);
                }

                // Round 0
                AddRoundKey(state, roundKeys[0]);

                Array.Copy(state, 0, output, i, 16);
            }
            return output;
        }

        // ============================================================
        // 🔥 PHẦN 3 — KEY EXPANSION (AES-256)
        // ============================================================
        private byte[][] KeyExpansion256(byte[] key, StringBuilder sb)
        {
            sb.AppendLine("🔧 ĐANG SINH KEY EXPANSION CHO AES-256...");

            int Nk = 8;   // 32 bytes → 8 words
            int Nr = 14;  // số vòng
            int Nb = 4;   // mỗi round key = 4 words

            int totalWords = (Nr + 1) * Nb; // 60 words
            byte[][] roundKeys = new byte[Nr + 1][];

            uint[] W = new uint[totalWords];

            // Copy key gốc
            for (int i = 0; i < Nk; i++)
            {
                W[i] =
                    ((uint)key[i * 4] << 24) |
                    ((uint)key[i * 4 + 1] << 16) |
                    ((uint)key[i * 4 + 2] << 8) |
                    ((uint)key[i * 4 + 3]);
            }

            // Expand
            for (int i = Nk; i < totalWords; i++)
            {
                uint temp = W[i - 1];

                if (i % Nk == 0)
                {
                    temp = SubWord(RotWord(temp)) ^ ((uint)Rcon[i / Nk] << 24);
                }
                else if (i % Nk == 4)
                {
                    temp = SubWord(temp);
                }

                W[i] = W[i - Nk] ^ temp;
            }

            // Convert 60 words → 15 round keys × 16 bytes
            for (int r = 0; r <= Nr; r++)
            {
                roundKeys[r] = new byte[16];
                for (int c = 0; c < 4; c++)
                {
                    uint word = W[r * 4 + c];
                    roundKeys[r][4 * c + 0] = (byte)(word >> 24);
                    roundKeys[r][4 * c + 1] = (byte)(word >> 16);
                    roundKeys[r][4 * c + 2] = (byte)(word >> 8);
                    roundKeys[r][4 * c + 3] = (byte)(word);
                }
            }

            sb.AppendLine("✅ HOÀN THÀNH KEY EXPANSION (AES-256)");

            return roundKeys;
        }

        private uint RotWord(uint w)
        {
            return ((w << 8) | (w >> 24)) & 0xFFFFFFFF;
        }

        private uint SubWord(uint w)
        {
            return
                ((uint)SBOX[(w >> 24) & 0xFF] << 24) |
                ((uint)SBOX[(w >> 16) & 0xFF] << 16) |
                ((uint)SBOX[(w >> 8) & 0xFF] << 8) |
                ((uint)SBOX[w & 0xFF]);
        }

        // ============================================================
        // 🔥 PHẦN 4 — SubBytes, ShiftRows, MixColumns...
        // (Dùng lại y hệt từ Aes128Handler)
        // ============================================================

        private void SubBytes(byte[] s)
        {
            for (int i = 0; i < 16; i++)
                s[i] = SBOX[s[i]];
        }

        private void InvSubBytes(byte[] s)
        {
            for (int i = 0; i < 16; i++)
                s[i] = INV_SBOX[s[i]];
        }

        private void ShiftRows(byte[] s)
        {
            byte temp;

            // row1
            temp = s[1];
            s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = temp;

            // row2
            temp = s[2]; s[2] = s[10]; s[10] = temp;
            temp = s[6]; s[6] = s[14]; s[14] = temp;

            // row3
            temp = s[3];
            s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = temp;
        }

        private void InvShiftRows(byte[] s)
        {
            byte temp;

            temp = s[13];
            s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = temp;

            temp = s[2]; s[2] = s[10]; s[10] = temp;
            temp = s[6]; s[6] = s[14]; s[14] = temp;

            temp = s[3];
            s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = temp;
        }

        private void MixColumns(byte[] s)
        {
            for (int c = 0; c < 4; c++)
            {
                int i = c * 4;
                byte a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];

                s[i]     = (byte)(GMul(a0, 2) ^ GMul(a1, 3) ^ a2 ^ a3);
                s[i + 1] = (byte)(a0 ^ GMul(a1, 2) ^ GMul(a2, 3) ^ a3);
                s[i + 2] = (byte)(a0 ^ a1 ^ GMul(a2, 2) ^ GMul(a3, 3));
                s[i + 3] = (byte)(GMul(a0, 3) ^ a1 ^ a2 ^ GMul(a3, 2));
            }
        }

        private void InvMixColumns(byte[] s)
        {
            for (int c = 0; c < 4; c++)
            {
                int i = c * 4;
                byte a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];

                s[i]     = (byte)(GMul(a0, 14) ^ GMul(a1, 11) ^ GMul(a2, 13) ^ GMul(a3, 9));
                s[i + 1] = (byte)(GMul(a0, 9) ^ GMul(a1, 14) ^ GMul(a2, 11) ^ GMul(a3, 13));
                s[i + 2] = (byte)(GMul(a0, 13) ^ GMul(a1, 9) ^ GMul(a2, 14) ^ GMul(a3, 11));
                s[i + 3] = (byte)(GMul(a0, 11) ^ GMul(a1, 13) ^ GMul(a2, 9) ^ GMul(a3, 14));
            }
        }

        private byte GMul(byte a, byte b)
        {
            byte p = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                    p ^= a;

                bool hi = (a & 0x80) != 0;
                a <<= 1;
                if (hi) a ^= 0x1B;

                b >>= 1;
            }
            return p;
        }

        private void AddRoundKey(byte[] s, byte[] key)
        {
            for (int i = 0; i < 16; i++)
                s[i] ^= key[i];
        }

        private byte[] PadDataPKCS7(byte[] input)
        {
            int pad = 16 - (input.Length % 16);
            byte[] arr = new byte[input.Length + pad];
            Array.Copy(input, arr, input.Length);
            for (int i = input.Length; i < arr.Length; i++)
                arr[i] = (byte)pad;
            return arr;
        }

        private byte[] UnpadDataPKCS7(byte[] input)
        {
            int pad = input[input.Length - 1];
            byte[] arr = new byte[input.Length - pad];
            Array.Copy(input, arr, arr.Length);
            return arr;
        }
    }
}
