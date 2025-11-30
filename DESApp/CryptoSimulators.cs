using System;
using System.Linq;
using System.Text;
using System.Collections;
using System.Collections.Generic;

namespace DESApp.Services
{
    public static class CryptoSimulators
    {
        // ---------------------------
        // AES Helpers & Simulation
        // ---------------------------
        private static readonly byte[] AesSBox = new byte[256] {
            // 256-byte AES S-box
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
        };

        private static readonly byte[,] Rcon = new byte[,] {
            {0x00,0x00,0x00,0x00},
            {0x01,0x00,0x00,0x00},
            {0x02,0x00,0x00,0x00},
            {0x04,0x00,0x00,0x00},
            {0x08,0x00,0x00,0x00},
            {0x10,0x00,0x00,0x00},
            {0x20,0x00,0x00,0x00},
            {0x40,0x00,0x00,0x00},
            {0x80,0x00,0x00,0x00},
            {0x1B,0x00,0x00,0x00},
            {0x36,0x00,0x00,0x00}
        };



        private static byte GFMul(byte a, byte b)
        {
            // Multiply two bytes in GF(2^8)
            byte p = 0;
            byte hi_bit_set;
            for (int counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0) p ^= a;
                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0) a ^= 0x1B;
                b >>= 1;
            }
            return p;
        }

        private static void SubBytes(byte[] state)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = AesSBox[state[i]];
        }

        private static void ShiftRows(byte[] state)
        {
            byte[] temp = new byte[16];
            temp[0] = state[0]; temp[4] = state[4]; temp[8] = state[8]; temp[12] = state[12];
            temp[1] = state[5]; temp[5] = state[9]; temp[9] = state[13]; temp[13] = state[1];
            temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2]; temp[14] = state[6];
            temp[3] = state[15]; temp[7] = state[3]; temp[11] = state[7]; temp[15] = state[11];
            Buffer.BlockCopy(temp, 0, state, 0, 16);
        }

        private static void MixColumns(byte[] state)
        {
            for (int c = 0; c < 4; c++)
            {
                int col = c * 4;
                byte a0 = state[col + 0];
                byte a1 = state[col + 1];
                byte a2 = state[col + 2];
                byte a3 = state[col + 3];

                state[col + 0] = (byte)(GFMul(0x02, a0) ^ GFMul(0x03, a1) ^ a2 ^ a3);
                state[col + 1] = (byte)(a0 ^ GFMul(0x02, a1) ^ GFMul(0x03, a2) ^ a3);
                state[col + 2] = (byte)(a0 ^ a1 ^ GFMul(0x02, a2) ^ GFMul(0x03, a3));
                state[col + 3] = (byte)(GFMul(0x03, a0) ^ a1 ^ a2 ^ GFMul(0x02, a3));
            }
        }

        private static void AddRoundKey(byte[] state, byte[] roundKey, int roundIndex)
        {
            for (int i = 0; i < 16; i++)
                state[i] ^= roundKey[roundIndex * 16 + i];
        }

        // AES key expansion & simulate omitted here for brevity — keep as previous version
        public static byte[] ExpandKeyAes256(byte[] key)
        {
            if (key.Length != 32) throw new ArgumentException("AES-256 key must be 32 bytes.");
            int Nk = 8;
            int Nb = 4;
            int Nr = 14;
            int words = Nb * (Nr + 1);
            uint[] w = new uint[words];
            for (int i = 0; i < Nk; i++)
                w[i] = (uint)(key[4 * i] << 24 | key[4 * i + 1] << 16 | key[4 * i + 2] << 8 | key[4 * i + 3]);
            for (int i = Nk; i < words; i++)
            {
                uint temp = w[i - 1];
                if (i % Nk == 0) temp = SubWord(RotWord(temp)) ^ ((uint)Rcon[i / Nk, 0] << 24);
                else if (i % Nk == 4) temp = SubWord(temp);
                w[i] = w[i - Nk] ^ temp;
            }
            byte[] expanded = new byte[words * 4];
            for (int i = 0; i < words; i++)
            {
                expanded[4 * i + 0] = (byte)((w[i] >> 24) & 0xFF);
                expanded[4 * i + 1] = (byte)((w[i] >> 16) & 0xFF);
                expanded[4 * i + 2] = (byte)((w[i] >> 8) & 0xFF);
                expanded[4 * i + 3] = (byte)(w[i] & 0xFF);
            }
            return expanded;
        }

        private static uint RotWord(uint w) => ((w << 8) | (w >> 24));
        private static uint SubWord(uint w)
        {
            uint r = 0;
            r |= (uint)AesSBox[(w >> 24) & 0xFF] << 24;
            r |= (uint)AesSBox[(w >> 16) & 0xFF] << 16;
            r |= (uint)AesSBox[(w >> 8) & 0xFF] << 8;
            r |= (uint)AesSBox[w & 0xFF];
            return r;
        }

        // ========================
        // AES: detailed simulation with bit tables
        // ========================
        public static string SimulateAes256EncryptBlockDetailed(byte[] block16, byte[] key32)
        {
            if (block16.Length != 16) throw new ArgumentException("Block must be 16 bytes.");
            if (key32.Length != 32) throw new ArgumentException("Key must be 32 bytes.");

            var sb = new StringBuilder();
            sb.AppendLine("=== QUÁ TRÌNH MÃ HÓA AES-256 CHI TIẾT (BẢNG) ===");
            sb.AppendLine($"Plaintext (hex): {BitConverter.ToString(block16).Replace("-", " ")}");
            sb.AppendLine($"Key (hex):       {BitConverter.ToString(key32).Replace("-", " ")}");
            sb.AppendLine();

            // Expand key
            byte[] expandedKey = ExpandKeyAes256(key32);
            int Nr = 14;

            sb.AppendLine("===== BẢNG SINH KHÓA (Key Schedule) =====");
            sb.AppendLine($"Key expanded length: {expandedKey.Length} bytes ({Nr + 1} round keys)");
            sb.AppendLine();

            // Show initial key and round keys
            for (int i = 0; i <= Nr; i++)
            {
                byte[] roundKey = new byte[16];
                Buffer.BlockCopy(expandedKey, i * 16, roundKey, 0, 16);
                sb.AppendLine($"RoundKey[{i,2}]: {BytesToHex(roundKey)}");
            }
            sb.AppendLine();

            // Initial state
            byte[] state = (byte[])block16.Clone();

            sb.AppendLine("===== BẢNG TRẠNG THÁI (State) QUA CÁC VÒNG =====");

            // Initial AddRoundKey
            sb.AppendLine("--- Initial AddRoundKey ---");
            sb.AppendLine($"State trước:  {BytesToHex(state)}");
            sb.AppendLine($"RoundKey[0]:  {BytesToHex(expandedKey.Take(16).ToArray())}");
            AddRoundKey(state, expandedKey, 0);
            sb.AppendLine($"State sau:    {BytesToHex(state)}");
            sb.AppendLine();

            // Rounds 1 to Nr-1
            for (int round = 1; round <= Nr - 1; round++)
            {
                sb.AppendLine($"--- Round {round} ---");

                // SubBytes
                sb.AppendLine("SubBytes:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                byte[] stateBeforeSub = (byte[])state.Clone();
                SubBytes(state);
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");

                // Show S-box transformation details for first 4 bytes
                sb.AppendLine("  Chi tiết S-box (4 byte đầu):");
                for (int i = 0; i < 4; i++)
                {
                    sb.AppendLine($"    Byte[{i,2}]: {stateBeforeSub[i]:X2} -> {AesSBox[stateBeforeSub[i]]:X2}");
                }

                // ShiftRows
                sb.AppendLine("ShiftRows:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                byte[] stateBeforeShift = (byte[])state.Clone();
                ShiftRows(state);
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");

                // Show ShiftRows details
                sb.AppendLine("  Chi tiết dịch hàng:");
                sb.AppendLine($"    Hàng 0: giữ nguyên");
                sb.AppendLine($"    Hàng 1: dịch trái 1 - {stateBeforeShift[1]:X2},{stateBeforeShift[5]:X2},{stateBeforeShift[9]:X2},{stateBeforeShift[13]:X2} -> {state[1]:X2},{state[5]:X2},{state[9]:X2},{state[13]:X2}");
                sb.AppendLine($"    Hàng 2: dịch trái 2 - {stateBeforeShift[2]:X2},{stateBeforeShift[6]:X2},{stateBeforeShift[10]:X2},{stateBeforeShift[14]:X2} -> {state[2]:X2},{state[6]:X2},{state[10]:X2},{state[14]:X2}");
                sb.AppendLine($"    Hàng 3: dịch trái 3 - {stateBeforeShift[3]:X2},{stateBeforeShift[7]:X2},{stateBeforeShift[11]:X2},{stateBeforeShift[15]:X2} -> {state[3]:X2},{state[7]:X2},{state[11]:X2},{state[15]:X2}");

                // MixColumns
                sb.AppendLine("MixColumns:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                byte[] stateBeforeMix = (byte[])state.Clone();
                MixColumns(state);
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");

                // Show MixColumns details for first column
                sb.AppendLine("  Chi tiết MixColumns (cột 0):");
                byte a0 = stateBeforeMix[0], a1 = stateBeforeMix[1], a2 = stateBeforeMix[2], a3 = stateBeforeMix[3];
                sb.AppendLine($"    Input:  {a0:X2} {a1:X2} {a2:X2} {a3:X2}");
                sb.AppendLine($"    Output: {state[0]:X2} {state[1]:X2} {state[2]:X2} {state[3]:X2}");
                sb.AppendLine($"    Tính toán:");
                sb.AppendLine($"      Byte[0]: (02•{a0:X2}) ⊕ (03•{a1:X2}) ⊕ {a2:X2} ⊕ {a3:X2} = {state[0]:X2}");
                sb.AppendLine($"      Byte[1]: {a0:X2} ⊕ (02•{a1:X2}) ⊕ (03•{a2:X2}) ⊕ {a3:X2} = {state[1]:X2}");
                sb.AppendLine($"      Byte[2]: {a0:X2} ⊕ {a1:X2} ⊕ (02•{a2:X2}) ⊕ (03•{a3:X2}) = {state[2]:X2}");
                sb.AppendLine($"      Byte[3]: (03•{a0:X2}) ⊕ {a1:X2} ⊕ {a2:X2} ⊕ (02•{a3:X2}) = {state[3]:X2}");

                // AddRoundKey
                sb.AppendLine("AddRoundKey:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                byte[] roundKey = expandedKey.Skip(round * 16).Take(16).ToArray();
                sb.AppendLine($"  RoundKey[{round}]: {BytesToHex(roundKey)}");
                AddRoundKey(state, expandedKey, round);
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");
                sb.AppendLine();
            }

            // Final round (no MixColumns)
            sb.AppendLine($"--- Round {Nr} (Final) ---");

            // SubBytes
            sb.AppendLine("SubBytes:");
            sb.AppendLine($"  State trước:  {BytesToHex(state)}");
            SubBytes(state);
            sb.AppendLine($"  State sau:    {BytesToHex(state)}");

            // ShiftRows
            sb.AppendLine("ShiftRows:");
            sb.AppendLine($"  State trước:  {BytesToHex(state)}");
            ShiftRows(state);
            sb.AppendLine($"  State sau:    {BytesToHex(state)}");

            // Final AddRoundKey
            sb.AppendLine("AddRoundKey (Final):");
            sb.AppendLine($"  State trước:  {BytesToHex(state)}");
            byte[] finalRoundKey = expandedKey.Skip(Nr * 16).Take(16).ToArray();
            sb.AppendLine($"  RoundKey[{Nr}]: {BytesToHex(finalRoundKey)}");
            AddRoundKey(state, expandedKey, Nr);
            sb.AppendLine($"  Ciphertext:   {BytesToHex(state)}");
            sb.AppendLine();

            sb.AppendLine("=== KẾT THÚC MÃ HÓA AES-256 ===");
            return sb.ToString();
        }

        // Helper method to display state as matrix
        private static string StateToMatrixString(byte[] state)
        {
            var sb = new StringBuilder();
            sb.AppendLine("State Matrix:");
            for (int row = 0; row < 4; row++)
            {
                sb.Append("  ");
                for (int col = 0; col < 4; col++)
                {
                    sb.Append($"{state[row + col * 4]:X2} ");
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }

        // Method to show GF(2^8) multiplication details
        private static string GFMulDetails(byte a, byte b, byte result)
        {
            return $"{a:X2} × {b:X2} = {result:X2}";
        }

        private static string BytesToHex(byte[] b) => string.Join(" ", b.Select(x => x.ToString("X2")));

        // ---------------------------
        // DES / 3DES Simulation (educational)
        // ---------------------------

        // DES tables (IP, FP, E, S-boxes, P, PC-1, PC-2, shifts)
        private static readonly int[] IP = {
            58,50,42,34,26,18,10,2,
            60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,
            64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,
            59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,
            63,55,47,39,31,23,15,7
        };

        private static readonly int[] FP = {
            40,8,48,16,56,24,64,32,
            39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,
            37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,
            35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,
            33,1,41,9,49,17,57,25
        };

        private static readonly int[] E = {
            32,1,2,3,4,5,
            4,5,6,7,8,9,
            8,9,10,11,12,13,
            12,13,14,15,16,17,
            16,17,18,19,20,21,
            20,21,22,23,24,25,
            24,25,26,27,28,29,
            28,29,30,31,32,1
        };

        private static readonly int[,] SBoxes = new int[8, 64] {
            // S1
            {
                14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
                0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
                4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
                15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
            },
            // S2
            {
                15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
                3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
                0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
                13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
            },
            // S3
            {
                10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
                13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
                13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
                1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
            },
            // S4
            {
                7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
                13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
                10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
                3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
            },
            // S5
            {
                2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
                14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
                4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
                11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
            },
            // S6
            {
                12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
                10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
                9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
                4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
            },
            // S7
            {
                4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
                13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
                1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
                6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
            },
            // S8
            {
                13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
                1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
                7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
                2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
            }
        };

        private static readonly int[] P = {
            16,7,20,21,29,12,28,17,
            1,15,23,26,5,18,31,10,
            2,8,24,14,32,27,3,9,
            19,13,30,6,22,11,4,25
        };

        private static readonly int[] PC1 = {
            57,49,41,33,25,17,9,
            1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4
        };

        private static readonly int[] PC2 = {
            14,17,11,24,1,5,
            3,28,15,6,21,10,
            23,19,12,4,26,8,
            16,7,27,20,13,2,
            41,52,31,37,47,55,
            30,40,51,45,33,48,
            44,49,39,56,34,53,
            46,42,50,36,29,32
        };

        private static readonly int[] LeftShifts = {
            1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
        };

        // Helper bit ops (1-based pos for Permute/Set/Get)
        private static int GetBit(byte[] src, int pos)
        {
            pos--;
            int byteIndex = pos / 8;
            int bitIndex = 7 - (pos % 8);
            return (src[byteIndex] >> bitIndex) & 1;
        }

        private static void SetBit(byte[] dest, int pos, int val)
        {
            pos--;
            int byteIndex = pos / 8;
            int bitIndex = 7 - (pos % 8);
            if (val == 1) dest[byteIndex] |= (byte)(1 << bitIndex);
            else dest[byteIndex] &= (byte)~(1 << bitIndex);
        }

        private static byte[] Permute(byte[] input, int[] table)
        {
            int outLen = table.Length / 8;
            byte[] outb = new byte[outLen];
            for (int i = 0; i < table.Length; i++)
            {
                int bit = GetBit(input, table[i]);
                SetBit(outb, i + 1, bit);
            }
            return outb;
        }

        private static byte[] PC1Permute(byte[] key8) => Permute(key8, PC1);
        private static byte[] PC2Permute(byte[] key56) => Permute(key56, PC2);

        private static byte[] LeftRotate28(byte[] half28, int shift)
        {
            int val = 0;
            for (int i = 0; i < 4; i++) val = (val << 8) | half28[i];
            val &= 0x0FFFFFFF;
            val = ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;
            byte[] outb = new byte[4];
            outb[0] = (byte)((val >> 24) & 0xFF);
            outb[1] = (byte)((val >> 16) & 0xFF);
            outb[2] = (byte)((val >> 8) & 0xFF);
            outb[3] = (byte)(val & 0xFF);
            return outb;
        }

        private static byte[] GenerateSubkeysForDes(byte[] key8)
        {
            var pc1 = PC1Permute(key8);
            byte[] c = new byte[4];
            byte[] d = new byte[4];
            for (int i = 0; i < 28; i++)
            {
                int bit = GetBit(pc1, i + 1);
                SetBit(c, i + 1, bit);
            }
            for (int i = 0; i < 28; i++)
            {
                int bit = GetBit(pc1, 28 + i + 1);
                SetBit(d, i + 1, bit);
            }
            byte[] subkeys = new byte[16 * 6];
            for (int round = 0; round < 16; round++)
            {
                c = LeftRotate28(c, LeftShifts[round]);
                d = LeftRotate28(d, LeftShifts[round]);
                byte[] cd = new byte[7];
                for (int i = 0; i < 28; i++) SetBit(cd, i + 1, GetBit(c, i + 1));
                for (int i = 0; i < 28; i++) SetBit(cd, 28 + i + 1, GetBit(d, i + 1));
                var sub = PC2Permute(cd);
                Buffer.BlockCopy(sub, 0, subkeys, round * 6, 6);
            }
            return subkeys;
        }

        private static byte[] ExpandBlockTo48(byte[] right32)
        {
            byte[] outb = new byte[6];
            for (int i = 0; i < 48; i++)
            {
                int bit = GetBit(right32, E[i]);
                SetBit(outb, i + 1, bit);
            }
            return outb;
        }

        private static byte[] SBoxSubstitution(byte[] sixBytes)
        {
            int[] bits = new int[48];
            for (int i = 0; i < 48; i++) bits[i] = GetBit(sixBytes, i + 1);
            int[] outputBits = new int[32];
            for (int s = 0; s < 8; s++)
            {
                int start = s * 6;
                int row = (bits[start] << 1) | bits[start + 5];
                int col = (bits[start + 1] << 3) | (bits[start + 2] << 2) | (bits[start + 3] << 1) | bits[start + 4];
                int val = SBoxes[s, row * 16 + col];
                for (int b = 0; b < 4; b++) outputBits[s * 4 + (3 - b)] = (val >> b) & 1;
            }
            byte[] outb = new byte[4];
            for (int i = 0; i < 32; i++) SetBit(outb, i + 1, outputBits[i]);
            return outb;
        }

        private static byte[] ApplyPermutationP(byte[] in4)
        {
            byte[] out4 = new byte[4];
            for (int i = 0; i < 32; i++)
            {
                int bit = GetBit(in4, P[i]);
                SetBit(out4, i + 1, bit);
            }
            return out4;
        }

        private static byte[] FeistelFunction(byte[] right32, byte[] subkey6)
        {
            var expanded = ExpandBlockTo48(right32);
            for (int i = 0; i < 6; i++) expanded[i] ^= subkey6[i];
            var sboxed = SBoxSubstitution(expanded);
            var permuted = ApplyPermutationP(sboxed);
            return permuted;
        }

        private static string BytesToHexShort(byte[] b) => string.Join(" ", b.Select(x => x.ToString("X2")));

        private static void SplitBlock(byte[] block8, out byte[] left32, out byte[] right32)
        {
            left32 = new byte[4];
            right32 = new byte[4];
            Buffer.BlockCopy(block8, 0, left32, 0, 4);
            Buffer.BlockCopy(block8, 4, right32, 0, 4);
        }

        private static byte[] JoinLeftRight(byte[] left32, byte[] right32)
        {
            byte[] outb = new byte[8];
            Buffer.BlockCopy(left32, 0, outb, 0, 4);
            Buffer.BlockCopy(right32, 0, outb, 4, 4);
            return outb;
        }

        private static byte[] InitialPermutation(byte[] block8) => Permute(block8, IP);
        private static byte[] FinalPermutation(byte[] block8) => Permute(block8, FP);

        // ========== Helpers to convert bytes <-> big-endian bit arrays ==========
        private static BitArray BitsFromBytesBE(byte[] src, int bitCount)
        {
            bool[] bits = new bool[bitCount];
            for (int i = 0; i < bitCount; i++)
            {
                int byteIdx = i / 8;
                int bitIdx = 7 - (i % 8);
                bits[i] = ((src[byteIdx] >> bitIdx) & 1) == 1;
            }
            return new BitArray(bits);
        }

        private static string BitArrayToString(BitArray bits)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < bits.Length; i++) sb.Append(bits[i] ? '1' : '0');
            return sb.ToString();
        }

        private static string PadRight(string s, int width)
        {
            if (s.Length >= width) return s;
            return s + new string(' ', width - s.Length);
        }

        // ========================
        // DES: detailed column tables
        // ========================
        public static string SimulateDesEncryptBlock(byte[] block, byte[] key)
        {
            if (block.Length != 8) throw new ArgumentException("Block must be 8 bytes.");
            if (key.Length != 8) throw new ArgumentException("Key must be 8 bytes.");

            var sb = new StringBuilder();
            sb.AppendLine("=== QUÁ TRÌNH MÃ HÓA DES CHI TIẾT (BẢNG) ===");
            sb.AppendLine($"Plaintext (hex): {BitConverter.ToString(block).Replace("-", " ")} ");
            sb.AppendLine($"Key (hex):       {BitConverter.ToString(key).Replace("-", " ")} ");
            sb.AppendLine();

            // 1) PC-1 and split into C0/D0 (as bytes)
            var pc1 = PC1Permute(key);
            byte[] c = new byte[4];
            byte[] d = new byte[4];
            for (int i = 0; i < 28; i++) SetBit(c, i + 1, GetBit(pc1, i + 1));
            for (int i = 0; i < 28; i++) SetBit(d, i + 1, GetBit(pc1, 28 + i + 1));

            // We'll collect C[i], D[i], K[i] as BitArray strings for column output
            var cList = new List<BitArray>();
            var dList = new List<BitArray>();
            var kList = new List<BitArray>();

            // 2) Key schedule rounds
            for (int round = 0; round < 16; round++)
            {
                c = LeftRotate28(c, LeftShifts[round]);
                d = LeftRotate28(d, LeftShifts[round]);

                // combine c + d into 56-bit and PC-2 permute to get 48-bit subkey
                byte[] cd = new byte[7];
                for (int i = 0; i < 28; i++) SetBit(cd, i + 1, GetBit(c, i + 1));
                for (int i = 0; i < 28; i++) SetBit(cd, 28 + i + 1, GetBit(d, i + 1));
                var sub = PC2Permute(cd); // 6 bytes

                // convert to BitArray big-endian
                var cBits = BitsFromBytesBE(c, 28);
                var dBits = BitsFromBytesBE(d, 28);
                var kBits = BitsFromBytesBE(sub, 48);

                cList.Add(cBits);
                dList.Add(dBits);
                kList.Add(kBits);
            }

            // Print key schedule table header
            sb.AppendLine("===== BẢNG SINH KHÓA (C1..C16 | D1..D16 | K1..K16) =====");
            // compute column widths
            int roundColW = 6;
            int cW = 28;
            int dW = 28;
            int kW = 48;
            string header = PadRight("Round", roundColW) + " | " + PadRight("C (28b)", cW) + " | " + PadRight("D (28b)", dW) + " | " + PadRight("K (48b)", kW);
            sb.AppendLine(header);
            sb.AppendLine(new string('-', header.Length));

            for (int i = 0; i < 16; i++)
            {
                string r = PadRight((i + 1).ToString(), roundColW);
                string cstr = BitArrayToString(cList[i]);
                string dstr = BitArrayToString(dList[i]);
                string kstr = BitArrayToString(kList[i]);
                sb.AppendLine($"{r} | {cstr} | {dstr} | {kstr}");
            }
            sb.AppendLine();

            // 3) IP and Feistel rounds, collect L/R
            sb.AppendLine("===== BẢNG VÒNG MÃ HÓA (L0..L16 | R0..R16) =====");
            byte[] ip = InitialPermutation(block);
            byte[] L = new byte[4];
            byte[] R = new byte[4];
            Buffer.BlockCopy(ip, 0, L, 0, 4);
            Buffer.BlockCopy(ip, 4, R, 0, 4);

            var Llist = new List<BitArray> { BitsFromBytesBE(L, 32) };
            var Rlist = new List<BitArray> { BitsFromBytesBE(R, 32) };

            // Need subkeys for rounds as byte[] sequences (we already computed kList bits but we also need actual 6-byte arrays)
            byte[] allSubkeys = GenerateSubkeysForDes(key); // 16 * 6 bytes

            for (int round = 0; round < 16; round++)
            {
                byte[] subkey = new byte[6];
                Buffer.BlockCopy(allSubkeys, round * 6, subkey, 0, 6);
                byte[] fOut = FeistelFunction(R, subkey); // 4 bytes
                byte[] newR = new byte[4];
                for (int i = 0; i < 4; i++) newR[i] = (byte)(L[i] ^ fOut[i]);
                L = R;
                R = newR;
                Llist.Add(BitsFromBytesBE(L, 32));
                Rlist.Add(BitsFromBytesBE(R, 32));
            }

            // Print L/R table header
            int lrRoundW = 6;
            int lrW = 32;
            string lrHeader = PadRight("Round", lrRoundW) + " | " + PadRight("L (32b)", lrW) + " | " + PadRight("R (32b)", lrW);
            sb.AppendLine(lrHeader);
            sb.AppendLine(new string('-', lrHeader.Length));
            for (int i = 0; i < Llist.Count; i++)
            {
                string r = PadRight(i.ToString(), lrRoundW);
                string lstr = BitArrayToString(Llist[i]);
                string rstr = BitArrayToString(Rlist[i]);
                sb.AppendLine($"{r} | {lstr} | {rstr}");
            }
            sb.AppendLine();

            // 4) Final permute to get cipher block
            var preout = JoinLeftRight(R, L); // note swap
            var fp = FinalPermutation(preout);
            sb.AppendLine($"Cipher block (hex): {BytesToHexShort(fp)}");
            sb.AppendLine("=== KẾT THÚC MÃ HÓA DES ===");
            return sb.ToString();
        }

        // Decrypt simulation: similarly prints key schedule + L/R but rounds reversed for decrypt log clarity
        public static string SimulateDesDecryptBlock(byte[] block, byte[] key)
        {
            if (block.Length != 8) throw new ArgumentException("Block must be 8 bytes.");
            if (key.Length != 8) throw new ArgumentException("Key must be 8 bytes.");

            var sb = new StringBuilder();
            sb.AppendLine("=== QUÁ TRÌNH GIẢI MÃ DES CHI TIẾT (BẢNG) ===");
            sb.AppendLine($"Ciphertext (hex): {BitConverter.ToString(block).Replace("-", " ")} ");
            sb.AppendLine($"Key (hex):        {BitConverter.ToString(key).Replace("-", " ")} ");
            sb.AppendLine();

            // Build subkeys / C/D/K as in encrypt, because decrypt uses reverse order
            var pc1 = PC1Permute(key);
            byte[] c = new byte[4];
            byte[] d = new byte[4];
            for (int i = 0; i < 28; i++) SetBit(c, i + 1, GetBit(pc1, i + 1));
            for (int i = 0; i < 28; i++) SetBit(d, i + 1, GetBit(pc1, 28 + i + 1));

            var cList = new List<BitArray>();
            var dList = new List<BitArray>();
            var kList = new List<BitArray>();
            var allSubkeys = new List<byte[]>();

            for (int round = 0; round < 16; round++)
            {
                c = LeftRotate28(c, LeftShifts[round]);
                d = LeftRotate28(d, LeftShifts[round]);
                byte[] cd = new byte[7];
                for (int i = 0; i < 28; i++) SetBit(cd, i + 1, GetBit(c, i + 1));
                for (int i = 0; i < 28; i++) SetBit(cd, 28 + i + 1, GetBit(d, i + 1));
                var sub = PC2Permute(cd); // 6 bytes
                cList.Add(BitsFromBytesBE(c, 28));
                dList.Add(BitsFromBytesBE(d, 28));
                kList.Add(BitsFromBytesBE(sub, 48));
                allSubkeys.Add(sub);
            }

            // print key schedule
            sb.AppendLine("===== BẢNG SINH KHÓA (C1..C16 | D1..D16 | K1..K16) =====");
            int roundColW = 6; int cW = 28; int dW = 28; int kW = 48;
            string header = PadRight("Round", roundColW) + " | " + PadRight("C (28b)", cW) + " | " + PadRight("D (28b)", dW) + " | " + PadRight("K (48b)", kW);
            sb.AppendLine(header);
            sb.AppendLine(new string('-', header.Length));
            for (int i = 0; i < 16; i++)
            {
                string r = PadRight((i + 1).ToString(), roundColW);
                string cstr = BitArrayToString(cList[i]);
                string dstr = BitArrayToString(dList[i]);
                string kstr = BitArrayToString(kList[i]);
                sb.AppendLine($"{r} | {cstr} | {dstr} | {kstr}");
            }
            sb.AppendLine();

            // IP and L/R rounds (for decrypt, iterate using subkeys in reverse)
            sb.AppendLine("===== BẢNG VÒNG GIẢI MÃ (L0..L16 | R0..R16) =====");
            byte[] ip = InitialPermutation(block);
            byte[] L = new byte[4]; byte[] R = new byte[4];
            Buffer.BlockCopy(ip, 0, L, 0, 4); Buffer.BlockCopy(ip, 4, R, 0, 4);
            var Llist = new List<BitArray> { BitsFromBytesBE(L, 32) };
            var Rlist = new List<BitArray> { BitsFromBytesBE(R, 32) };

            // subkeys are generated earlier in allSubkeys (K1..K16), but decrypt uses K16..K1
            for (int round = 15; round >= 0; round--)
            {
                byte[] subkey = allSubkeys[round];
                byte[] fOut = FeistelFunction(R, subkey);
                byte[] newR = new byte[4];
                for (int i = 0; i < 4; i++) newR[i] = (byte)(L[i] ^ fOut[i]);
                L = R;
                R = newR;
                Llist.Add(BitsFromBytesBE(L, 32));
                Rlist.Add(BitsFromBytesBE(R, 32));
            }

            int lrRoundW = 6; int lrW = 32;
            string lrHeader = PadRight("Round", lrRoundW) + " | " + PadRight("L (32b)", lrW) + " | " + PadRight("R (32b)", lrW);
            sb.AppendLine(lrHeader);
            sb.AppendLine(new string('-', lrHeader.Length));
            for (int i = 0; i < Llist.Count; i++)
            {
                string r = PadRight(i.ToString(), lrRoundW);
                string lstr = BitArrayToString(Llist[i]);
                string rstr = BitArrayToString(Rlist[i]);
                sb.AppendLine($"{r} | {lstr} | {rstr}");
            }
            sb.AppendLine();

            // final permutation
            var preout = JoinLeftRight(R, L);
            var fp = FinalPermutation(preout);
            sb.AppendLine($"Plaintext block (hex): {BytesToHexShort(fp)}");
            sb.AppendLine("=== KẾT THÚC GIẢI MÃ DES ===");
            return sb.ToString();
        }

        // 3DES simulation kept (uses DES helper functions)
        public static string Simulate3DesEncryptBlock(byte[] block8, byte[] key24)
        {
            if (block8.Length != 8) throw new ArgumentException("Block must be 8 bytes.");
            if (key24.Length != 24) throw new ArgumentException("3DES key must be 24 bytes.");

            byte[] k1 = key24.Take(8).ToArray();
            byte[] k2 = key24.Skip(8).Take(8).ToArray();
            byte[] k3 = key24.Skip(16).Take(8).ToArray();

            var sb = new StringBuilder();
            sb.AppendLine("=== 3DES Simulation (E(K1) D(K2) E(K3)) ===");
            sb.AppendLine($"Plaintext block: {BytesToHexShort(block8)}");
            sb.AppendLine($"K1: {BytesToHexShort(k1)}");
            sb.AppendLine($"K2: {BytesToHexShort(k2)}");
            sb.AppendLine($"K3: {BytesToHexShort(k3)}");
            sb.AppendLine();

            sb.AppendLine("---- DES encrypt with K1 (round details) ----");
            sb.AppendLine(SimulateDesEncryptBlock(block8, k1));
            byte[] cipher1 = DesEncryptBlockBytes(block8, k1);

            sb.AppendLine("---- DES decrypt with K2 (round details) ----");
            sb.AppendLine(SimulateDesDecryptBlock(cipher1, k2));
            byte[] plain2 = DesDecryptBlockBytes(cipher1, k2);

            sb.AppendLine("---- DES encrypt with K3 (round details) ----");
            sb.AppendLine(SimulateDesEncryptBlock(plain2, k3));
            byte[] cipher3 = DesEncryptBlockBytes(plain2, k3);

            sb.AppendLine($"Final 3DES Cipher block: {BytesToHexShort(cipher3)}");
            sb.AppendLine("=== End 3DES Simulation ===");
            return sb.ToString();
        }

        // Lightweight DES encrypt/decrypt returning bytes (used for chaining in 3DES)
        private static byte[] DesEncryptBlockBytes(byte[] block8, byte[] key8)
        {
            var ip = InitialPermutation(block8);
            SplitBlock(ip, out byte[] L, out byte[] R);
            var subkeys = GenerateSubkeysForDes(key8);
            for (int round = 0; round < 16; round++)
            {
                byte[] subkey = new byte[6];
                Buffer.BlockCopy(subkeys, round * 6, subkey, 0, 6);
                var fOut = FeistelFunction(R, subkey);
                byte[] newR = new byte[4];
                for (int i = 0; i < 4; i++) newR[i] = (byte)(L[i] ^ fOut[i]);
                L = R;
                R = newR;
            }
            var preout = JoinLeftRight(R, L);
            var fp = FinalPermutation(preout);
            return fp;
        }

        public static byte[] PublicDesEncryptBlockBytes(byte[] block8, byte[] key8)
        {
            if (block8.Length != 8) throw new ArgumentException("Block must be 8 bytes.");
            if (key8.Length != 8) throw new ArgumentException("Key must be 8 bytes.");
            return DesEncryptBlockBytes(block8, key8);
        }

        // Thêm vào class CryptoSimulators (cuối file, trước dòng "End of class")
        public static byte[] PublicDesDecryptBlockBytes(byte[] block8, byte[] key8)
        {
            if (block8.Length != 8) throw new ArgumentException("Block must be 8 bytes.");
            if (key8.Length != 8) throw new ArgumentException("Key must be 8 bytes.");
            return DesDecryptBlockBytes(block8, key8);
        }

        public static byte[] DesDecryptBlockBytes(byte[] block8, byte[] key8)
        {
            var ip = InitialPermutation(block8);
            SplitBlock(ip, out byte[] L, out byte[] R);
            var subkeys = GenerateSubkeysForDes(key8);
            for (int round = 15; round >= 0; round--)
            {
                byte[] subkey = new byte[6];
                Buffer.BlockCopy(subkeys, round * 6, subkey, 0, 6);
                var fOut = FeistelFunction(R, subkey);
                byte[] newR = new byte[4];
                for (int i = 0; i < 4; i++) newR[i] = (byte)(L[i] ^ fOut[i]);
                L = R;
                R = newR;
            }
            var preout = JoinLeftRight(R, L);
            var fp = FinalPermutation(preout);
            return fp;
        }

        // ========================
        // AES: detailed simulation with tables similar to DES
        // ========================
        public static string SimulateAes256EncryptBlockTableFormat(byte[] block16, byte[] key32)
        {
            if (block16.Length != 16) throw new ArgumentException("Block must be 16 bytes.");
            if (key32.Length != 32) throw new ArgumentException("Key must be 32 bytes.");

            var sb = new StringBuilder();
            sb.AppendLine("=== QUÁ TRÌNH MÃ HÓA AES-256 CHI TIẾT (BẢNG) ===");
            sb.AppendLine($"Plaintext (hex): {BitConverter.ToString(block16).Replace("-", " ")}");
            sb.AppendLine($"Key (hex):       {BitConverter.ToString(key32).Replace("-", " ")}");
            sb.AppendLine();

            // Expand key
            byte[] expandedKey = ExpandKeyAes256(key32);
            int Nr = 14;

            sb.AppendLine("===== BẢNG SINH KHÓA (Key Schedule) =====");
            sb.AppendLine($"Key expanded length: {expandedKey.Length} bytes ({Nr + 1} round keys)");
            sb.AppendLine();

            // Show round keys in table format
            string keyHeader = "Round  | Round Key (128-bit)";
            sb.AppendLine(keyHeader);
            sb.AppendLine(new string('-', keyHeader.Length + 30));

            for (int i = 0; i <= Nr; i++)
            {
                byte[] roundKey = new byte[16];
                Buffer.BlockCopy(expandedKey, i * 16, roundKey, 0, 16);
                sb.AppendLine($"Key[{i,2}] | {BytesToHex(roundKey)}");
            }
            sb.AppendLine();

            // Initial state
            byte[] state = (byte[])block16.Clone();
            var stateHistory = new List<byte[]>();

            sb.AppendLine("===== BẢNG TRẠNG THÁI (State) QUA CÁC VÒNG =====");

            // Initial AddRoundKey
            sb.AppendLine("--- Initial AddRoundKey (Round 0) ---");
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"State trước:  {BytesToHex(state)}");
            byte[] initialKey = expandedKey.Take(16).ToArray();
            sb.AppendLine($"RoundKey[0]:  {BytesToHex(initialKey)}");
            AddRoundKey(state, expandedKey, 0);
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"State sau:    {BytesToHex(state)}");
            sb.AppendLine();

            // Rounds 1 to Nr-1
            for (int round = 1; round <= Nr - 1; round++)
            {
                sb.AppendLine($"--- Round {round} ---");

                // SubBytes
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine("SubBytes:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                SubBytes(state);
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");

                // ShiftRows
                sb.AppendLine("ShiftRows:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                ShiftRows(state);
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");

                // MixColumns
                sb.AppendLine("MixColumns:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                MixColumns(state);
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");

                // AddRoundKey
                sb.AppendLine("AddRoundKey:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                byte[] roundKey = expandedKey.Skip(round * 16).Take(16).ToArray();
                sb.AppendLine($"  RoundKey[{round}]: {BytesToHex(roundKey)}");
                AddRoundKey(state, expandedKey, round);
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");
                sb.AppendLine();
            }

            // Final round (no MixColumns)
            sb.AppendLine($"--- Round {Nr} (Final) ---");

            // SubBytes
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine("SubBytes:");
            sb.AppendLine($"  State trước:  {BytesToHex(state)}");
            SubBytes(state);
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"  State sau:    {BytesToHex(state)}");

            // ShiftRows
            sb.AppendLine("ShiftRows:");
            sb.AppendLine($"  State trước:  {BytesToHex(state)}");
            ShiftRows(state);
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"  State sau:    {BytesToHex(state)}");

            // Final AddRoundKey
            sb.AppendLine("AddRoundKey (Final):");
            sb.AppendLine($"  State trước:  {BytesToHex(state)}");
            byte[] finalRoundKey = expandedKey.Skip(Nr * 16).Take(16).ToArray();
            sb.AppendLine($"  RoundKey[{Nr}]: {BytesToHex(finalRoundKey)}");
            AddRoundKey(state, expandedKey, Nr);
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"  Ciphertext:   {BytesToHex(state)}");
            sb.AppendLine();

            // Summary table of all states
            sb.AppendLine("===== TÓM TẮT TRẠNG THÁI =====");
            string stateHeader = "Bước           | State (128-bit)";
            sb.AppendLine(stateHeader);
            sb.AppendLine(new string('-', stateHeader.Length + 50));

            string[] stepNames = {
        "Start", "AddRoundKey[0]",
        "Round1-SubBytes", "Round1-ShiftRows", "Round1-MixColumns", "Round1-AddRoundKey",
        "Round2-SubBytes", "Round2-ShiftRows", "Round2-MixColumns", "Round2-AddRoundKey",
        // ... continue for all rounds
        "Round14-SubBytes", "Round14-ShiftRows", "Round14-AddRoundKey", "Final"
    };

            for (int i = 0; i < stateHistory.Count && i < stepNames.Length; i++)
            {
                sb.AppendLine($"{PadRight(stepNames[i], 15)} | {BytesToHex(stateHistory[i])}");
            }

            sb.AppendLine();
            sb.AppendLine("=== KẾT THÚC MÃ HÓA AES-256 ===");
            return sb.ToString();
        }

        public static string SimulateAes256DecryptBlockTableFormat(byte[] block16, byte[] key32)
        {
            if (block16.Length != 16) throw new ArgumentException("Block must be 16 bytes.");
            if (key32.Length != 32) throw new ArgumentException("Key must be 32 bytes.");

            var sb = new StringBuilder();
            sb.AppendLine("=== QUÁ TRÌNH GIẢI MÃ AES-256 CHI TIẾT (BẢNG) ===");
            sb.AppendLine($"Ciphertext (hex): {BitConverter.ToString(block16).Replace("-", " ")}");
            sb.AppendLine($"Key (hex):        {BitConverter.ToString(key32).Replace("-", " ")}");
            sb.AppendLine();

            // Expand key
            byte[] expandedKey = ExpandKeyAes256(key32);
            int Nr = 14;

            sb.AppendLine("===== BẢNG SINH KHÓA (Key Schedule) =====");
            string keyHeader = "Round  | Round Key (128-bit)";
            sb.AppendLine(keyHeader);
            sb.AppendLine(new string('-', keyHeader.Length + 30));

            for (int i = 0; i <= Nr; i++)
            {
                byte[] roundKey = new byte[16];
                Buffer.BlockCopy(expandedKey, i * 16, roundKey, 0, 16);
                sb.AppendLine($"Key[{i,2}] | {BytesToHex(roundKey)}");
            }
            sb.AppendLine();

            // Initial state
            byte[] state = (byte[])block16.Clone();
            var stateHistory = new List<byte[]>();

            sb.AppendLine("===== BẢNG TRẠNG THÁI (State) QUA CÁC VÒNG =====");

            // Initial AddRoundKey (with last key)
            sb.AppendLine("--- Initial AddRoundKey (Round 14) ---");
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"State trước:    {BytesToHex(state)}");
            byte[] initialKey = expandedKey.Skip(Nr * 16).Take(16).ToArray();
            sb.AppendLine($"RoundKey[{Nr}]:  {BytesToHex(initialKey)}");
            AddRoundKey(state, expandedKey, Nr);
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"State sau:      {BytesToHex(state)}");
            sb.AppendLine();

            // Rounds 13 to 1 (in reverse)
            for (int round = Nr - 1; round >= 1; round--)
            {
                sb.AppendLine($"--- Round {round + 1} (Reverse) ---");

                // Inverse ShiftRows (you'd need to implement InverseShiftRows)
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine("InvShiftRows:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                InvShiftRows(state); // You need to implement this
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");

                // Inverse SubBytes (you'd need to implement InverseSubBytes)
                sb.AppendLine("InvSubBytes:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                InvSubBytes(state); // You need to implement this
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");

                // AddRoundKey
                sb.AppendLine("AddRoundKey:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                byte[] roundKey = expandedKey.Skip(round * 16).Take(16).ToArray();
                sb.AppendLine($"  RoundKey[{round}]: {BytesToHex(roundKey)}");
                AddRoundKey(state, expandedKey, round);
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");

                // Inverse MixColumns (you'd need to implement InverseMixColumns)
                sb.AppendLine("InvMixColumns:");
                sb.AppendLine($"  State trước:  {BytesToHex(state)}");
                InvMixColumns(state); // You need to implement this
                stateHistory.Add((byte[])state.Clone());
                sb.AppendLine($"  State sau:    {BytesToHex(state)}");
                sb.AppendLine();
            }

            // Final round (no Inverse MixColumns)
            sb.AppendLine($"--- Round 1 (Final Reverse) ---");

            // Inverse ShiftRows
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine("InvShiftRows:");
            sb.AppendLine($"  State trước:  {BytesToHex(state)}");
            InvShiftRows(state);
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"  State sau:    {BytesToHex(state)}");

            // Inverse SubBytes
            sb.AppendLine("InvSubBytes:");
            sb.AppendLine($"  State trước:  {BytesToHex(state)}");
            InvSubBytes(state);
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"  State sau:    {BytesToHex(state)}");

            // Final AddRoundKey
            sb.AppendLine("AddRoundKey (Final):");
            sb.AppendLine($"  State trước:  {BytesToHex(state)}");
            byte[] finalRoundKey = expandedKey.Take(16).ToArray();
            sb.AppendLine($"  RoundKey[0]:  {BytesToHex(finalRoundKey)}");
            AddRoundKey(state, expandedKey, 0);
            stateHistory.Add((byte[])state.Clone());
            sb.AppendLine($"  Plaintext:    {BytesToHex(state)}");
            sb.AppendLine();

            sb.AppendLine("=== KẾT THÚC GIẢI MÃ AES-256 ===");
            return sb.ToString();
        }

        // Helper methods needed for decryption (you need to implement these)
        // Tìm và xóa các hàm inverse cũ (nếu có), sau đó thêm các hàm này:

        // AES Inverse S-box
        private static readonly byte[] AesInvSBox = new byte[256] {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

        // Inverse functions for AES decryption (REPLACE the existing ones)
        private static void InvSubBytes(byte[] state)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = AesInvSBox[state[i]];
        }

        private static void InvShiftRows(byte[] state)
        {
            byte[] temp = new byte[16];
            temp[0] = state[0]; temp[4] = state[4]; temp[8] = state[8]; temp[12] = state[12];
            temp[1] = state[13]; temp[5] = state[1]; temp[9] = state[5]; temp[13] = state[9];
            temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2]; temp[14] = state[6];
            temp[3] = state[7]; temp[7] = state[11]; temp[11] = state[15]; temp[15] = state[3];
            Buffer.BlockCopy(temp, 0, state, 0, 16);
        }

        private static void InvMixColumns(byte[] state)
        {
            for (int c = 0; c < 4; c++)
            {
                int col = c * 4;
                byte a0 = state[col + 0];
                byte a1 = state[col + 1];
                byte a2 = state[col + 2];
                byte a3 = state[col + 3];

                state[col + 0] = (byte)(GFMul(0x0E, a0) ^ GFMul(0x0B, a1) ^ GFMul(0x0D, a2) ^ GFMul(0x09, a3));
                state[col + 1] = (byte)(GFMul(0x09, a0) ^ GFMul(0x0E, a1) ^ GFMul(0x0B, a2) ^ GFMul(0x0D, a3));
                state[col + 2] = (byte)(GFMul(0x0D, a0) ^ GFMul(0x09, a1) ^ GFMul(0x0E, a2) ^ GFMul(0x0B, a3));
                state[col + 3] = (byte)(GFMul(0x0B, a0) ^ GFMul(0x0D, a1) ^ GFMul(0x09, a2) ^ GFMul(0x0E, a3));
            }
        }

        // Simple AES encryption/decryption methods for actual operation
        public static byte[] EncryptAesBlock(byte[] block, byte[] key)
        {
            if (block.Length != 16) throw new ArgumentException("Block must be 16 bytes.");
            if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes.");

            byte[] expandedKey = ExpandKeyAes256(key);
            byte[] state = (byte[])block.Clone();
            int Nr = 14;

            // Initial AddRoundKey
            AddRoundKey(state, expandedKey, 0);

            // Rounds 1 to Nr-1
            for (int round = 1; round <= Nr - 1; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, expandedKey, round);
            }

            // Final round (no MixColumns)
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, expandedKey, Nr);

            return state;
        }

        public static byte[] DecryptAesBlock(byte[] block, byte[] key)
        {
            if (block.Length != 16) throw new ArgumentException("Block must be 16 bytes.");
            if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes.");

            byte[] expandedKey = ExpandKeyAes256(key);
            byte[] state = (byte[])block.Clone();
            int Nr = 14;

            // Initial AddRoundKey (with last key)
            AddRoundKey(state, expandedKey, Nr);

            // Rounds Nr-1 to 1 (in reverse)
            for (int round = Nr - 1; round >= 1; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, expandedKey, round);
                InvMixColumns(state);
            }

            // Final round (no InvMixColumns)
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, expandedKey, 0);

            return state;
        }

        // Thêm vào class CryptoSimulators
        public static byte[] PublicAesDecryptBlockBytes(byte[] block16, byte[] key32)
        {
            if (block16.Length != 16) throw new ArgumentException("Block must be 16 bytes.");
            if (key32.Length != 32) throw new ArgumentException("Key must be 32 bytes.");

            return DecryptAesBlock(block16, key32);
        }

        public static byte[] PublicAesEncryptBlockBytes(byte[] block16, byte[] key32)
        {
            if (block16.Length != 16) throw new ArgumentException("Block must be 16 bytes.");
            if (key32.Length != 32) throw new ArgumentException("Key must be 32 bytes.");

            return EncryptAesBlock(block16, key32);
        }

        // Phương thức mã hóa/giải mã AES an toàn cho nhiều block
        public static byte[] AesEncrypt(byte[] data, byte[] key)
        {
            if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes.");

            // Padding
            int padLength = 16 - (data.Length % 16);
            if (padLength == 0) padLength = 16;

            byte[] padded = new byte[data.Length + padLength];
            Buffer.BlockCopy(data, 0, padded, 0, data.Length);
            for (int i = data.Length; i < padded.Length; i++)
            {
                padded[i] = (byte)padLength;
            }

            // Mã hóa từng block
            byte[] result = new byte[padded.Length];
            int blockCount = padded.Length / 16;

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[16];
                Buffer.BlockCopy(padded, i * 16, block, 0, 16);
                byte[] encryptedBlock = EncryptAesBlock(block, key);
                Buffer.BlockCopy(encryptedBlock, 0, result, i * 16, 16);
            }

            return result;
        }

        public static byte[] AesDecrypt(byte[] ciphertext, byte[] key)
        {
            if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes.");
            if (ciphertext.Length % 16 != 0) throw new ArgumentException("Ciphertext length must be multiple of 16 bytes.");

            // Giải mã từng block
            byte[] decrypted = new byte[ciphertext.Length];
            int blockCount = ciphertext.Length / 16;

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[16];
                Buffer.BlockCopy(ciphertext, i * 16, block, 0, 16);
                byte[] decryptedBlock = DecryptAesBlock(block, key);
                Buffer.BlockCopy(decryptedBlock, 0, decrypted, i * 16, 16);
            }

            // Remove padding
            return RemovePaddingSafe(decrypted);
        }

        private static byte[] RemovePaddingSafe(byte[] data)
        {
            if (data == null || data.Length == 0)
                return data;

            try
            {
                int padLength = data[data.Length - 1];

                // Validate padding
                if (padLength > 0 && padLength <= 16 && padLength <= data.Length)
                {
                    bool validPadding = true;
                    for (int i = data.Length - padLength; i < data.Length; i++)
                    {
                        if (i < 0 || i >= data.Length || data[i] != padLength)
                        {
                            validPadding = false;
                            break;
                        }
                    }

                    if (validPadding)
                    {
                        byte[] result = new byte[data.Length - padLength];
                        Buffer.BlockCopy(data, 0, result, 0, result.Length);
                        return result;
                    }
                }

                return data;
            }
            catch
            {
                return data;
            }
        }
    }
}
