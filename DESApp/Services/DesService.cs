using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DESApp.Services
{
    public class DesService : ICryptoService
    {
        private const int BlockSizeBytes = 8;
        private const int IvSize = 8;

        // Permutation tables (1-based indices)
        private static readonly int[] IP = {
            58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
        };

        private static readonly int[] FP = {
            40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
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
            14,17,11,24,1,5,3,28,15,6,21,10,
            23,19,12,4,26,8,16,7,27,20,13,2,
            41,52,31,37,47,55,30,40,51,45,33,48,
            44,49,39,56,34,53,46,42,50,36,29,32
        };

        private static readonly int[] Shifts = {
            1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
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

        // ------------------ ENCRYPT / DECRYPT (Single DES) ------------------
        public string Encrypt(string plainText, byte[] key, Encoding encoding)
        {
            // Expect 8-byte key for DES
            if (key == null || key.Length != 8)
                throw new ArgumentException("DES key must be 8 bytes (64 bits).", nameof(key));

            var plainBytes = (plainText == null) ? Array.Empty<byte>() : encoding.GetBytes(plainText);
            // PKCS7 pad
            int pad = BlockSizeBytes - (plainBytes.Length % BlockSizeBytes);
            if (pad == 0) pad = BlockSizeBytes;
            var padded = new byte[plainBytes.Length + pad];
            Buffer.BlockCopy(plainBytes, 0, padded, 0, plainBytes.Length);
            for (int i = plainBytes.Length; i < padded.Length; i++) padded[i] = (byte)pad;

            // Generate IV
            var iv = new byte[IvSize];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }

            // Generate subkeys for the single key
            var subKeys = GenerateSubKeys(key);

            // CBC encrypt block-by-block
            using var ms = new MemoryStream();
            ms.Write(iv, 0, iv.Length); // prefix IV

            byte[] prev = iv;
            for (int i = 0; i < padded.Length; i += BlockSizeBytes)
            {
                var block = new byte[BlockSizeBytes];
                Buffer.BlockCopy(padded, i, block, 0, BlockSizeBytes);
                // XOR with prev (CBC)
                for (int b = 0; b < BlockSizeBytes; b++) block[b] ^= prev[b];

                // Single DES: Encrypt with key
                var enc = EncryptBlock(block, subKeys);

                ms.Write(enc, 0, enc.Length);
                prev = enc;
            }

            return Convert.ToBase64String(ms.ToArray());
        }

        public string Decrypt(string base64Package, byte[] key, Encoding encoding)
        {
            if (key == null || key.Length != 8)
                throw new ArgumentException("DES key must be 8 bytes (64 bits).", nameof(key));
            var package = Convert.FromBase64String(base64Package ?? "");
            if (package.Length < IvSize + BlockSizeBytes) throw new CryptographicException("Package too short.");

            var iv = new byte[IvSize];
            Buffer.BlockCopy(package, 0, iv, 0, IvSize);
            var cipher = new byte[package.Length - IvSize];
            Buffer.BlockCopy(package, IvSize, cipher, 0, cipher.Length);

            var subKeys = GenerateSubKeys(key);

            using var ms = new MemoryStream();
            byte[] prev = iv;
            for (int i = 0; i < cipher.Length; i += BlockSizeBytes)
            {
                var block = new byte[BlockSizeBytes];
                Buffer.BlockCopy(cipher, i, block, 0, BlockSizeBytes);

                // Single DES: Decrypt with key
                var dec = DecryptBlock(block, subKeys);

                // XOR with prev (CBC)
                for (int b = 0; b < BlockSizeBytes; b++) dec[b] ^= prev[b];
                ms.Write(dec, 0, dec.Length);
                prev = block;
            }

            var all = ms.ToArray();
            // Remove PKCS7
            if (all.Length == 0) return "";
            int pad = all[all.Length - 1];
            if (pad <= 0 || pad > BlockSizeBytes) throw new CryptographicException("Invalid padding.");
            var result = new byte[all.Length - pad];
            Buffer.BlockCopy(all, 0, result, 0, result.Length);
            return encoding.GetString(result);
        }

        // ---------- Core block-level operations ----------
        private byte[] EncryptBlock(byte[] block, bool[][] subKeys)
        {
            var bits = BytesToBits(block);
            bits = Permute(bits, IP);
            bool[] L = new bool[32];
            bool[] R = new bool[32];
            Array.Copy(bits, 0, L, 0, 32);
            Array.Copy(bits, 32, R, 0, 32);

            for (int round = 0; round < 16; round++)
            {
                var expandedR = Permute(R, E);
                var xored = Xor(expandedR, subKeys[round]);
                var sOut = SBoxTransform(xored);
                var pOut = Permute(sOut, P);
                var newR = Xor(L, pOut);
                var newL = R;
                L = newL;
                R = newR;
            }

            // swap R and L
            var preoutput = new bool[64];
            Array.Copy(R, 0, preoutput, 0, 32);
            Array.Copy(L, 0, preoutput, 32, 32);

            var finalBits = Permute(preoutput, FP);
            return BitsToBytes(finalBits);
        }

        private byte[] DecryptBlock(byte[] block, bool[][] subKeys)
        {
            var bits = BytesToBits(block);
            bits = Permute(bits, IP);
            bool[] L = new bool[32];
            bool[] R = new bool[32];
            Array.Copy(bits, 0, L, 0, 32);
            Array.Copy(bits, 32, R, 0, 32);

            for (int round = 15; round >= 0; round--)
            {
                var expandedR = Permute(R, E);
                var xored = Xor(expandedR, subKeys[round]);
                var sOut = SBoxTransform(xored);
                var pOut = Permute(sOut, P);
                var newR = Xor(L, pOut);
                var newL = R;
                L = newL;
                R = newR;
            }

            var preoutput = new bool[64];
            Array.Copy(R, 0, preoutput, 0, 32);
            Array.Copy(L, 0, preoutput, 32, 32);

            var finalBits = Permute(preoutput, FP);
            return BitsToBytes(finalBits);
        }

        // ---------- Key schedule ----------
        // Returns array of 16 keys, each as bool[48]
        private bool[][] GenerateSubKeys(byte[] keyBytes)
        {
            var keyBits64 = BytesToBits(keyBytes); // 64 bits
            // apply PC1 -> 56 bits
            var key56 = Permute(keyBits64, PC1); // bool[56]
            // split
            bool[] C = new bool[28];
            bool[] D = new bool[28];
            Array.Copy(key56, 0, C, 0, 28);
            Array.Copy(key56, 28, D, 0, 28);

            bool[][] subKeys = new bool[16][];
            for (int i = 0; i < 16; i++)
            {
                // left shifts
                int shift = Shifts[i];
                C = LeftShift(C, shift);
                D = LeftShift(D, shift);

                // combine C+D -> 56 bits
                var CD = new bool[56];
                Array.Copy(C, 0, CD, 0, 28);
                Array.Copy(D, 0, CD, 28, 28);

                // apply PC2 -> 48 bits
                var Ki = Permute(CD, PC2);
                subKeys[i] = Ki;
            }
            return subKeys;
        }

        // ---------- helper bit ops ----------
        private static bool[] Permute(bool[] input, int[] table)
        {
            bool[] outp = new bool[table.Length];
            for (int i = 0; i < table.Length; i++)
            {
                outp[i] = input[table[i] - 1];
            }
            return outp;
        }

        private static bool[] LeftShift(bool[] bits, int n)
        {
            var outp = new bool[bits.Length];
            for (int i = 0; i < bits.Length; i++)
            {
                outp[i] = bits[(i + n) % bits.Length];
            }
            return outp;
        }

        private static bool[] Xor(bool[] a, bool[] b)
        {
            var o = new bool[a.Length];
            for (int i = 0; i < a.Length; i++) o[i] = a[i] ^ b[i];
            return o;
        }

        private static bool[] SBoxTransform(bool[] inp48)
        {
            var out32 = new bool[32];
            for (int s = 0; s < 8; s++)
            {
                int offset = s * 6;
                int row = (inp48[offset] ? 2 : 0) | (inp48[offset + 5] ? 1 : 0);
                int col = 0;
                for (int j = 1; j <= 4; j++)
                {
                    col = (col << 1) | (inp48[offset + j] ? 1 : 0);
                }
                int val = SBoxes[s, row * 16 + col];
                // write 4 bits
                int outOffset = s * 4;
                for (int bit = 0; bit < 4; bit++)
                {
                    out32[outOffset + (3 - bit)] = ((val >> bit) & 1) == 1;
                }
            }
            return out32;
        }

        private static bool[] BytesToBits(byte[] bytes)
        {
            var bits = new bool[bytes.Length * 8];
            for (int i = 0; i < bytes.Length; i++)
            {
                for (int b = 0; b < 8; b++)
                {
                    bits[i * 8 + (7 - b)] = ((bytes[i] >> b) & 1) == 1;
                }
            }
            return bits;
        }

        private static byte[] BitsToBytes(bool[] bits)
        {
            int bytesLen = bits.Length / 8;
            var bytes = new byte[bytesLen];
            for (int i = 0; i < bytesLen; i++)
            {
                byte val = 0;
                for (int b = 0; b < 8; b++)
                {
                    val = (byte)((val << 1) | (bits[i * 8 + b] ? 1 : 0));
                }
                bytes[i] = val;
            }
            return bytes;
        }

        private static string BitsToString(bool[] bits)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < bits.Length; i++)
            {
                sb.Append(bits[i] ? '1' : '0');
                if ((i + 1) % 8 == 0 && i != bits.Length - 1) sb.Append(' ');
            }
            return sb.ToString();
        }

        private static string ByteArrayToBinary(byte[] bytes)
        {
            var sb = new StringBuilder();
            foreach (var b in bytes)
            {
                sb.Append(Convert.ToString(b, 2).PadLeft(8, '0')).Append(' ');
            }
            return sb.ToString().Trim();
        }
    }
}