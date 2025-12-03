using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using DESApp.Services;
using DESApp.Handlers;
using System.Windows.Input;
using System.Windows.Media;
using System.Linq;
using System.Security.Cryptography;
using System.Collections.Generic;
using DESApp.Data;

namespace DESApp
{
    public partial class MainWindow : Window
    {
        private readonly string[] _vietnameseChars =
        {
            "a", "á", "à", "ả", "ã", "ạ",
            "ă", "ắ", "ằ", "ẳ", "ẵ", "ặ",
            "â", "ấ", "ầ", "ẩ", "ẫ", "ậ",
            "e", "é", "è", "ẻ", "ẽ", "ẹ",
            "ê", "ế", "ề", "ể", "ễ", "ệ",
            "i", "í", "ì", "ỉ", "ĩ", "ị",
            "o", "ó", "ò", "ỏ", "õ", "ọ",
            "ô", "ố", "ồ", "ổ", "ỗ", "ộ",
            "ơ", "ớ", "ờ", "ở", "ỡ", "ợ",
            "u", "ú", "ù", "ủ", "ũ", "ụ",
            "ư", "ứ", "ừ", "ử", "ữ", "ự",
            "y", "ý", "ỳ", "ỷ", "ỹ", "ỵ",
            "d", "đ"
        };

        private readonly string[] _specialChars =
        {
            "!", "@", "#", "$", "%", "^", "&", "*", "(", ")",
            "-", "_", "=", "+", "[", "]", "{", "}", ";", ":",
            "'", "\"", ",", ".", "<", ">", "/", "?", "\\", "|",
            "~", "`", "ˆ", "˙"
        };

        public MainWindow()
        {
            InitializeComponent();
            UpdateKeyHint();

            AES128_Radio.Checked += AlgoRadio_Checked;
            AES192_Radio.Checked += AlgoRadio_Checked;
            AES256_Radio.Checked += AlgoRadio_Checked;
            DES_Radio.Checked += AlgoRadio_Checked;

            BenchmarkDatabase.Init();
        }

        private void UpdateKeyHint()
        {
            var algo = GetSelectedAlgorithm();
            var handler = GetEncryptionHandler(algo ?? "AES-256");
            KeyHint.Text = handler.GetKeyHint();
        }

        private IEncryptionHandler GetEncryptionHandler(string algorithm)
        {
            return algorithm switch
            {
                "DES" => new DesHandler(),
                "AES-128" => new Aes128Handler(),
                "AES-192" => new Aes192Handler(),
                "AES-256" => new Aes256Handler(),
                _ => new Aes256Handler() // Mặc định
            };
        }

        private string GetSelectedAlgorithm()
        {
            if (AES128_Radio.IsChecked == true) return "AES-128";
            if (AES192_Radio.IsChecked == true) return "AES-192";
            if (AES256_Radio.IsChecked == true) return "AES-256";
            if (DES_Radio.IsChecked == true) return "DES";
            return "AES-256";
        }


        private void AlgoBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateKeyHint();
        }

        private void AlgoRadio_Checked(object sender, RoutedEventArgs e)
        {
            UpdateKeyHint();
        }


        private void GenerateKeyBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var algo = GetSelectedAlgorithm();
                int keyLengthBytes;

                if (algo == "AES-128") keyLengthBytes = 16;
                else if (algo == "AES-192") keyLengthBytes = 24;
                else if (algo == "AES-256") keyLengthBytes = 32;
                else keyLengthBytes = 8; // DES

                // Tạo key với ký tự đa dạng (bao gồm tiếng Việt)
                string generatedKey = GenerateRandomKey(keyLengthBytes);
                KeyBox.Text = generatedKey;

                // Hiển thị thông tin key
                byte[] keyBytes = Encoding.UTF8.GetBytes(generatedKey);
                string keyInfo = $"Key generated successfully!\n" +
                               $"Length: {keyBytes.Length} bytes\n" +
                               $"Characters: {generatedKey.Length} chars\n" +
                               $"Contains Vietnamese: {ContainsVietnamese(generatedKey)}\n" +
                               $"Contains Special: {ContainsSpecialChars(generatedKey)}";

                MessageBox.Show(keyInfo, "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Key generation failed: {ex.Message}",
                               "Error",
                               MessageBoxButton.OK,
                               MessageBoxImage.Error);
            }
        }

        private string GenerateRandomKey(int keyLengthBytes)
        {
            const string allowedChars =
                "abcdefghijklmnopqrstuvwxyz" +
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                "0123456789" +
                "!@#$%^&*()-_=+[]{};:,.<>/?";

            var random = new Random();
            var keyChars = new List<char>();

            while (Encoding.UTF8.GetByteCount(new string(keyChars.ToArray())) < keyLengthBytes)
            {
                char c = allowedChars[random.Next(allowedChars.Length)];

                // Nếu thêm ký tự này vượt quá giới hạn byte thì bỏ
                int bytesIfAdded = Encoding.UTF8.GetByteCount((new string(keyChars.ToArray())) + c);
                if (bytesIfAdded <= keyLengthBytes)
                    keyChars.Add(c);
            }

            return new string(keyChars.ToArray());
        }


        private string GenerateAdvancedKey(int keyLengthBytes)
        {
            var random = new Random();
            var stringBuilder = new StringBuilder();

            // Phân phối tỷ lệ các loại ký tự
            while (Encoding.UTF8.GetByteCount(stringBuilder.ToString()) < keyLengthBytes)
            {
                double choice = random.NextDouble();

                if (choice < 0.3) // 30% ký tự tiếng Việt
                {
                    stringBuilder.Append(_vietnameseChars[random.Next(_vietnameseChars.Length)]);
                }
                else if (choice < 0.6) // 30% ký tự đặc biệt
                {
                    stringBuilder.Append(_specialChars[random.Next(_specialChars.Length)]);
                }
                else if (choice < 0.8) // 20% chữ số
                {
                    stringBuilder.Append((char)random.Next('0', '9' + 1));
                }
                else // 20% chữ cái Latin
                {
                    stringBuilder.Append((char)random.Next('a', 'z' + 1));
                }

                // Kiểm tra nếu vượt quá độ dài byte mong muốn
                if (Encoding.UTF8.GetByteCount(stringBuilder.ToString()) > keyLengthBytes)
                {
                    // Xóa ký tự cuối cùng và thử lại
                    stringBuilder.Length--;
                }
            }

            return stringBuilder.ToString();
        }

        private bool ContainsVietnamese(string text)
        {
            foreach (string vietChar in _vietnameseChars)
            {
                if (text.Contains(vietChar))
                    return true;
            }
            return false;
        }

        private bool ContainsSpecialChars(string text)
        {
            foreach (string specialChar in _specialChars)
            {
                if (text.Contains(specialChar))
                    return true;
            }
            return false;
        }

        private void EncryptBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var watch = Stopwatch.StartNew();

                // Get algorithm and encoding
                var algo = GetSelectedAlgorithm();
                var encoding = (EncodingBox.SelectedItem as ComboBoxItem)?.Content.ToString();
                var useUtf8 = encoding?.Contains("UTF-8") == true;
                var encoder = useUtf8 ? Encoding.UTF8 : Encoding.ASCII;

                // Parse key
                byte[] key = ParseKey(KeyBox.Text, algo);
                if (key == null || key.Length == 0)
                {
                    MessageBox.Show("Invalid key.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Get plaintext
                byte[] plaintext = encoder.GetBytes(PlainTextBox.Text);

                // Build log
                var processSb = new StringBuilder();
                processSb.AppendLine($"=== QUÁ TRÌNH MÃ HÓA {algo} ===");
                processSb.AppendLine($"Encoding: {(useUtf8 ? "UTF-8" : "ASCII")}");
                processSb.AppendLine($"Key Length: {key.Length} bytes");

                // Encrypt
                var handler = GetEncryptionHandler(algo);
                byte[] result = handler.Encrypt(plaintext, key, encoder, processSb);

                // Final result
                string base64Result = Convert.ToBase64String(result);
                processSb.AppendLine($"→ Cipher (Base64): {base64Result}");

                watch.Stop();
                ProcessTextBlock.Text = processSb.ToString();
                SpeedTextBlock.Text = $"⏱ Encryption completed in {watch.ElapsedMilliseconds}ms";
                OutputBox.Text = base64Result;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Encryption failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var watch = Stopwatch.StartNew();

                // Get algorithm and encoding
                var algo = GetSelectedAlgorithm();
                var encoding = (EncodingBox.SelectedItem as ComboBoxItem)?.Content.ToString();
                var useUtf8 = encoding?.Contains("UTF-8") == true;
                var encoder = useUtf8 ? Encoding.UTF8 : Encoding.ASCII;

                // Parse key
                byte[] key = ParseKey(KeyBox.Text, algo);
                if (key == null || key.Length == 0)
                {
                    MessageBox.Show("Invalid key.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Get ciphertext
                byte[] ciphertext = Convert.FromBase64String(PlainTextBox.Text.Trim());

                // Log
                var processSb = new StringBuilder();
                processSb.AppendLine($"=== QUÁ TRÌNH GIẢI MÃ {algo} ===");

                // Decrypt
                var handler = GetEncryptionHandler(algo);
                byte[] result = handler.Decrypt(ciphertext, key, encoder, processSb);

                // Show plaintext
                string plaintextResult = encoder.GetString(result);
                processSb.AppendLine($"→ Plaintext: {plaintextResult}");

                watch.Stop();
                ProcessTextBlock.Text = processSb.ToString();
                SpeedTextBlock.Text = $"⏱ Decryption completed in {watch.ElapsedMilliseconds}ms";
                OutputBox.Text = plaintextResult;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Decryption failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


        private byte[] ParseKey(string keyText, string algorithm)
        {
            if (string.IsNullOrWhiteSpace(keyText))
                return null;

            int requiredLength = algorithm switch
            {
                "DES" => 8,
                "AES-128" => 16,
                "AES-192" => 24,
                "AES-256" => 32,
                _ => 32
            };

            var encoder = Encoding.UTF8;
            var keyBytes = new List<byte>();

            foreach (char c in keyText)
            {
                byte[] charBytes = encoder.GetBytes(c.ToString());

                // nếu thêm vào bị vượt quá requiredLength thì dừng
                if (keyBytes.Count + charBytes.Length > requiredLength)
                    break;

                keyBytes.AddRange(charBytes);
            }

            while (keyBytes.Count < requiredLength)
                keyBytes.Add((byte)'x');

            return keyBytes.ToArray();
        }


        // Các method utility và UI events giữ nguyên
        private void CopyResult_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(OutputBox.Text);
            MessageBox.Show("Result copied to clipboard!");
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            PlainTextBox.Clear();
            OutputBox.Text = string.Empty;
            ProcessTextBlock.Text = string.Empty;
            SpeedTextBlock.Text = "⏱ Tốc độ sẽ hiển thị ở đây";
        }

        private void SaveToFile_Click(object sender, RoutedEventArgs e)
        {
            var saveDialog = new SaveFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                Title = "Save encryption/decryption process to file"
            };

            if (saveDialog.ShowDialog() == true)
            {
                string processContent = ProcessTextBlock.Text;
                if (!string.IsNullOrEmpty(SpeedTextBlock.Text) && SpeedTextBlock.Text != "⏱ Tốc độ sẽ hiển thị ở đây")
                {
                    processContent = SpeedTextBlock.Text + "\n\n" + processContent;
                }

                File.WriteAllText(saveDialog.FileName, processContent);
                MessageBox.Show("Encryption/Decryption process saved successfully!");
            }
        }

        private void LoadFromFile_Click(object sender, RoutedEventArgs e)
        {
            var openDialog = new OpenFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                Title = "Load data from file"
            };

            if (openDialog.ShowDialog() == true)
            {
                PlainTextBox.Text = File.ReadAllText(openDialog.FileName);
            }
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            this.DragMove();
        }

        private void MinimizeBtn_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void MaximizeBtn_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = this.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }

        private void CloseBtn_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void CloseBtn_MouseEnter(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
        }

        private void CloseBtn_MouseLeave(object sender, MouseEventArgs e)
        {
            ((Button)sender).Background = new SolidColorBrush(Colors.Transparent);
        }

        private void OnDrawChartClick(object sender, RoutedEventArgs e)
        {
            DrawChart();
        }

        private void DrawChart()
        {
            try
            {
                var plt = aesPlot.Plot;
                plt.Clear();

                var data = BenchmarkDatabase.GetAll()
                           .Where(x => x.Algorithm == "AES-128" && x.Operation == "Encrypt")
                           .OrderBy(x => x.DataSize)
                           .ToList();

                if (data.Count > 0)
                {
                    double[] xs = data.Select(d => (double)d.DataSize).ToArray();
                    double[] ys = data.Select(d => d.TimeMs).ToArray();

                    // Scatter plot
                    var scatter = plt.AddScatter(xs, ys);
                    scatter.Color = ScottPlot.Drawing.Colors.FromHex("#6366F1");
                    scatter.LineWidth = 2;
                    scatter.MarkerSize = 8;
                    scatter.MarkerShape = ScottPlot.MarkerShape.filledCircle;
                    scatter.LegendText = "AES-128 Encrypt";

                    // Titles
                    plt.Title("AES-128 Encryption Performance");
                    plt.XLabel("Data Size (bytes)");
                    plt.YLabel($"Time (ms)\n({data.Count} data points)");

                    // Axis limits
                    plt.SetAxisLimits(
                        xs.Min() * 0.9,
                        xs.Max() * 1.1,
                        0,
                        ys.Max() * 1.1
                    );

                    // Grid (ScottPlot 4)
                    plt.Grid(enable: true, lineStyle: ScottPlot.LineStyle.Dot);

                    // Stats
                    double avg = ys.Average();
                    double max = ys.Max();
                    double min = ys.Min();

                    // Annotation
                    var ann = plt.AddAnnotation(
                        $"Avg: {avg:F2} ms\nMax: {max:F2} ms\nMin: {min:F2} ms",
                        xs.Average(),
                        ys.Max() * 0.9
                    );

                    ann.Font.Size = 12;
                    ann.Font.Color = System.Drawing.Color.Gray;
                    ann.BackgroundColor = System.Drawing.Color.White;
                    ann.BorderColor = System.Drawing.Color.LightGray;
                }
                else
                {
                    // Sample data
                    double[] xs = { 100, 200, 500, 1000, 2000 };
                    double[] ys = { 5, 8, 15, 25, 45 };

                    var scatter = plt.AddScatter(xs, ys);
                    scatter.Color = ScottPlot.Drawing.Colors.FromHex("#6366F1");
                    scatter.LineWidth = 2;
                    scatter.MarkerSize = 6;
                    scatter.MarkerShape = ScottPlot.MarkerShape.filledCircle;
                    scatter.LegendText = "Sample Data";

                    plt.Title("AES-128 Encryption Performance (Sample Data)");
                    plt.XLabel("Data Size (bytes)");
                    plt.YLabel("Time (ms)");

                    plt.Grid(enable: true, lineStyle: ScottPlot.LineStyle.Dot);

                    var ann = plt.AddAnnotation(
                        "No data yet.\nRun encryption to generate data.",
                        500,
                        30
                    );

                    ann.Font.Size = 12;
                    ann.Font.Color = System.Drawing.Color.Red;
                    ann.BackgroundColor = System.Drawing.Color.White;
                    ann.BorderColor = System.Drawing.Color.Red;
                }

                aesPlot.Refresh();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Error drawing chart: {ex.Message}\n\n{ex.StackTrace}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
        }

    }
}