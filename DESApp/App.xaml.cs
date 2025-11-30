using System;
using System.Windows;
using System.Runtime.InteropServices;

namespace DESApp
{
    public partial class App : Application
    {
        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // (Tuỳ chọn) mở console để xem log lỗi nếu WPF gặp sự cố
            AllocConsole();
            Console.WriteLine("DESApp starting...");

            // Khởi tạo và hiển thị MainWindow
            var main = new MainWindow();
            main.Show();
        }
    }
}
