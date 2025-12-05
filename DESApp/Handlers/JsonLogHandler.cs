using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using DESApp.Models;

namespace DESApp.Handlers
{
    public static class JsonLogHandler
    {
        private static readonly string FilePath = "aes_speed_log.json";

        public static void WriteLog(PerformanceLog log)
        {
            List<PerformanceLog> logs = new();

            if (File.Exists(FilePath))
            {
                string json = File.ReadAllText(FilePath);
                if (!string.IsNullOrWhiteSpace(json))
                {
                    logs = JsonSerializer.Deserialize<List<PerformanceLog>>(json);
                }
            }

            logs.Add(log);

            var options = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(FilePath, JsonSerializer.Serialize(logs, options));
        }
    }
}
