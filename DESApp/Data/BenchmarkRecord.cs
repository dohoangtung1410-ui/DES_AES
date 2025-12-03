using System;

namespace DESApp.Data;

public class BenchmarkRecord
{
    public string Algorithm { get; set; }
    public string Operation { get; set; }
    public int KeySize { get; set; }
    public int DataSize { get; set; }
    public double TimeMs { get; set; }
    public DateTime Timestamp { get; set; }
}