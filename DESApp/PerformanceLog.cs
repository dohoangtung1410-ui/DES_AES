namespace DESApp.Models
{
    public class PerformanceLog
    {
        public string Algorithm { get; set; }
        public string Mode { get; set; }
        public int KeySize { get; set; }
        public int InputLength { get; set; }
        public double ExecutionTimeMs { get; set; }
        public string DateCreated { get; set; }
    }
}
