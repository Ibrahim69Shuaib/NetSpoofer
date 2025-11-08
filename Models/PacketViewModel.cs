using System;

namespace NetSpoofer {
    public class PacketViewModel {
        public DateTime Time { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Destination { get; set; } = string.Empty;
        public string Info { get; set; } = string.Empty;
        public int Length { get; set; }
    }
}