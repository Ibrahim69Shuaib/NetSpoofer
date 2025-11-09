using System;
using System.ComponentModel;
using System.Net;
using System.Runtime.CompilerServices;

namespace NetSpoofer {
    public class HostEntry : INotifyPropertyChanged {
        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? n = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));

        public IPAddress Ip { get => _ip; set { _ip = value; OnPropertyChanged(); } }
        private IPAddress _ip = IPAddress.Any;

        public string Mac { get => _mac; set { _mac = value; OnPropertyChanged(); } }
        private string _mac = string.Empty;

        public string Name { get => _name; set { _name = value; OnPropertyChanged(); } }
        private string _name = string.Empty;

        public double DownloadKbps { get => _down; set { _down = value; OnPropertyChanged(); } }
        private double _down;

        public double UploadKbps { get => _up; set { _up = value; OnPropertyChanged(); } }
        private double _up;

        public bool Blocked { get => _blocked; set { _blocked = value; OnPropertyChanged(); } }
        private bool _blocked;

        public int DownLimitKbps { get => _downLimit; set { _downLimit = value; OnPropertyChanged(); } }
        private int _downLimit = 0;

        public int UpLimitKbps { get => _upLimit; set { _upLimit = value; OnPropertyChanged(); } }
        private int _upLimit = 0;

        public DateTime LastSeenUtc { get => _last; set { _last = value; OnPropertyChanged(); } }
        private DateTime _last = DateTime.MinValue;
    }
}