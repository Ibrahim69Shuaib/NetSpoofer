using MahApps.Metro.Controls;
using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.ObjectModel;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace NetSpoofer {
    public class RelayCommand : ICommand {
        private readonly Action _action; private readonly Func<bool>? _can;
        public RelayCommand(Action action, Func<bool>? can = null) { _action = action; _can = can; }
        public bool CanExecute(object? p) => _can?.Invoke() ?? true;
        public void Execute(object? p) => _action();
        public event EventHandler? CanExecuteChanged { add { CommandManager.RequerySuggested += value; } remove { CommandManager.RequerySuggested -= value; } }
    }

    public partial class MainWindow : MetroWindow, INotifyPropertyChanged {
        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? n = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));

        public ObservableCollection<ICaptureDevice> Interfaces { get; } = new();
        private ICaptureDevice? _selectedInterface; public ICaptureDevice? SelectedInterface { get => _selectedInterface; set { _selectedInterface = value; OnPropertyChanged(); } }
        public string GatewayIp { get => _gatewayIp; set { _gatewayIp = value; OnPropertyChanged(); } } private string _gatewayIp = "";
        public string TargetIp { get => _targetIp; set { _targetIp = value; OnPropertyChanged(); } } private string _targetIp = "";
        public bool EnableArp { get => _enableArp; set { _enableArp = value; OnPropertyChanged(); } } private bool _enableArp = true;
        public bool EnableForwarding { get => _enableForwarding; set { _enableForwarding = value; OnPropertyChanged(); } } private bool _enableForwarding = true;
        public bool EnableDns { get => _enableDns; set { _enableDns = value; OnPropertyChanged(); } } private bool _enableDns = true;
        public bool EnableLimit { get => _enableLimit; set { _enableLimit = value; OnPropertyChanged(); } } private bool _enableLimit = false;
        public int DownKbps { get => _downKbps; set { _downKbps = value; OnPropertyChanged(); } } private int _downKbps = 1024;
        public int UpKbps { get => _upKbps; set { _upKbps = value; OnPropertyChanged(); } } private int _upKbps = 512;
        public int ExtraDelayMs { get => _extraDelayMs; set { _extraDelayMs = value; OnPropertyChanged(); } } private int _extraDelayMs = 0;
        public string Status { get => _status; set { _status = value; OnPropertyChanged(); } } private string _status = "Idle";

        public string FilterText { get => _filterText; set { _filterText = value; OnPropertyChanged(); _monitor?.SetUiFilter(_filterText); } } private string _filterText = "";
        public ObservableCollection<PacketViewModel> Packets { get; } = new();
        public ObservableCollection<HostEntry> Hosts { get; } = new();

        public string DnsDomain { get => _dnsDomain; set { _dnsDomain = value; OnPropertyChanged(); } } private string _dnsDomain = "";
        public string DnsIp { get => _dnsIp; set { _dnsIp = value; OnPropertyChanged(); } } private string _dnsIp = "";
        public ObservableCollection<DnsRule> DnsRules { get; } = new();

        public ICommand AddDnsRuleCommand => new RelayCommand(() => {
            if (IPAddress.TryParse(DnsIp, out var ip) && !string.IsNullOrWhiteSpace(DnsDomain)) {
                DnsRules.Add(new DnsRule(DnsDomain.Trim().ToLowerInvariant(), ip));
                DnsDomain = string.Empty; DnsIp = string.Empty;
            }
        });

        public ICommand StartCommand => new RelayCommand(Start, () => SelectedInterface != null);
        public ICommand StopCommand => new RelayCommand(Stop);

        public ICommand ScanSubnetCommand => new RelayCommand(async () => await ScanSubnet(), () => SelectedInterface != null);

        private CaptureManager? _cap;
        private ArpSpoofer? _arp;
        private DnsSpoofer? _dns;
        private PacketMonitor? _monitor;
        private BandwidthLimiter? _limiter;
        private HostPolicyManager? _hostPolicies;
        private HostTracker? _tracker;
        private readonly ConcurrentDictionary<IPAddress, ArpSpoofer> _arpSpoofers = new();

        public MainWindow() {
            InitializeComponent();
            DataContext = this;
            try {
                Interfaces.Clear();
                foreach (var dev in CaptureDeviceList.Instance) Interfaces.Add(dev);
                Status = Interfaces.Count > 0 ? "Interfaces loaded" : "No capture interfaces found. Ensure Npcap is installed.";
            } catch (Exception ex) {
                Status = "Failed to enumerate interfaces: " + ex.Message;
            }
        }

        private void Start() {
            try {
                if (SelectedInterface == null) return;
                Status = "Starting...";
                _cap = new CaptureManager(SelectedInterface);
                _limiter = new BandwidthLimiter(DownKbps * 1024, UpKbps * 1024, ExtraDelayMs);
                _hostPolicies = new HostPolicyManager();
                _monitor = new PacketMonitor(Packets);
                _cap.OnPacket += pkt => {
                    _monitor!.OnPacket(pkt);
                    _tracker?.Record(pkt);
                };
        
                // Auto-detect gateway if not provided
                if (string.IsNullOrWhiteSpace(GatewayIp)) {
                    var gwAuto = TryGetDefaultGatewayForDevice(SelectedInterface);
                    if (gwAuto != null) GatewayIp = gwAuto.ToString();
                }
        
                PhysicalAddressEx nicMac = new(SelectedInterface.MacAddress);
                // Start host tracking (uses gateway context if known)
                _tracker = new HostTracker(Hosts, IPAddress.TryParse(GatewayIp, out var gwTracker) ? gwTracker : null);
        
                if (EnableDns) {
                    _dns = new DnsSpoofer(_cap, nicMac, DnsRules);
                    _cap.AttachDnsSpoof(_dns);
                }
        
                if (EnableForwarding) {
                    _cap.EnableForwarding = true;
                    _cap.AttachBandwidthLimiter(_limiter!);
                    _cap.AttachHostPolicies(_hostPolicies!);
        
                    IPAddress? gw = IPAddress.TryParse(GatewayIp, out var parsedGw) ? parsedGw : null;
                    if (gw != null) _cap.SetGatewayIp(gw);
        
                    // As hosts appear, start ARP/forwarding for each
                    Hosts.CollectionChanged += (s, e) => {
                        if (e.NewItems != null) {
                            foreach (HostEntry h in e.NewItems) {
                                h.PropertyChanged += (_, __) => ApplyHostPolicy(h);
                                ApplyHostPolicy(h);
                                if (gw != null) SetupArpAndForward(h.Ip, nicMac, gw);
                            }
                        }
                    };
                    foreach (var h in Hosts.ToList()) {
                        h.PropertyChanged += (_, __) => ApplyHostPolicy(h);
                        ApplyHostPolicy(h);
                        if (gw != null) SetupArpAndForward(h.Ip, nicMac, gw);
                    }
                }
        
                _cap.Start();
                Status = "Running";
            } catch (Exception ex) { Status = "Error: " + ex.Message; }
        }

        private void Stop() {
            try {
                _dns?.Stop();
                _arp?.Stop();
                foreach (var kv in _arpSpoofers) kv.Value.Stop();
                _cap?.Stop();
                Status = "Stopped";
            } catch (Exception ex) { Status = "Error: " + ex.Message; }
        }

        private void SetupArpAndForward(IPAddress ip, PhysicalAddressEx nicMac, IPAddress gw) {
            try {
                if (!_arpSpoofers.ContainsKey(ip) && EnableArp) {
                    var spoofer = new ArpSpoofer(_cap!, nicMac, gw, ip);
                    spoofer.Start();
                    _arpSpoofers[ip] = spoofer;
                }
                _cap!.AddTarget(ip);
            } catch { }
        }

        private void ApplyHostPolicy(HostEntry h) {
            try {
                var down = h.DownLimitKbps > 0 ? h.DownLimitKbps * 1024L : DownKbps * 1024L;
                var up = h.UpLimitKbps > 0 ? h.UpLimitKbps * 1024L : UpKbps * 1024L;
                _hostPolicies?.SetPolicy(h.Ip, down, up, h.Blocked, ExtraDelayMs);
            } catch { }
        }

        private static IPAddress? TryGetDefaultGatewayForDevice(ICaptureDevice dev) {
            try {
                var mac = dev.MacAddress.GetAddressBytes();
                var ni = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.GetPhysicalAddress().GetAddressBytes().SequenceEqual(mac));
                var gw = ni?.GetIPProperties().GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address;
                return gw;
            } catch { return null; }
        }

        private async Task ScanSubnet() {
            try {
                if (SelectedInterface == null) return;
                Status = "Scanning subnet...";
                var gw = IPAddress.TryParse(GatewayIp, out var gwi) ? gwi : TryGetDefaultGatewayForDevice(SelectedInterface);
    
                await SubnetScanner.ScanAsync(
                    SelectedInterface,
                    Hosts,
                    onFound: entry => {
                        // If capture already running, wire policies/ARP forward for new entries immediately
                        entry.PropertyChanged += (_, __) => ApplyHostPolicy(entry);
                        ApplyHostPolicy(entry);
                        if (_cap != null && EnableForwarding && gw != null) {
                            var nic = new PhysicalAddressEx(SelectedInterface.MacAddress);
                            SetupArpAndForward(entry.Ip, nic, gw);
                        }
                    });
    
                Status = "Scan complete";
            } catch (Exception ex) {
                Status = "Scan error: " + ex.Message;
            }
        }
    }
}