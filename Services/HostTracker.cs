using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;

namespace NetSpoofer {
    public class HostTracker : IDisposable {
        private readonly ObservableCollection<HostEntry> _list;
        private readonly ConcurrentDictionary<IPAddress, HostEntry> _map = new();
        private readonly ConcurrentDictionary<IPAddress, long> _upAcc = new();
        private readonly ConcurrentDictionary<IPAddress, long> _downAcc = new();
        private readonly IPAddress? _gatewayIp;
        private readonly Thread _timer;
        private volatile bool _running = true;

        public HostTracker(ObservableCollection<HostEntry> list, IPAddress? gatewayIp = null) {
            _list = list; _gatewayIp = gatewayIp;
            _timer = new Thread(TimerLoop) { IsBackground = true };
            _timer.Start();
        }

        public void Record(Packet pkt) {
            var eth = pkt.Extract<EthernetPacket>();
            var ip = pkt.Extract<IPv4Packet>();
            if (eth == null || ip == null) return;
            // Track both endpoints if they look LAN-like
            Track(ip.SourceAddress, eth.SourceHardwareAddress);
            Track(ip.DestinationAddress, eth.DestinationHardwareAddress);

            var bytes = eth.Bytes.Length;
            if (_gatewayIp != null) {
                // Attribute per direction relative to gateway
                if (ip.SourceAddress.Equals(_gatewayIp)) {
                    _downAcc.AddOrUpdate(ip.DestinationAddress, bytes, (_, v) => v + bytes);
                } else if (ip.DestinationAddress.Equals(_gatewayIp)) {
                    _upAcc.AddOrUpdate(ip.SourceAddress, bytes, (_, v) => v + bytes);
                }
            } else {
                // If no gateway known, split heuristically
                _upAcc.AddOrUpdate(ip.SourceAddress, bytes, (_, v) => v + bytes);
                _downAcc.AddOrUpdate(ip.DestinationAddress, bytes, (_, v) => v + bytes);
            }
        }

        private static bool IsLan(IPAddress ip) {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            return b[0] == 10 || b[0] == 192 && b[1] == 168 || b[0] == 172 && b[1] >= 16 && b[1] <= 31;
        }

        private void Track(IPAddress ip, PhysicalAddress mac) {
            if (!IsLan(ip)) return;
            var entry = _map.GetOrAdd(ip, _ => {
                var e = new HostEntry { Ip = ip, Mac = FormatMac(mac), LastSeenUtc = DateTime.UtcNow };
                e.Vendor = VendorLookup.FromMac(e.Mac);
                App.Current.Dispatcher.Invoke(() => _list.Add(e));
                // Resolve DNS/NetBIOS name in background (short timeout)
                System.Threading.Tasks.Task.Run(async () => {
                    var name = await NameResolver.ResolveAsync(ip, 2000);
                    if (!string.IsNullOrWhiteSpace(name)) {
                        App.Current.Dispatcher.Invoke(() => e.Name = name!);
                    }
                });
                return e;
            });
            entry.Mac = FormatMac(mac);
            entry.Vendor = VendorLookup.FromMac(entry.Mac);
            entry.LastSeenUtc = DateTime.UtcNow;
        }

        private void TimerLoop() {
            while (_running) {
                Thread.Sleep(1000);
                foreach (var kv in _map) {
                    var ip = kv.Key;
                    var up = _upAcc.TryGetValue(ip, out var u) ? u : 0;
                    var down = _downAcc.TryGetValue(ip, out var d) ? d : 0;
                    var entry = kv.Value;
                    App.Current.Dispatcher.Invoke(() => {
                        entry.UploadKbps = Math.Round(u / 1024.0, 1);
                        entry.DownloadKbps = Math.Round(d / 1024.0, 1);
                    });
                }
                _upAcc.Clear(); _downAcc.Clear();
            }
        }

        private static string FormatMac(PhysicalAddress mac) {
            var bytes = mac.GetAddressBytes();
            return string.Join(":", bytes.Select(b => b.ToString("X2")));
        }

        public void Dispose() { _running = false; }
    }
}