using SharpPcap;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace NetSpoofer {
    public static class SubnetScanner {
        public static async Task ScanAsync(ICaptureDevice dev, ObservableCollection<HostEntry> hosts, Action<HostEntry>? onFound = null) {
            if (!TryGetInterfaceIPv4(dev, out var ip, out var mask)) return;

            var (start, end) = GetRange(ip, mask);
            var concurrency = new SemaphoreSlim(64);
            var tasks = new Task[end - start + 1];

            int idx = 0;
            for (uint u = start; u <= end; u++) {
                var target = UIntToIp(u);
                await concurrency.WaitAsync();
                tasks[idx++] = Task.Run(async () => {
                    try {
                        bool alive = await PingAsync(target, 300);
                        var mac = ArpSpoofer.ResolveMacAddress(target);
                        bool hasMac = mac != null;
                        if (alive || hasMac) {
                            var macStr = hasMac ? FormatMac(mac!) : string.Empty;
                            HostEntry? existing = null;
                            App.Current.Dispatcher.Invoke(() => {
                                existing = hosts.FirstOrDefault(h => h.Ip.Equals(target));
                                if (existing == null) {
                                    existing = new HostEntry { Ip = target, Mac = macStr, LastSeenUtc = DateTime.UtcNow };
                                    existing.Vendor = VendorLookup.FromMac(existing.Mac);
                                    hosts.Add(existing);
                                } else {
                                    existing.Mac = macStr;
                                    existing.Vendor = VendorLookup.FromMac(existing.Mac);
                                    existing.LastSeenUtc = DateTime.UtcNow;
                                }
                            });

                            // Resolve name in background
                            _ = Task.Run(async () => {
                                var name = await NameResolver.ResolveAsync(target, 2000);
                                if (!string.IsNullOrWhiteSpace(name)) {
                                    App.Current.Dispatcher.Invoke(() => existing!.Name = name!);
                                }
                            });

                            onFound?.Invoke(existing!);
                        }
                    } finally { concurrency.Release(); }
                });
            }

            await Task.WhenAll(tasks.Where(t => t != null));
        }

        private static bool TryGetInterfaceIPv4(ICaptureDevice dev, out IPAddress addr, out IPAddress mask) {
            addr = IPAddress.Any; mask = IPAddress.Any;
            try {
                var mac = dev.MacAddress.GetAddressBytes();
                var ni = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.GetPhysicalAddress().GetAddressBytes().SequenceEqual(mac));
                var ua = ni?.GetIPProperties().UnicastAddresses
                    .FirstOrDefault(u => u.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                if (ua == null) return false;
                addr = ua.Address;
                mask = ua.IPv4Mask ?? IPAddress.Parse("255.255.255.0"); // fallback /24
                return true;
            } catch { return false; }
        }

        private static (uint start, uint end) GetRange(IPAddress ip, IPAddress mask) {
            var ipU = IpToUInt(ip);
            var maskU = IpToUInt(mask);
            var network = ipU & maskU;
            var broadcast = network | ~maskU;
            var start = network + 1;      // skip network
            var end = broadcast - 1;      // skip broadcast
            return (start, end);
        }

        private static async Task<bool> PingAsync(IPAddress ip, int timeoutMs) {
            try {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, timeoutMs);
                return reply.Status == IPStatus.Success;
            } catch { return false; }
        }

        private static uint IpToUInt(IPAddress ip) => BitConverter.ToUInt32(ip.GetAddressBytes().Reverse().ToArray(), 0);
        private static IPAddress UIntToIp(uint u) => new IPAddress(BitConverter.GetBytes(u).Reverse().ToArray());
        private static string FormatMac(PhysicalAddress mac) {
            var bytes = mac.GetAddressBytes();
            return string.Join(":", bytes.Select(b => b.ToString("X2")));
        }
    }
}