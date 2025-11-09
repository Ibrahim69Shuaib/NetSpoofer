using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;

namespace NetSpoofer {
    public class CaptureManager {
        private readonly ICaptureDevice _dev;
        private Thread? _thread;
        private volatile bool _running;
        public event Action<Packet>? OnPacket;
        public bool EnableForwarding { get; set; }
        private BandwidthLimiter? _limiter;
        private HostPolicyManager? _hostPolicies;
        private IPAddress? _gatewayIp;
        private PhysicalAddress? _gatewayMac;
        private readonly ConcurrentDictionary<IPAddress, PhysicalAddress?> _targets = new();
        private readonly ConcurrentQueue<RawCapture> _q = new();
        private DnsSpoofer? _dns;

        public CaptureManager(ICaptureDevice dev) { _dev = dev; }
        public void AttachBandwidthLimiter(BandwidthLimiter limiter) => _limiter = limiter;
        public void AttachHostPolicies(HostPolicyManager policies) => _hostPolicies = policies;
        public void AttachDnsSpoof(DnsSpoofer dns) => _dns = dns;
        public void SetGatewayIp(IPAddress gatewayIp) { _gatewayIp = gatewayIp; }
        public void AddTarget(IPAddress ip) { _targets.TryAdd(ip, null); }
        public void RemoveTarget(IPAddress ip) { _targets.TryRemove(ip, out _); }

        public void Start() {
            _dev.Open(DeviceModes.Promiscuous, 1);
            _dev.OnPacketArrival += (s, e) => _q.Enqueue(e.GetPacket());
            _dev.StartCapture();
            _running = true;
            _thread = new Thread(Loop) { IsBackground = true };
            _thread.Start();
        }
        public void Stop() { _running = false; try { _dev.StopCapture(); } catch { } try { _dev.Close(); } catch { } }

        private void Loop() {
            while (_running) {
                if (!_q.TryDequeue(out var rc)) { Thread.Sleep(1); continue; }
                var packet = Packet.ParsePacket(rc.LinkLayerType, rc.Data);
                OnPacket?.Invoke(packet);
                _dns?.Process(packet, _dev);
                if (EnableForwarding) Forward(packet);
            }
        }

        private void Forward(Packet pkt) {
            var eth = pkt.Extract<EthernetPacket>();
            var ip = pkt.Extract<IPv4Packet>();
            if (eth == null || ip == null) return;
            if (_gatewayIp == null) return;
            _gatewayMac ??= ArpSpoofer.ResolveMacAddress(_gatewayIp);
            if (_gatewayMac == null) return;

            // target -> gateway
            if (_targets.ContainsKey(ip.SourceAddress)) {
                if (_hostPolicies?.IsBlocked(ip.SourceAddress) == true) return;
                eth.DestinationHardwareAddress = _gatewayMac;
                eth.SourceHardwareAddress = _dev.MacAddress;
                var bytes = eth.Bytes;
                var limiter = _hostPolicies?.GetLimiter(ip.SourceAddress) ?? _limiter;
                limiter?.ThrottleUpload(bytes.Length);
                SendBytes(bytes);
            }
            // gateway -> target
            else if (ip.SourceAddress.Equals(_gatewayIp) && _targets.ContainsKey(ip.DestinationAddress)) {
                var tmac = _targets[ip.DestinationAddress] ??= ArpSpoofer.ResolveMacAddress(ip.DestinationAddress);
                if (_hostPolicies?.IsBlocked(ip.DestinationAddress) == true) return;
                eth.DestinationHardwareAddress = tmac ?? eth.DestinationHardwareAddress;
                eth.SourceHardwareAddress = _dev.MacAddress;
                var bytes = eth.Bytes;
                var limiter = _hostPolicies?.GetLimiter(ip.DestinationAddress) ?? _limiter;
                limiter?.ThrottleDownload(bytes.Length);
                SendBytes(bytes);
            }
        }

        public void SendBytes(byte[] bytes) {
            var inj = _dev as IInjectionDevice;
            if (inj != null) {
                inj.SendPacket(bytes);
            }
        }
    }
}