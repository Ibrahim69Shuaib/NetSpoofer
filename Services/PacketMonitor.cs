using PacketDotNet;
using System;
using System.Collections.ObjectModel;

namespace NetSpoofer {
    public class PacketMonitor {
        private readonly ObservableCollection<PacketViewModel> _items;
        private string _uiFilter = string.Empty;
        public PacketMonitor(ObservableCollection<PacketViewModel> items) { _items = items; }
        public void SetUiFilter(string filter) => _uiFilter = filter ?? string.Empty;
        public void OnPacket(Packet pkt) {
            var eth = pkt.Extract<EthernetPacket>(); var ip = pkt.Extract<IPv4Packet>(); var udp = pkt.Extract<UdpPacket>(); var tcp = pkt.Extract<TcpPacket>();
            string proto = eth?.Type.ToString() ?? ""; string src = ip != null ? ip.SourceAddress.ToString() : ""; string dst = ip != null ? ip.DestinationAddress.ToString() : "";
            string info = tcp != null ? $"TCP {tcp.SourcePort}->{tcp.DestinationPort}" : udp != null ? $"UDP {udp.SourcePort}->{udp.DestinationPort}" : eth?.Type.ToString() ?? "";
            int len = pkt.Bytes.Length;
            var row = new PacketViewModel { Time = DateTime.Now, Protocol = proto, Source = src, Destination = dst, Info = info, Length = len };
            if (!PassesFilter(row)) return;
            App.Current.Dispatcher.Invoke(() => _items.Add(row));
            if (_items.Count > 5000) App.Current.Dispatcher.Invoke(() => _items.RemoveAt(0));
        }
        private bool PassesFilter(PacketViewModel p) {
            if (string.IsNullOrWhiteSpace(_uiFilter)) return true;
            var f = _uiFilter.ToLowerInvariant();
            if (p.Source.ToLowerInvariant().Contains(f) || p.Destination.ToLowerInvariant().Contains(f) || p.Protocol.ToLowerInvariant().Contains(f) || p.Info.ToLowerInvariant().Contains(f)) return true;
            return false;
        }
    }
}