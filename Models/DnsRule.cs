using System.Net;

namespace NetSpoofer {
    public record DnsRule(string Domain, IPAddress RedirectTo) {
        public string Display => Domain + " -> " + RedirectTo;
    }
}