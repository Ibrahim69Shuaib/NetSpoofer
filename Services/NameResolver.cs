using System;
using System.Net;
using System.Threading.Tasks;

namespace NetSpoofer {
    public static class NameResolver {
        public static async Task<string?> ResolveAsync(IPAddress ip, int timeoutMs = 2000) {
            try {
                var dnsTask = Dns.GetHostEntryAsync(ip);
                var completed = await Task.WhenAny(dnsTask, Task.Delay(timeoutMs));
                if (completed == dnsTask) {
                    var entry = await dnsTask;
                    var host = entry?.HostName;
                    if (!string.IsNullOrWhiteSpace(host)) {
                        // Prefer short name without domain
                        return host.Split('.')[0];
                    }
                }
            } catch { }
            return null;
        }
    }
}