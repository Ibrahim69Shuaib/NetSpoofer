using System.Collections.Concurrent;
using System.Net;

namespace NetSpoofer {
    public class HostPolicyManager {
        private readonly ConcurrentDictionary<IPAddress, HostPolicy> _policies = new();

        public void SetPolicy(IPAddress ip, long downBytesPerSec, long upBytesPerSec, bool blocked, int extraDelayMs = 0) {
            _policies[ip] = new HostPolicy(downBytesPerSec, upBytesPerSec, blocked, extraDelayMs);
        }

        public bool IsBlocked(IPAddress ip) {
            return _policies.TryGetValue(ip, out var p) && p.Blocked;
        }

        public BandwidthLimiter? GetLimiter(IPAddress ip) {
            return _policies.TryGetValue(ip, out var p) ? p.Limiter : null;
        }

        private class HostPolicy {
            public bool Blocked { get; }
            public BandwidthLimiter Limiter { get; }
            public HostPolicy(long downBytesPerSec, long upBytesPerSec, bool blocked, int extraDelayMs) {
                Blocked = blocked;
                Limiter = new BandwidthLimiter(downBytesPerSec, upBytesPerSec, extraDelayMs);
            }
        }
    }
}