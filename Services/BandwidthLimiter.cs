using System;
using System.Threading;

namespace NetSpoofer {
    public class BandwidthLimiter {
        private readonly long _downRateBytesPerSec;
        private readonly long _upRateBytesPerSec;
        private readonly int _extraDelayMs;
        private double _downTokens;
        private double _upTokens;
        private long _lastTicks;
        public BandwidthLimiter(long downBytesPerSec, long upBytesPerSec, int extraDelayMs) {
            _downRateBytesPerSec = downBytesPerSec; _upRateBytesPerSec = upBytesPerSec; _extraDelayMs = extraDelayMs; _lastTicks = Environment.TickCount64;
        }
        private void Refill() {
            var now = Environment.TickCount64; var dt = (now - _lastTicks) / 1000.0; _lastTicks = now;
            _downTokens = Math.Min(_downRateBytesPerSec, _downTokens + dt * _downRateBytesPerSec);
            _upTokens = Math.Min(_upRateBytesPerSec, _upTokens + dt * _upRateBytesPerSec);
        }
        public void ThrottleDownload(int bytes) { Throttle(ref _downTokens, _downRateBytesPerSec, bytes); }
        public void ThrottleUpload(int bytes) { Throttle(ref _upTokens, _upRateBytesPerSec, bytes); }
        private void Throttle(ref double tokens, long rate, int bytes) {
            Refill();
            while (tokens < bytes) { Thread.Sleep(1); Refill(); }
            tokens -= bytes;
            if (_extraDelayMs > 0) Thread.Sleep(_extraDelayMs);
        }
    }
}