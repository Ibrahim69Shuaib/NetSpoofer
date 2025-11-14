using System;
using System.Collections.Generic;
using System.Globalization;

namespace NetSpoofer {
    public static class VendorLookup {
        private static readonly Dictionary<string, string> Oui = new(StringComparer.OrdinalIgnoreCase) {
            // OUI -> Vendor (common)
            ["00:1C:B3"] = "Apple",
            ["FC:FB:FB"] = "Apple",
            ["3C:5A:B4"] = "Apple",
            ["F0:79:59"] = "Samsung",
            ["64:16:66"] = "Samsung",
            ["68:3E:34"] = "Huawei",
            ["00:1B:21"] = "Intel",
            ["A4:5E:60"] = "Intel",
            ["00:14:22"] = "Dell",
            ["C4:34:6B"] = "Dell",
            ["00:1D:D8"] = "HP",
            ["B8:6B:23"] = "HP",
            ["00:1B:54"] = "Cisco",
            ["00:25:9C"] = "Cisco",
            ["C8:2A:14"] = "Lenovo",
            ["00:0C:42"] = "TP-Link",
            ["50:7B:9D"] = "Realtek",
            ["60:A4:4C"] = "AzureWave",
            ["6C:4D:73"] = "Xiaomi",
        };

        public static string FromMac(string? mac) {
            if (string.IsNullOrWhiteSpace(mac)) return "Unknown Vendor";
            try {
                var parts = mac.Replace("-", ":").Split(':');
                if (parts.Length < 3) return "Unknown Vendor";
                var oui = $"{Norm(parts[0])}:{Norm(parts[1])}:{Norm(parts[2])}";
                return Oui.TryGetValue(oui, out var vendor) ? vendor : "Unknown Vendor";
            } catch { return "Unknown Vendor"; }
        }

        private static string Norm(string s) => byte.Parse(s, NumberStyles.HexNumber).ToString("X2");
    }
}