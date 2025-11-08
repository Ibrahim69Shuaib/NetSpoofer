using System;
using System.Net.NetworkInformation;

namespace NetSpoofer {
    public readonly struct PhysicalAddressEx {
        public readonly byte[] Bytes;
        public PhysicalAddressEx(PhysicalAddress addr) => Bytes = addr.GetAddressBytes();
        public PhysicalAddressEx(byte[] bytes) => Bytes = bytes;
        public override string ToString() => BitConverter.ToString(Bytes);
    }
}