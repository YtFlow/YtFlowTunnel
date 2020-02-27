using System;
using System.Collections.Generic;
using System.Text;

namespace YtFlow.Tunnel.Adapter.Destination
{
    internal struct DomainNameHost : IHost, IEquatable<DomainNameHost>
    {
        private readonly Memory<byte> data;
        public string DomainName { get; }
        public int Size { get => data.Length; }

        public DomainNameHost(string domain)
        {
            DomainName = domain;
            data = Encoding.ASCII.GetBytes(DomainName);
        }

        public DomainNameHost(byte[] domain)
        {
            data = domain;
            DomainName = Encoding.ASCII.GetString(domain);
        }

        public void CopyTo(Span<byte> buffer)
        {
            data.Span.CopyTo(buffer);
        }

        public override string ToString ()
        {
            return DomainName;
        }

        public override bool Equals (object obj)
        {
            return obj is DomainNameHost host && Equals(host);
        }

        public bool Equals (DomainNameHost other)
        {
            return DomainName == other.DomainName;
        }

        public override int GetHashCode ()
        {
            return 1022487930 + EqualityComparer<string>.Default.GetHashCode(DomainName);
        }

        public static bool operator == (DomainNameHost left, DomainNameHost right)
        {
            return left.Equals(right);
        }

        public static bool operator != (DomainNameHost left, DomainNameHost right)
        {
            return !(left == right);
        }
    }
}
