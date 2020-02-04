using System;
using System.Text;

namespace YtFlow.Tunnel.Adapter.Destination
{
    internal struct DomainNameHost : IHost
    {
        private readonly byte[] data;
        public string DomainName { get; }
        public int Size { get => data.Length; }

        public DomainNameHost(string domain)
        {
            DomainName = domain;
            data = Encoding.ASCII.GetBytes(DomainName);
        }

        public void CopyTo(Span<byte> buffer)
        {
            data.CopyTo(buffer);
        }

        public override string ToString ()
        {
            return DomainName;
        }
    }
}
