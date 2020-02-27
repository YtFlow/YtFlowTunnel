using System;

namespace YtFlow.Tunnel.Adapter.Destination
{
    internal struct Ipv6Host : IHost
    {
        public int Size => 16;

        // Not implemented
        public void CopyTo (Span<byte> buffer)
        {
            throw new NotImplementedException();
        }
    }
}
