using System;

namespace YtFlow.Tunnel.Adapter.Destination
{
    internal struct Ipv6Host : IHost
    {
        // Not implemented
        public int Size => throw new NotImplementedException();

        public void CopyTo (Span<byte> buffer)
        {
            throw new NotImplementedException();
        }
    }
}
