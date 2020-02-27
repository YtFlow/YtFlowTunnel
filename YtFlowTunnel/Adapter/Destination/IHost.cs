using System;

namespace YtFlow.Tunnel.Adapter.Destination
{
    internal interface IHost
    {
        int Size { get; }
        void CopyTo (Span<byte> buffer);
    }
}
