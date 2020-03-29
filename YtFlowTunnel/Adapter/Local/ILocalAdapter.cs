using System;
using System.Threading;
using System.Threading.Tasks;

namespace YtFlow.Tunnel.Adapter.Local
{
    internal interface ILocalAdapter
    {
        Destination.Destination Destination { get; set; }
        ValueTask WritePacketToLocal (Span<byte> data, CancellationToken cancellationToken = default);
    }
}
