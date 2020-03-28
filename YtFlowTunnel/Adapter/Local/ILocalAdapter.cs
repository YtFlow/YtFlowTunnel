using System;
using System.Threading;
using System.Threading.Tasks;

namespace YtFlow.Tunnel.Adapter.Local
{
    internal interface ILocalAdapter
    {
        Destination.Destination Destination { get; set; }
        void ConfirmRecvFromLocal (ushort bytesToConfirm);
        Span<byte> GetSpanForWriteToLocal (int len);
        ValueTask FlushToLocal (int len, CancellationToken cancellationToken = default);
        ValueTask WriteToLocal (Span<byte> data, CancellationToken cancellationToken = default);
    }
}
