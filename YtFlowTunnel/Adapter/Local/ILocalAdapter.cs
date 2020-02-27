using System;
using System.Threading;
using System.Threading.Tasks;

namespace YtFlow.Tunnel.Adapter.Local
{
    internal interface ILocalAdapter
    {
        Destination.Destination Destination { get; set; }
        void Reset ();
        void CheckShutdown ();
        void ConfirmRecvFromLocal (ushort bytesToConfirm);
        Task StartForward ();
        Span<byte> GetSpanForWriteToLocal (int len);
        Task FlushToLocal (int len, CancellationToken cancellationToken = default);
        Task WriteToLocal (Span<byte> data, CancellationToken cancellationToken = default);
        Task FinishInbound ();
    }
}
