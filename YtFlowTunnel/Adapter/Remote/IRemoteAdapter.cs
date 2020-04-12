using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using YtFlow.Tunnel.Adapter.Local;

namespace YtFlow.Tunnel.Adapter.Remote
{
    internal interface IRemoteAdapter
    {
        bool RemoteDisconnected { get; set; }
        ValueTask Init (ChannelReader<byte[]> channel, ILocalAdapter localAdapter);
        Task StartSend (ChannelReader<byte[]> channel, CancellationToken cancellationToken = default);
        ValueTask<int> GetRecvBufSizeHint (int preferredSize, CancellationToken cancellationToken = default);
        ValueTask<int> StartRecv (ArraySegment<byte> outBuf, CancellationToken cancellationToken = default);
        Task StartRecvPacket (ILocalAdapter localAdapter, CancellationToken cancellationToken = default);
        void SendPacketToRemote (Memory<byte> data, Destination.Destination destination);
        void CheckShutdown ();
    }
}
