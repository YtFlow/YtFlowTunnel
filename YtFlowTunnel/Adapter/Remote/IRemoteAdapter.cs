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
        ValueTask<int> GetRecvBufSizeHint (CancellationToken cancellationToken = default);
        ValueTask<int> StartRecv (byte[] outBuf, int offset, CancellationToken cancellationToken = default);
        Task StartSend (ChannelReader<byte[]> channel, CancellationToken cancellationToken = default);
        Task StartRecvPacket (CancellationToken cancellationToken = default);
        void SendPacketToRemote (Memory<byte> data, Destination.Destination destination);
        void CheckShutdown ();
    }
}
