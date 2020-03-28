using System;
using System.Threading;
using System.Threading.Tasks;
using YtFlow.Tunnel.Adapter.Local;

namespace YtFlow.Tunnel.Adapter.Remote
{
    internal interface IRemoteAdapter
    {
        bool RemoteDisconnected { get; set; }
        ValueTask Init (ILocalAdapter localAdapter);
        Task StartRecv (CancellationToken cancellationToken = default);
        Task StartRecvPacket (CancellationToken cancellationToken = default);
        Task StartSend (CancellationToken cancellationToken = default);
        void FinishSendToRemote (Exception ex = null);
        void SendToRemote (byte[] buffer);
        void SendPacketToRemote (Memory<byte> data, Destination.Destination destination);
        void CheckShutdown ();
    }
}
