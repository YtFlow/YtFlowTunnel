using System;
using System.Threading;
using System.Threading.Tasks;
using YtFlow.Tunnel.Adapter.Local;
using YtFlow.Tunnel.Adapter.Remote;

namespace YtFlow.Tunnel.Adapter.Relay
{
    internal class DirectRelay : ILocalAdapter, IRemoteAdapter
    {
        protected ILocalAdapter localAdapter;
        protected IRemoteAdapter remoteAdapter;

        public DirectRelay (IRemoteAdapter remoteAdapter)
        {
            this.remoteAdapter = remoteAdapter;
        }

        #region LocalAdapter
        public virtual Destination.Destination Destination
        {
            get => localAdapter.Destination;
            set => localAdapter.Destination = value;
        }

        public void CheckShutdown ()
        {
            remoteAdapter.CheckShutdown();
        }

        public void ConfirmRecvFromLocal (ushort bytesToConfirm)
        {
            localAdapter.ConfirmRecvFromLocal(bytesToConfirm);
        }

        public ValueTask FlushToLocal (int len, CancellationToken cancellationToken = default)
        {
            return localAdapter.FlushToLocal(len, cancellationToken);
        }

        public ValueTask WriteToLocal (Span<byte> data, CancellationToken cancellationToken = default)
        {
            return localAdapter.WriteToLocal(data, cancellationToken);
        }

        public Span<byte> GetSpanForWriteToLocal (int len)
        {
            return localAdapter.GetSpanForWriteToLocal(len);
        }
        #endregion

        #region RemoteAdapter
        public bool RemoteDisconnected { get => remoteAdapter.RemoteDisconnected; set => remoteAdapter.RemoteDisconnected = value; }

        public void FinishSendToRemote (Exception ex = null)
        {
            remoteAdapter.FinishSendToRemote(ex);
        }

        public virtual ValueTask Init (ILocalAdapter localAdapter)
        {
            this.localAdapter = localAdapter;
            return remoteAdapter.Init(this);
        }

        public virtual void SendToRemote (byte[] buffer)
        {
            remoteAdapter.SendToRemote(buffer);
        }

        public virtual Task StartRecv (CancellationToken cancellationToken = default)
        {
            return remoteAdapter.StartRecv(cancellationToken);
        }

        public Task StartSend (CancellationToken cancellationToken = default)
        {
            return remoteAdapter.StartSend(cancellationToken);
        }

        public Task StartRecvPacket (CancellationToken cancellationToken = default)
        {
            return remoteAdapter.StartRecvPacket(cancellationToken);
        }

        public void SendPacketToRemote (Memory<byte> data, Destination.Destination destination)
        {
            remoteAdapter.SendPacketToRemote(data, destination);
        }
        #endregion
    }
}
