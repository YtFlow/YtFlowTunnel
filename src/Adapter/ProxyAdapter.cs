using System;
using System.Threading;
using System.Threading.Tasks;
using Wintun2socks;

namespace YtFlow.Tunnel
{

    internal abstract class ProxyAdapter : TunSocketAdapter
    {
        protected bool RemoteDisconnected { get; set; } = false;
        protected abstract Task StartRecv (CancellationToken cancellationToken = default);
        protected abstract Task StartSend (CancellationToken cancellationToken = default);
        protected abstract void SendToRemote (byte[] e);
        protected abstract void FinishSendToRemote (Exception ex = null);

        public ProxyAdapter (TcpSocket socket, TunInterface tun) : base(socket, tun)
        {
            ReadData += ProxyAdapter_ReadData;
            OnError += ProxyAdapter_OnError;
            OnFinished += ProxyAdapter_OnFinished;
        }

        protected Task RemoteReceived (Span<byte> e)
        {
            return WriteToLocal(e);
        }

        protected async Task StartForward (string context)
        {
            var recvCancel = new CancellationTokenSource();
            var sendCancel = new CancellationTokenSource();
            try
            {
                await Task.WhenAll(
                    StartRecv(recvCancel.Token).ContinueWith(t =>
                    {
                        if (t.IsFaulted)
                        {
                            sendCancel.Cancel();
                            var ex = t.Exception.Flatten().GetBaseException();
                            DebugLogger.Log($"Recv error: {context}: {ex}");
                            throw ex;
                        }
                    }, recvCancel.Token),
                    StartSend(sendCancel.Token).ContinueWith(t =>
                    {
                        if (t.IsFaulted)
                        {
                            recvCancel.Cancel();
                            var ex = t.Exception.Flatten().GetBaseException();
                            DebugLogger.Log($"Send error: {context}: {ex}");
                            throw ex;
                        }
                    }, sendCancel.Token)
                ).ConfigureAwait(false);
                DebugLogger.Log("Close!: " + context);
                await Close().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Something wrong happened during recv/send and was handled separatedly.
                DebugLogger.Log("Reset!: " + context);
                Reset();
            }
            finally
            {
                RemoteDisconnected = true;
                recvCancel.Dispose();
                sendCancel.Dispose();
            }
            CheckShutdown();
        }

        protected void ProxyAdapter_OnFinished (object sender)
        {
            if (!RemoteDisconnected)
            {
                FinishSendToRemote();
            }
        }

        private void ProxyAdapter_ReadData (object sender, byte[] e)
        {
            SendToRemote(e);
        }

        private void ProxyAdapter_OnError (object sender, int err)
        {
            if (!RemoteDisconnected)
            {
                FinishSendToRemote(new LwipException(err));
            }
        }

        protected override void CheckShutdown ()
        {
            ReadData -= ProxyAdapter_ReadData;
            OnError -= ProxyAdapter_OnError;
            OnFinished -= ProxyAdapter_OnFinished;
            base.CheckShutdown();
        }
    }
}
