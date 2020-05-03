using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Connectivity;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;
using YtFlow.Tunnel.Adapter.Local;

namespace YtFlow.Tunnel.Adapter.Remote
{
    class DirectAdapter : IRemoteAdapter
    {
        private StreamSocket streamSocket;
        private DatagramSocket datagramSocket;
        protected Action<DatagramSocket, DatagramSocketMessageReceivedEventArgs> udpReceivedHandler = (_s, _e) => { };

        public bool RemoteDisconnected { get; set; }

        public async ValueTask Init (ChannelReader<byte[]> channel, ILocalAdapter localAdapter, CancellationToken cancellationToken = default)
        {
            var dev = NetworkInformation.GetInternetConnectionProfile().NetworkAdapter;
            var port = localAdapter.Destination.Port;
            switch (localAdapter.Destination.TransportProtocol)
            {
                case Destination.TransportProtocol.Tcp:
                    streamSocket = new StreamSocket();
                    await streamSocket.ConnectAsync((HostName)localAdapter.Destination, port.ToString(), SocketProtectionLevel.PlainSocket, dev).AsTask(cancellationToken).ConfigureAwait(false);
                    break;
                case Destination.TransportProtocol.Udp:
                    datagramSocket = new DatagramSocket();
                    datagramSocket.MessageReceived += DatagramSocket_MessageReceived;
                    await datagramSocket.BindServiceNameAsync(string.Empty, dev).AsTask(cancellationToken).ConfigureAwait(false);
                    await datagramSocket.ConnectAsync((HostName)localAdapter.Destination, port.ToString()).AsTask(cancellationToken).ConfigureAwait(false);
                    break;
            }
        }

        private void DatagramSocket_MessageReceived (DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            udpReceivedHandler(sender, args);
        }

        public ValueTask<int> GetRecvBufSizeHint (int preferredSize, CancellationToken cancellationToken = default) => new ValueTask<int>(preferredSize);

        public async ValueTask<int> StartRecv (ArraySegment<byte> outBuf, CancellationToken cancellationToken = default)
        {
            var bytesRead = await streamSocket.InputStream.ReadAsync(
                outBuf.Array.AsBuffer(outBuf.Offset, outBuf.Count),
                (uint)outBuf.Count,
                InputStreamOptions.Partial)
            .AsTask(cancellationToken).ConfigureAwait(false);
            return (int)bytesRead.Length;
        }

        public async Task StartSend (ChannelReader<byte[]> channel, CancellationToken cancellationToken = default)
        {
            using (var outputStream = streamSocket.OutputStream)
            {
                while (await channel.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var packetsToSend = new List<byte[]>();
                    while (channel.TryRead(out var segment))
                    {
                        packetsToSend.Add(segment);
                    }
                    var pendingTasks = new Task[packetsToSend.Count];
                    for (var index = 0; index < packetsToSend.Count; ++index)
                    {
                        var segment = packetsToSend[index];
                        pendingTasks[index] = outputStream.WriteAsync(segment.AsBuffer()).AsTask(cancellationToken);
                    }
                    await Task.WhenAll(pendingTasks).ConfigureAwait(false);
                }
                await outputStream.FlushAsync().AsTask(cancellationToken).ConfigureAwait(false);
            }
        }

        public unsafe Task StartRecvPacket (ILocalAdapter localAdapter, CancellationToken cancellationToken = default)
        {
            var tcs = new TaskCompletionSource<object>();
            void packetHandler (DatagramSocket socket, DatagramSocketMessageReceivedEventArgs e)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }
                try
                {
                    var buffer = e.GetDataReader().DetachBuffer();
                    var ptr = ((IBufferByteAccess)buffer).GetBuffer();
                    localAdapter.WritePacketToLocal(new Span<byte>(ptr.ToPointer(), (int)buffer.Length), cancellationToken);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            }
            udpReceivedHandler = packetHandler;
            cancellationToken.Register(() =>
            {
                tcs.TrySetCanceled();
                var socket = datagramSocket;
                if (socket != null)
                {
                    socket.MessageReceived -= packetHandler;
                }
            });
            return tcs.Task;
        }

        public void SendPacketToRemote (Memory<byte> data, Destination.Destination destination)
        {
            if (!MemoryMarshal.TryGetArray<byte>(data, out var segment))
            {
                throw new NotSupportedException("Cannot get segment from memory");
            }
            _ = datagramSocket.OutputStream.WriteAsync(segment.Array.AsBuffer(segment.Offset, segment.Count));
        }

        public void CheckShutdown ()
        {
            if (datagramSocket != null)
            {
                datagramSocket.MessageReceived -= DatagramSocket_MessageReceived;
            }
            try
            {
                datagramSocket?.Dispose();
            }
            catch (ObjectDisposedException) { }
            try
            {
                streamSocket?.Dispose();
            }
            catch (ObjectDisposedException) { }
        }
    }
}
