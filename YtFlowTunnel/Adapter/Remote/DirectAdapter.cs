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

        public bool RemoteDisconnected { get; set; }

        public async ValueTask Init (ChannelReader<byte[]> channel, ILocalAdapter localAdapter)
        {
            var dev = NetworkInformation.GetInternetConnectionProfile().NetworkAdapter;
            var port = localAdapter.Destination.Port;
            switch (localAdapter.Destination.TransportProtocol)
            {
                case Destination.TransportProtocol.Tcp:
                    streamSocket = new StreamSocket();
                    await streamSocket.ConnectAsync((HostName)localAdapter.Destination, port.ToString(), SocketProtectionLevel.PlainSocket, dev);
                    break;
                case Destination.TransportProtocol.Udp:
                    datagramSocket = new DatagramSocket();
                    await datagramSocket.BindServiceNameAsync(string.Empty, dev);
                    await datagramSocket.ConnectAsync((HostName)localAdapter.Destination, port.ToString());
                    break;
            }
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
                var buffer = e.GetDataReader().DetachBuffer();
                var ptr = ((IBufferByteAccess)buffer).GetBuffer();
                localAdapter.WritePacketToLocal(new Span<byte>(ptr.ToPointer(), (int)buffer.Length), cancellationToken);
            }
            datagramSocket.MessageReceived += packetHandler;
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
