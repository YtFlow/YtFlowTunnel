using System.Threading.Tasks;
using Windows.Storage.Streams;

namespace YtFlow.Tunnel
{
    internal delegate void ReadDataHandler(object sender, byte[] e);
    internal delegate void SocketErrorHandler(object sender, int err);
    internal delegate void SocketFinishedHandler(object sender);
    internal interface IAdapterSocket
    {
        void Write(IBuffer e);
        event ReadDataHandler ReadData;
        event SocketErrorHandler OnError;
        void Close();
        void Reset();
    }
}
