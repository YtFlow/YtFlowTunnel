using System;
using System.Threading;
using System.Threading.Tasks;
using YtCrypto;

namespace YtFlow.Tunnel.Adapter.Remote
{
    internal class ShadowsocksAeadAdapter : ShadowsocksAdapter
    {
        private const int TAG_SIZE = 16;
        private const int SIZE_MASK = 0x3fff;
        private byte[] lenData = new byte[2];
        protected override int sendBufferLen => SIZE_MASK;

        public ShadowsocksAeadAdapter (string server, int port, ICryptor cryptor) : base(server, port, cryptor)
        {

        }

        public unsafe int RealEncrypt (ReadOnlySpan<byte> data, Span<byte> tag, Span<byte> outData)
        {
            fixed (byte* dataPtr = &data.GetPinnableReference(), tagPtr = &tag.GetPinnableReference(), outDataPtr = &outData.GetPinnableReference())
            {
                // Reserve for iv
#if X64
                var outLen = cryptor.EncryptAuth((long)dataPtr, data.Length, (long)tagPtr, (ulong)tag.Length, (long)outDataPtr, outData.Length);
#else
                var outLen = cryptor.EncryptAuth((int)dataPtr, data.Length, (int)tagPtr, (uint)tag.Length, (int)outDataPtr, outData.Length);
#endif
                if (outLen < 0)
                {
                    throw new AeadOperationException(outLen);
                }
                return outLen;
            }
        }

        /// <summary>
        /// Encrypt Shadowsocks request.
        /// </summary>
        /// <param name="data">Input data.</param>
        /// <param name="outData">Output data. Must have enough capacity to hold encrypted data, tags and additional data.</param>
        /// <returns>The length of <paramref name="outData"/> used.</returns>
        public override uint Encrypt (ReadOnlySpan<byte> data, Span<byte> outData)
        {
            if (data.Length == 0)
            {
                // First chunk, fill IV/salt only
                return (uint)RealEncrypt(Array.Empty<byte>(), Array.Empty<byte>(), outData);
            }
            lenData[0] = (byte)(data.Length >> 8);
            lenData[1] = (byte)(data.Length & 0xFF);
            var encryptedLenSize = RealEncrypt(lenData, outData.Slice(2, TAG_SIZE), outData.Slice(0, 2)) + TAG_SIZE;
            var dataLenSize = RealEncrypt(data, outData.Slice(encryptedLenSize + data.Length, TAG_SIZE), outData.Slice(encryptedLenSize, data.Length)) + TAG_SIZE;
            return (uint)(encryptedLenSize + dataLenSize);
        }

        public unsafe int Decrypt (ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag, Span<byte> outData)
        {
            fixed (byte* dataPtr = &data.GetPinnableReference(), tagPtr = &tag.GetPinnableReference(), outDataPtr = &outData.GetPinnableReference())
            {
#if X64
                var outLen = cryptor.DecryptAuth((long)dataPtr, data.Length, (long)tagPtr, (ulong)tag.Length, (long)outDataPtr, outData.Length);
#else
                var outLen = cryptor.DecryptAuth((int)dataPtr, data.Length, (int)tagPtr, (uint)tag.Length, (int)outDataPtr, outData.Length);
#endif
                if (outLen < 0)
                {
                    throw new AeadOperationException(outLen);
                }
                return outLen;
            }
        }

        private async Task<bool> ReadFullOrZero (byte[] buffer, int offset, int length, CancellationToken cancellationToken)
        {
            do
            {
                var chunkLen = await networkStream.ReadAsync(buffer, offset, length, cancellationToken).ConfigureAwait(false);
                if (chunkLen == 0)
                {
                    return false;
                }
                offset += chunkLen;
                length -= chunkLen;
            } while (length > 0);
            return true;
        }

        public override async Task StartRecv (CancellationToken cancellationToken = default)
        {
            byte[] sizeDataBuffer = new byte[2 + TAG_SIZE];
            byte[] sizeBuffer = new byte[2];
            byte[] dataBuffer = new byte[sendBufferLen + TAG_SIZE];
            // Receive salt
            var ivLen = (int)cryptor.IvLen;
            if (!await ReadFullOrZero(dataBuffer, 0, ivLen, cancellationToken).ConfigureAwait(false))
            {
                return;
            }
            Decrypt(dataBuffer.AsSpan(0, ivLen), Array.Empty<byte>(), Array.Empty<byte>());
            while (client.Connected && networkStream.CanRead)
            {
                // [encrypted payload length][length tag]
                if (!await ReadFullOrZero(sizeDataBuffer, 0, sizeDataBuffer.Length, cancellationToken).ConfigureAwait(false))
                {
                    break;
                }
                Decrypt(sizeDataBuffer.AsSpan(0, 2), sizeDataBuffer.AsSpan(2, TAG_SIZE), sizeBuffer);
                var size = sizeBuffer[0] << 8 | sizeBuffer[1];

                // [encrypted payload][payload tag]
                if (!await ReadFullOrZero(dataBuffer, 0, size + TAG_SIZE, cancellationToken).ConfigureAwait(false))
                {
                    break;
                }
                Decrypt(dataBuffer.AsSpan(0, size), dataBuffer.AsSpan(size, TAG_SIZE), localAdapter.GetSpanForWriteToLocal(size));
                await localAdapter.FlushToLocal(size, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
