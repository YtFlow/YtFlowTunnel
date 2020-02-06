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
        private const int READ_SIZE_SIZE = TAG_SIZE + 2;
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

        private async Task<int> ReadAtLeast (byte[] buffer, int offset, int desiredLength, CancellationToken cancellationToken)
        {
            if (offset + desiredLength > buffer.Length)
            {
                throw new ArgumentOutOfRangeException($"{nameof(offset)} + {nameof(desiredLength)} must not exceed buffer length.", nameof(desiredLength));
            }
            int readLength = 0;
            do
            {
                var chunkLen = await networkStream.ReadAsync(buffer, offset, buffer.Length - offset, cancellationToken).ConfigureAwait(false);
                if (chunkLen == 0)
                {
                    return readLength;
                }
                offset += chunkLen;
                readLength += chunkLen;
            } while (readLength < desiredLength);
            return readLength;
        }

        public override async Task StartRecv (CancellationToken cancellationToken = default)
        {
            int size, currentChunkSize, ivLen = (int)cryptor.IvLen;
            byte[] dataBuffer = new byte[sendBufferLen + ivLen + TAG_SIZE * 2 + 2];
            byte[] sizeBuffer = new byte[2];
            // Receive salt
            int readSize = await ReadAtLeast(dataBuffer, 0, ivLen, cancellationToken).ConfigureAwait(false);
            if (readSize < ivLen)
            {
                return;
            }
            Decrypt(dataBuffer.AsSpan(0, ivLen), Array.Empty<byte>(), Array.Empty<byte>());
            readSize -= ivLen;
            if (readSize > 0)
            {
                Array.Copy(dataBuffer, ivLen, dataBuffer, 0, readSize);
            }
            while (client.Connected && networkStream.CanRead)
            {
                // [encrypted payload length][length tag]
                if (readSize < READ_SIZE_SIZE)
                {
                    readSize += await ReadAtLeast(dataBuffer, readSize, READ_SIZE_SIZE - readSize, cancellationToken).ConfigureAwait(false);
                }
                if (readSize < READ_SIZE_SIZE)
                {
                    break;
                }
                Decrypt(dataBuffer.AsSpan(0, 2), dataBuffer.AsSpan(2, TAG_SIZE), sizeBuffer);
                size = sizeBuffer[0] << 8 | sizeBuffer[1];
                currentChunkSize = READ_SIZE_SIZE + size + TAG_SIZE;

                // [encrypted payload][payload tag]
                if (readSize < currentChunkSize)
                {
                    readSize += await ReadAtLeast(dataBuffer, readSize, currentChunkSize - readSize, cancellationToken).ConfigureAwait(false);
                }
                if (readSize < currentChunkSize)
                {
                    break;
                }
                Decrypt(dataBuffer.AsSpan(READ_SIZE_SIZE, size), dataBuffer.AsSpan(READ_SIZE_SIZE + size, TAG_SIZE), localAdapter.GetSpanForWriteToLocal(size));

                // Copy remaining data to the front
                if (readSize > currentChunkSize)
                {
                    Array.Copy(dataBuffer, currentChunkSize, dataBuffer, 0, readSize - currentChunkSize);
                }
                readSize -= currentChunkSize;

                // TODO: flush now?
                await localAdapter.FlushToLocal(size, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
