using System;

namespace YtFlow.Tunnel.Adapter.Remote
{
    internal class AeadOperationException : Exception
    {
        public AeadOperationException () { }
        public AeadOperationException(int code) : base("Error during AEAD operation, code = " + code.ToString()) { }
        public AeadOperationException (string message) : base(message) { }
        public AeadOperationException (string message, Exception inner) : base(message, inner) { }
    }
}
