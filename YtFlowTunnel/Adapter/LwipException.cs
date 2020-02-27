using System;

namespace YtFlow.Tunnel
{
    internal class LwipException : Exception
    {
        public int LwipCode { get; set; }
        public LwipException () { }
        public LwipException (int code) : this("Error originated from lwIP, code = " + code.ToString())
        {
            LwipCode = code;
        }
        public LwipException (string message) : base(message) { }
        public LwipException (string message, Exception inner) : base(message, inner) { }
    }
}
