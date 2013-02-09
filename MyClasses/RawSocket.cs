using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace MyScanner.MyClasses
{
    [StructLayout(LayoutKind.Explicit)]
    public struct IPHeader
    {
        [FieldOffset(0)]
        public byte ip_verlen; //IP version and IP Header length Combined
        [FieldOffset(1)]
        public byte ip_tos; //Type of Service
        [FieldOffset(2)]
        public ushort ip_totallength; //Total Packet Length
        [FieldOffset(4)]
        public ushort ip_id; //Unique ID
        [FieldOffset(6)]
        public ushort ip_offset; //Flags and Offset
        [FieldOffset(8)]
        public byte ip_ttl; //Time To Live
        [FieldOffset(9)]
        public byte ip_protocol; //Protocol (TCP, UDP, ICMP, Etc.)
        [FieldOffset(10)]
        public ushort ip_checksum; //IP Header Checksum
        [FieldOffset(12)]
        public uint ip_srcaddr; //Source IP Address
        [FieldOffset(16)]
        public uint ip_destaddr; //Destination IP Address
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct TCPHeader
    {
        [FieldOffset(0)]
        public ushort th_sport; //16位源端口   
        [FieldOffset(2)]
        public ushort th_dport; //16位目的端口   
        [FieldOffset(4)]
        public uint th_seq; //32位序列号   
        [FieldOffset(8)]
        public uint th_ack; //32位确认号   
        [FieldOffset(12)]
        public byte th_lenres; //4位首部长度+6位保留字中的4位   
        [FieldOffset(13)]
        public byte th_flag; //2位保留字+6位标志位   
        [FieldOffset(14)]
        public ushort th_win; //16位窗口大小   
        [FieldOffset(16)]
        public ushort th_sum; //16位校验和   
        [FieldOffset(18)]
        public ushort th_urp; //16位紧急数据偏移量   
    }

    public class RawSocket
    {
        private bool error_occurred;
        public bool KeepRunning;
        private static int len_receive_buf;
        byte[] receive_buf_bytes;
        private Socket socket = null;

        public RawSocket()
        {
            error_occurred = false;
            len_receive_buf = 4096;
            receive_buf_bytes = new byte[len_receive_buf];
        }

        public void CreateAndBindSocket(string IP)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            socket.Blocking = false;
            socket.Bind(new IPEndPoint(IPAddress.Parse(IP), 0));

            if (SetSocketOption() == false) error_occurred = true;
        }

        public void Shutdown()
        {
            if (socket != null)
            {
                socket.Shutdown(SocketShutdown.Both);
                socket.Close();
            }
        }

        private bool SetSocketOption()
        {
            bool ret_value = true;
            try
            {
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);

                byte[] IN = new byte[4] { 1, 0, 0, 0 };
                byte[] OUT = new byte[4];
                int SIO_RCVALL = unchecked((int)0x98000001);
                int ret_code = socket.IOControl(SIO_RCVALL, IN, OUT);
                ret_code = OUT[0] + OUT[1] + OUT[2] + OUT[3];
                if (ret_code != 0) ret_value = false;
            }
            catch (SocketException)
            {
                ret_value = false;
            }
            return ret_value;
        }

        public bool ErrorOccurred
        {
            get
            {
                return error_occurred;
            }
        }

        unsafe private void Receive(byte[] buf, int len)
        {
            byte temp_protocol = 0;
            byte temp_flag = 0;
            uint temp_version = 0;
            uint temp_ip_srcaddr = 0;
            uint temp_ip_destaddr = 0;
            short temp_srcport = 0;
            short temp_dstport = 0;
            IPAddress temp_ip;

            PacketArrivedEventArgs e = new PacketArrivedEventArgs();

            fixed (byte* fixed_buf = buf)
            {
                IPHeader* head = (IPHeader*)fixed_buf;
                e.HeaderLength = (uint)(head->ip_verlen & 0x0F) << 2;

                temp_protocol = head->ip_protocol;
                switch (temp_protocol)
                {
                    case 1: e.Protocol = "ICMP"; break;
                    case 2: e.Protocol = "IGMP"; break;
                    case 6: e.Protocol = "TCP"; break;
                    case 17: e.Protocol = "UDP"; break;
                    default: e.Protocol = "UNKNOWN"; break;
                }

                temp_version = (uint)(head->ip_verlen & 0xF0) >> 4;
                e.IPVersion = temp_version.ToString();

                temp_ip_srcaddr = head->ip_srcaddr;
                temp_ip_destaddr = head->ip_destaddr;
                temp_ip = new IPAddress(temp_ip_srcaddr);
                e.OriginationAddress = temp_ip.ToString();
                temp_ip = new IPAddress(temp_ip_destaddr);
                e.DestinationAddress = temp_ip.ToString();

                temp_srcport = *(short*)&fixed_buf[e.HeaderLength];
                temp_dstport = *(short*)&fixed_buf[e.HeaderLength + 2];
                temp_flag = *(byte*)&fixed_buf[e.HeaderLength + 13];
                e.Flag = temp_flag.ToString();
                e.OriginationPort = IPAddress.NetworkToHostOrder(temp_srcport).ToString();
                e.DestinationPort = IPAddress.NetworkToHostOrder(temp_dstport).ToString();

                e.PacketLength = (uint)len;
                e.MessageLength = (uint)len - e.HeaderLength;

                e.ReceiveBuffer = buf;
                Array.Copy(buf, 0, e.IPHeaderBuffer, 0, (int)e.HeaderLength);
                Array.Copy(buf, (int)e.HeaderLength, e.MessageBuffer, 0, (int)e.MessageLength);
            }

            OnPacketArrival(e);
        }

        public void Run()
        {
            try
            {
                IAsyncResult ar = socket.BeginReceive(receive_buf_bytes, 0, len_receive_buf, SocketFlags.None, new AsyncCallback(CallReceive), this);
            }
            catch
            {
            }
        }

        private void CallReceive(IAsyncResult ar)
        {
            try
            {
                int received_bytes;
                received_bytes = socket.EndReceive(ar);
                Receive(receive_buf_bytes, received_bytes);
                if (KeepRunning) Run();
            }
            catch
            {
            }
        }

        public class PacketArrivedEventArgs : EventArgs
        {
            public PacketArrivedEventArgs()
            {
                this.protocol = "";
                this.flag = "";
                this.destination_port = "";
                this.origination_port = "";
                this.destination_address = "";
                this.origination_address = "";
                this.ip_version = "";

                this.total_packet_length = 0;
                this.message_length = 0;
                this.header_length = 0;

                this.receive_buf_bytes = new byte[len_receive_buf];
                this.ip_header_bytes = new byte[len_receive_buf];
                this.message_bytes = new byte[len_receive_buf];
            }

            public string Flag
            {
                get { return flag; }
                set { flag = value; }
            }

            public string Protocol
            {
                get { return protocol; }
                set { protocol = value; }
            }
            public string DestinationPort
            {
                get { return destination_port; }
                set { destination_port = value; }
            }
            public string OriginationPort
            {
                get { return origination_port; }
                set { origination_port = value; }
            }
            public string DestinationAddress
            {
                get { return destination_address; }
                set { destination_address = value; }
            }
            public string OriginationAddress
            {
                get { return origination_address; }
                set { origination_address = value; }
            }
            public string IPVersion
            {
                get { return ip_version; }
                set { ip_version = value; }
            }
            public uint PacketLength
            {
                get { return total_packet_length; }
                set { total_packet_length = value; }
            }
            public uint MessageLength
            {
                get { return message_length; }
                set { message_length = value; }
            }
            public uint HeaderLength
            {
                get { return header_length; }
                set { header_length = value; }
            }
            public byte[] ReceiveBuffer
            {
                get { return receive_buf_bytes; }
                set { receive_buf_bytes = value; }
            }
            public byte[] IPHeaderBuffer
            {
                get { return ip_header_bytes; }
                set { ip_header_bytes = value; }
            }
            public byte[] MessageBuffer
            {
                get { return message_bytes; }
                set { message_bytes = value; }
            }
            private string protocol;
            private string flag;
            private string destination_port;
            private string origination_port;
            private string destination_address;
            private string origination_address;
            private string ip_version;
            private uint total_packet_length;
            private uint message_length;
            private uint header_length;
            private byte[] receive_buf_bytes = null;
            private byte[] ip_header_bytes = null;
            private byte[] message_bytes = null;
        }

        public delegate void PacketArrivedEventHandler(
            Object sender, PacketArrivedEventArgs args);

        public event PacketArrivedEventHandler PacketArrival;

        protected virtual void OnPacketArrival(PacketArrivedEventArgs e)
        {
            if (PacketArrival != null)
            {
                PacketArrival(this, e);
            }
        }
    }
}
