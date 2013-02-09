using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace MyScanner.MyClasses
{
    /// <summary>
    /// TcpSyn方式扫描
    /// 半开放式扫描
    /// </summary>
    class CTcpSyn
    {
        public int startPort;
        public int endPort;
        //public int threadOrder;
        public string aimAddr;
        public int threadCount;
        public MyScanner.Scanner ui;
        public Thread tcpSender;   //用于发送syn包的线程
        public Thread tcpListener; //用于接收过滤tcp包的线程
        private bool success;
        /// <summary>
        /// 初始化
        /// </summary>
        /// <param name="UI"></param>
        /// <param name="threadOrder"></param>
        public CTcpSyn(MyScanner.Scanner UI)
        {
            ui = UI;
            startPort = Convert.ToInt32(ui.TBStartPort.Text);
            endPort = Convert.ToInt32(ui.TBEndPort.Text);
            aimAddr = ui.aimIPAddress.Text.ToString();
            //this.threadOrder = threadOrder;
            this.threadCount = Scanner.threadCount;
            //ui.finishThread[threadOrder] = false;
            success = false;
        }

        public void BeginSynScan()
        {
            try
            {
                tcpSender = new Thread(new ThreadStart(ScanPorts));
                tcpSender.Start();

                Thread.Sleep(200);

                tcpListener = new Thread(new ThreadStart(Receive));
                tcpListener.Start();
            }
            catch(Exception ex)
            {
                UpdateTBResult(ui, ex.Message.ToString());
            }
        }

        /// <summary>
        /// 发送TcySyn包
        /// </summary>
        /// <param name="aimAddr"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        public void ScanPorts()
        {
            try
            {
                //获取目标主机信息 IP地址
                IPAddress ipAddr = IPAddress.Parse(aimAddr);
              
                for (int port = startPort; port <= endPort; port++)
                {
                    //循环扫描各个端口
                    Updateloglist(ui,port);
                    Scanner.finishPort++;
                    IPEndPoint iep = new IPEndPoint(ipAddr, port);
                    try
                    {                      
                        #region 构造TCP包 新版
                        Random rand = new Random();
                        uint ip = BitConverter.ToUInt32(ipAddr.GetAddressBytes(), 0);
                        syn synSock = new syn(ip, Convert.ToUInt16(port), iep, rand, Convert.ToByte(0x02));
                        synSock.synFS();
                        #endregion
                    }
                    catch(Exception ex)
                    {
                        UpdateTBResult(ui, ex.Message.ToString() + "\r\n");
                    }
                    finally
                    {
                    }
                }
            }
            catch
            {
            }
            
        }

        /// <summary>
        /// 获取包
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        public void TcpSyn_PacketArrival(object sender, RawSocket.PacketArrivedEventArgs args)
        {
            if (args.Protocol == "TCP" && args.OriginationAddress == aimAddr)
            {
                //处理数据包
                byte[] revMsg = args.ReceiveBuffer;
                byte flag = revMsg[33];
                ushort port = BitConverter.ToUInt16(revMsg, 20);
                byte[] rport = BitConverter.GetBytes(port);
                Array.Reverse(rport);
                port = BitConverter.ToUInt16(rport, 0);
                if (flag == 0x0012)
                {
                    Updateportlist1(ui,port);
                    success = true;
                    #region 如果接收到SYN|ACK，发送一个RST信号关闭连接
                    IPAddress ipAddr = IPAddress.Parse(aimAddr);
                    IPEndPoint iep = new IPEndPoint(ipAddr, Convert.ToInt32(port));
                    Random rand = new Random();
                    uint ip = BitConverter.ToUInt32(ipAddr.GetAddressBytes(), 0);
                    syn rstSock = new syn(ip, port, iep, rand, Convert.ToByte(0x04));
                    rstSock.synFS();
                    #endregion
                }

                if (Scanner.finishPort == System.Math.Abs(endPort - startPort + 1) || rSocket.ErrorOccurred || rSocket.KeepRunning == false )
                {
                    UpdateTBResult(ui, "Finish!\r\n");
                    rSocket.Shutdown();
                    UpdateBtnStart(ui, true);
                }
            }
        }

        public RawSocket rSocket;
        /// <summary>
        /// 接收过滤Tcp包
        /// </summary>
        public void Receive()
        {
            try
            {
                //获取本机地址
                string hostName = Dns.GetHostName();
                IPAddress hostAddr = (IPAddress)Dns.GetHostByName(hostName).AddressList[0];
                string myAddr = hostAddr.ToString();

                rSocket = new RawSocket();
                rSocket.CreateAndBindSocket(myAddr);
                if (rSocket.ErrorOccurred)
                {
                    UpdateTBResult(ui, "监听端口错误！");
                }
                rSocket.PacketArrival += TcpSyn_PacketArrival;
                rSocket.KeepRunning = true;
                rSocket.Run();
            }
            catch//(Exception ex)
            {
                //UpdateTBResult(ui, ex.Message.ToString());
            }
            finally
            {
                //rSocket.Shutdown();
            }
        }

        /// <summary>
        /// 将psdHeader实例的信息转化为byte数组
        /// </summary>
        /// <param name="psdHeader"></param>
        /// <returns></returns>
        private byte[] GetBytesFromPsdHeader(DataStructures.psd_header psdHeader)
        {
            int count = 0;
            int len = sizeof(int) + sizeof(int) + 2 + sizeof(ushort);
            byte[] ByteBuf = new byte[len];
            byte[] tmp;
            tmp = BitConverter.GetBytes(psdHeader.saddr);
            for (int j = 0; j < sizeof(int); j++)
            {
                ByteBuf[count++] = tmp[j];
            }
            tmp = BitConverter.GetBytes(psdHeader.daddr);
            for (int j = 0; j < sizeof(int); j++)
            {
                ByteBuf[count++] = tmp[j];
            }
            ByteBuf[count++] = psdHeader.mbz;
            ByteBuf[count++] = psdHeader.ptcl;
            for (int j = 0; j < sizeof(ushort); j++)
            {
                ByteBuf[count++] = tmp[j];
            }
            return ByteBuf;
        }

        /// <summary>
        /// 将TcpHeader实例的信息转化为byte数组
        /// </summary>
        /// <param name="tcpHeader"></param>
        /// <returns></returns>
        private byte[] GetBytesFromTcpHeader(DataStructures.TCP_HEADER tcpHeader)
        {
            int count = 0;
            int len = sizeof(ushort) * 2 + sizeof(int) * 2 + 2 + sizeof(ushort) * 3;
            byte[] ByteBuf = new byte[len];
            byte[] tmp;
            tmp = BitConverter.GetBytes(tcpHeader.sourcePort);
            for (int i = 0; i < sizeof(ushort); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(tcpHeader.destPort);
            for (int i = 0; i < sizeof(ushort); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(tcpHeader.tcp_seq);
            for (int i = 0; i < sizeof(int); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(tcpHeader.tcp_ack);
            for (int i = 0; i < sizeof(int); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(tcpHeader.tcp_win);
            ByteBuf[count++] = tcpHeader.tcp_lenres;
            ByteBuf[count++] = tcpHeader.tcp_flags;
            for (int i = 0; i < sizeof(ushort); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(tcpHeader.tcp_checksum);
            for (int i = 0; i < sizeof(ushort); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(tcpHeader.tcp_urp);
            for (int i = 0; i < sizeof(ushort); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            return ByteBuf;
        }

        /// <summary>
        /// 将IPHeader实例的信息转化为byte数组
        /// </summary>
        /// <param name="ipHeader"></param>
        /// <returns></returns>
        private byte[] GetBytesFromIPHeader(DataStructures.IP_HEADER ipHeader)
        {
            int count = 0;
            int len = sizeof(ushort) * 4 + sizeof(int) * 2 + 4;
            byte[] ByteBuf = new byte[len];
            byte[] tmp;
            ByteBuf[count++] = ipHeader.ver_hlen;
            ByteBuf[count++] = ipHeader.TOS;
            tmp = BitConverter.GetBytes(ipHeader.totalLen);
            for (int i = 0; i < sizeof(ushort); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(ipHeader.ident);
            for (int i = 0; i < sizeof(ushort); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(ipHeader.frag_and_flags);
            for (int i = 0; i < sizeof(ushort); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            ByteBuf[count++] = ipHeader.ttl;
            ByteBuf[count++] = ipHeader.proto;
            tmp = BitConverter.GetBytes(ipHeader.checksum);
            for (int i = 0; i < sizeof(ushort); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(ipHeader.sourceIP);
            for (int i = 0; i < sizeof(int); i++)
            {
                ByteBuf[count++] = tmp[i];
            }
            tmp = BitConverter.GetBytes(ipHeader.destIP);
            for (int i = 0; i < sizeof(int); i++)
            {
                ByteBuf[count++] = tmp[i];
            }

            return ByteBuf;
        }

        /// <summary>
        /// 计算校验和
        /// 注意：buffer数组为整个ip包数组，需要转换成UInt16[];size为buffer数组的长度。
        /// </summary>
        public static UInt16 checksum(UInt16[] buffer, int size)
        {
            Int32 cksum = 0;
            int counter;
            counter = 0;
            while (size > 0)
            {
                UInt16 val = buffer[counter];
                cksum += Convert.ToInt32(buffer[counter]);
                counter += 1;
                size = -1;
            }
            cksum = (cksum >> 16) + (cksum & 0xffff);
            cksum += (cksum >> 16);
            return (UInt16)(~cksum);
        }

        /// <summary>
        /// 将byte数组转化为Unit16数组
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public UInt16[] byteToUshort(byte[] buffer)
        {
            int size = buffer.Length;
            ushort[] uBuffer = new ushort[size / 2];
            for (int i = 0; i < size; i += 2)
            {
                uBuffer[i / 2] = BitConverter.ToUInt16(buffer, i);
            }
            return uBuffer;
        }

        
        /// <summary>
        /// 创建跨线程更新界面信息的委托
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public delegate void DeleUpdateloglist(Scanner ui, int port);

        /// <summary>
        /// 跨线程更新界面信息
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public void Updateloglist(Scanner ui, int port)
        {
            if (ui.InvokeRequired)
            {
                Delegate d = new DeleUpdateloglist(Updateloglist);
                ui.Invoke(d, new Object[] { ui, port });
            }
            else
            {
                ui.loglist.Items.Add("已扫描端口"+port.ToString());
            }
        }
        /// <summary>
        /// 创建跨线程更新界面信息的委托
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public delegate void DeleUpdateportlist(Scanner ui, int port);

        /// <summary>
        /// 跨线程更新界面信息
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public void Updateportlist(Scanner ui, int port)
        {
            if (ui.InvokeRequired)
            {
                Delegate d = new DeleUpdateportlist(Updateportlist);
                ui.Invoke(d, new Object[] { ui, port });
            }
            else
            {
                ui.portlist.Items.Add("未打开端口" + port.ToString());
            }
        }
        /// <summary>
        /// 创建跨线程更新界面信息的委托
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public delegate void DeleUpdateportlist1(Scanner ui, int port);

        /// <summary>
        /// 跨线程更新界面信息
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public void Updateportlist1(Scanner ui, int port)
        {
            if (ui.InvokeRequired)
            {
                Delegate d = new DeleUpdateportlist1(Updateportlist1);
                ui.Invoke(d, new Object[] { ui, port});
            }
            else
            {
                ui.portlist1.Items.Add("已打开端口" + port.ToString());
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

        /// <summary>
        /// 创建跨线程更新界面信息的委托
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="value"></param>
        public delegate void DeleUpdateBtnStart(Scanner ui, bool value);

        /// <summary>
        /// 跨线程更新界面信息 开始按钮
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="value"></param>
        public void UpdateBtnStart(Scanner ui, bool value)
        {
            if (ui.InvokeRequired)
            {
                Delegate d = new DeleUpdateBtnStart(UpdateBtnStart);
                ui.Invoke(d, new object[] { ui, value });
            }
            else
            {
                ui.BtnStart.Enabled = value;
            }
        }

        public class syn
        {
            private uint ip;
            private ushort port;
            private EndPoint ep;
            private Random rand;
            private Socket sock;
            private DataStructures.ipHeader iph;
            private DataStructures.psdHeader psh;
            private DataStructures.tcpHeader tch;
            public byte pFlag;
            public UInt16 checksum(UInt16[] buffer, int size)
            {
                Int32 cksum = 0;
                int counter;
                counter = 0;

                while (size > 0)
                {
                    UInt16 val = buffer[counter];

                    cksum += Convert.ToInt32(buffer[counter]);
                    counter += 1;
                    size -= 1;
                }

                cksum = (cksum >> 16) + (cksum & 0xffff);
                cksum += (cksum >> 16);
                return (UInt16)(~cksum);
            }
              
            public syn(uint _ip, ushort _port, EndPoint _ep, Random _rand, byte flag)
            {
                ip = _ip;
                port = _port;
                ep = _ep;
                rand = _rand;
                DataStructures.ipHeader iph = new DataStructures.ipHeader();
                psh = new DataStructures.psdHeader();
                tch = new DataStructures.tcpHeader();
                sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);
                //这2个挺重要，必须这样才可以自己提供ip头  
                pFlag = flag;
            }
              
            /// <summary>
            /// 传参数的多线程需要用到代构造函数的对象
            /// </summary>
            /// <param name="pFlag">标志位参数 1为Fin 2为Syn</param>
            unsafe public void synFS()
            {
                iph.ip_verlen = (byte)(4 << 4 | sizeof(DataStructures.ipHeader) / sizeof(uint));                //ipv4，20字节ip头，这个固定就是69  
                iph.ip_tos = 0;                //这个0就行了  
                //这个是ip头+tcp头总长，40是最小长度，不带tcp option，应该是0028但是还是网络字节序所以倒过来成了2800  
                iph.ip_id = 0x9B18;                //这个我是拦截ie发送。直接添上来了  
                iph.ip_offset = 0x40;                //这个也是拦截ie的  
                iph.ip_ttl = 64;                //也是拦截ie的，也可以是128什么的。  
                iph.ip_protocol = 6;                //6就是tcp协议  
                iph.ip_checksum = UInt16.Parse("0");                //没计算之前都写0  
                iph.ip_destaddr = ip;                //ip头的目标地址就是要攻击的地址，上面传过来的。  
                psh.daddr = iph.ip_destaddr;                //伪tcp首部用于校验的，上面是目的地址，和ip的那个一样。  
                psh.mbz = 0;                //这个据说0就行  
                psh.ptcl = 6;                //6是tcp协议  
                psh.tcpl = 0x1400;                //tcp首部的大小，20字节，应该是0014，还是字节序原因成了1400  
                byte[] rport = BitConverter.GetBytes(port); //反转端口号 -by Hamvorinf
                Array.Reverse(rport); 
                tch.th_dport = BitConverter.ToUInt16(rport,0);                //扫描端口号，上面传过来的  
                tch.th_ack = 0;                //第一次发送所以没有服务器返回的序列号，为0  
                tch.th_lenres = (byte)((sizeof(DataStructures.tcpHeader) / 4 << 4 | 0));                //tcp长度  
                tch.th_flag = pFlag;               
                tch.th_win = ushort.Parse("16614");                //拦截ie的  
                tch.th_sum = UInt16.Parse("0");                //没计算之前都为0  
                tch.th_urp = UInt16.Parse("0");                //这个连ip都是0，新的攻击方法有改这个值的  
                System.Net.IPAddress[] addressList = Dns.GetHostByName(Dns.GetHostName()).AddressList;
                iph.ip_srcaddr = Convert.ToUInt32(IPAddress.Parse(addressList[0].ToString()).Address);
                psh.saddr = iph.ip_srcaddr;
                ushort duankou = Convert.ToUInt16(0);
                byte[] bt = BitConverter.GetBytes(duankou);
                Array.Reverse(bt);
                tch.th_sport = BitConverter.ToUInt16(bt, 0);
                tch.th_seq = IPAddress.HostToNetworkOrder((int)rand.Next(-2147483646, 2147483646));

                iph.ip_checksum = 0;
                tch.th_sum = 0;
                byte[] psh_buf = new byte[sizeof(DataStructures.psdHeader)];
                Int32 index = 0;
                index = pshto(psh, psh_buf, sizeof(DataStructures.psdHeader));
                if (index == -1)
                {
                    return;
                }
                index = 0;
                byte[] tch_buf = new byte[sizeof(DataStructures.tcpHeader)];
                index = tchto(tch, tch_buf, sizeof(DataStructures.tcpHeader));
                if (index == -1)
                {
                    return;
                }
                index = 0;
                byte[] tcphe = new byte[sizeof(DataStructures.psdHeader) + sizeof(DataStructures.tcpHeader)];
                Array.Copy(psh_buf, 0, tcphe, index, psh_buf.Length);
                index += psh_buf.Length;
                Array.Copy(tch_buf, 0, tcphe, index, tch_buf.Length);
                index += tch_buf.Length;
                tch.th_sum = chec(tcphe, index);
                index = 0;
                index = tchto(tch, tch_buf, sizeof(DataStructures.tcpHeader));
                if (index == -1)
                {
                    return;
                }
                index = 0;
                byte[] ip_buf = new byte[sizeof(DataStructures.ipHeader)];
                index = ipto(iph, ip_buf, sizeof(DataStructures.ipHeader));
                if (index == -1)
                {
                    return;
                }
                index = 0;
                byte[] iptcp = new byte[sizeof(DataStructures.ipHeader) + sizeof(DataStructures.tcpHeader)];
                Array.Copy(ip_buf, 0, iptcp, index, ip_buf.Length);
                index += ip_buf.Length;
                Array.Copy(tch_buf, 0, iptcp, index, tch_buf.Length);
                index += tch_buf.Length;
                iph.ip_checksum = chec(iptcp, index);
                index = 0;
                index = ipto(iph, ip_buf, sizeof(DataStructures.tcpHeader));
                if (index == -1)
                {
                    return;
                }
                index = 0;
                Array.Copy(ip_buf, 0, iptcp, index, ip_buf.Length);
                index += ip_buf.Length;
                Array.Copy(tch_buf, 0, iptcp, index, tch_buf.Length);
                index += tch_buf.Length;
                if (iptcp.Length != (sizeof(DataStructures.ipHeader) + sizeof(DataStructures.tcpHeader)))
                {
                    return;
                }
                //上面这一大堆东西就是计算校验和的方法了，方法是  
                //1、建立一个字节数组，前面放tcp伪首部后面放tcp首部，然后计算，确定最终tcp部分的校验和  
                //2、把确定了校验和地tcp首部重新生成字节数组，这是就不加tcp伪首部了，所以工20字节  
                //3、建40字节字节数组，前面放ip首部，后面放tcp首部，校验，确定最终ip部分校验和  
                //4、最后把确定了ip校验和的ip部分和tcp部分先后放入40字节的字节数组中，就是要发送的buffer[]了，就是这么麻烦  
                try
                {
                    sock.SendTo(iptcp, ep);
                    //构造发送字节数组总是麻烦，发送就简单了，socket.sendto就可以了  
                }
                catch
                {
                    return;
                }
            }

            /// <summary>
            /// 这个是计算校验，把那些类型不一样的全转为16位字节数组用的
            /// </summary>
            /// <param name="buffer"></param>
            /// <param name="size"></param>
            /// <returns></returns>
            public UInt16 chec(byte[] buffer, int size)
            {
                Double double_length = Convert.ToDouble(size);
                Double dtemp = Math.Ceiling(double_length / 2);
                int cksum_buffer_length = Convert.ToInt32(dtemp);
                UInt16[] cksum_buffer = new UInt16[cksum_buffer_length];
                int icmp_header_buffer_index = 0;
                for (int i = 0; i < cksum_buffer_length; i++)
                {
                    cksum_buffer[i] =
                     BitConverter.ToUInt16(buffer, icmp_header_buffer_index);
                    icmp_header_buffer_index += 2;
                }
                UInt16 u_cksum = checksum(cksum_buffer, cksum_buffer_length);
                return u_cksum;
            }
            
            /// <summary>
            /// 这个是把ip部分转为字节数组用的
            /// </summary>
            /// <param name="iph"></param>
            /// <param name="Buffer"></param>
            /// <param name="size"></param>
            /// <returns></returns>
            public Int32 ipto(DataStructures.ipHeader iph, byte[] Buffer, int size)
            {
                Int32 rtn = 0;
                int index = 0;
                byte[] b_verlen = new byte[1];
                b_verlen[0] = iph.ip_verlen;
                byte[] b_tos = new byte[1];
                b_tos[0] = iph.ip_tos;
                byte[] b_totallen = BitConverter.GetBytes(iph.ip_totallength);
                byte[] b_id = BitConverter.GetBytes(iph.ip_id);
                byte[] b_offset = BitConverter.GetBytes(iph.ip_offset);
                byte[] b_ttl = new byte[1];
                b_ttl[0] = iph.ip_ttl;
                byte[] b_protol = new byte[1];
                b_protol[0] = iph.ip_protocol;
                byte[] b_checksum = BitConverter.GetBytes(iph.ip_checksum);
                byte[] b_srcaddr = BitConverter.GetBytes(iph.ip_srcaddr);
                byte[] b_destaddr = BitConverter.GetBytes(iph.ip_destaddr);
                Array.Copy(b_verlen, 0, Buffer, index, b_verlen.Length);
                index += b_verlen.Length;
                Array.Copy(b_tos, 0, Buffer, index, b_tos.Length);
                index += b_tos.Length;
                Array.Copy(b_totallen, 0, Buffer, index, b_totallen.Length);
                index += b_totallen.Length;
                Array.Copy(b_id, 0, Buffer, index, b_id.Length);
                index += b_id.Length;
                Array.Copy(b_offset, 0, Buffer, index, b_offset.Length);
                index += b_offset.Length;
                Array.Copy(b_ttl, 0, Buffer, index, b_ttl.Length);
                index += b_ttl.Length;
                Array.Copy(b_protol, 0, Buffer, index, b_protol.Length);
                index += b_protol.Length;
                Array.Copy(b_checksum, 0, Buffer, index, b_checksum.Length);
                index += b_checksum.Length;
                Array.Copy(b_srcaddr, 0, Buffer, index, b_srcaddr.Length);
                index += b_srcaddr.Length;
                Array.Copy(b_destaddr, 0, Buffer, index, b_destaddr.Length);
                index += b_destaddr.Length;
                if (index != size/* sizeof(IcmpPacket)   */)
                {
                    rtn = -1;
                    return rtn;
                }

                rtn = index;
                return rtn;

            }
            
            /// <summary>
            /// 这个是把tcp伪首部转为字节数组用的
            /// </summary>
            /// <param name="psh"></param>
            /// <param name="buffer"></param>
            /// <param name="size"></param>
            /// <returns></returns>
            public Int32 pshto(DataStructures.psdHeader psh, byte[] buffer, int size)
            {
                Int32 rtn;
                int index = 0;
                byte[] b_psh_saddr = BitConverter.GetBytes(psh.saddr);
                byte[] b_psh_daddr = BitConverter.GetBytes(psh.daddr);
                byte[] b_psh_mbz = new byte[1];
                b_psh_mbz[0] = psh.mbz;
                byte[] b_psh_ptcl = new byte[1];
                b_psh_ptcl[0] = psh.ptcl;
                byte[] b_psh_tcpl = BitConverter.GetBytes(psh.tcpl);
                Array.Copy(b_psh_saddr, 0, buffer, index, b_psh_saddr.Length);
                index += b_psh_saddr.Length;
                Array.Copy(b_psh_daddr, 0, buffer, index, b_psh_daddr.Length);
                index += b_psh_daddr.Length;
                Array.Copy(b_psh_mbz, 0, buffer, index, b_psh_mbz.Length);
                index += b_psh_mbz.Length;
                Array.Copy(b_psh_ptcl, 0, buffer, index, b_psh_ptcl.Length);
                index += b_psh_ptcl.Length;
                Array.Copy(b_psh_tcpl, 0, buffer, index, b_psh_tcpl.Length);
                index += b_psh_tcpl.Length;
                if (index != size)
                {
                    rtn = -1;
                    return rtn;
                }
                else
                {
                    rtn = index;
                    return rtn;
                }

            }
            
            /// <summary>
            /// 这个是把tcp部分转为字节数组用的，因为这个要用到2次就不把这个和伪首部放一块了
            /// </summary>
            /// <param name="tch"></param>
            /// <param name="buffer"></param>
            /// <param name="size"></param>
            /// <returns></returns>
            public Int32 tchto(DataStructures.tcpHeader tch, byte[] buffer, int size)
            {
                Int32 rtn;
                int index = 0;
                byte[] b_tch_sport = BitConverter.GetBytes(tch.th_sport);
                byte[] b_tch_dport = BitConverter.GetBytes(tch.th_dport);
                byte[] b_tch_seq = BitConverter.GetBytes(tch.th_seq);
                byte[] b_tch_ack = BitConverter.GetBytes(tch.th_ack);
                byte[] b_tch_lenres = new byte[1];
                b_tch_lenres[0] = tch.th_lenres;
                byte[] b_tch_flag = new byte[1];
                b_tch_flag[0] = tch.th_flag;
                byte[] b_tch_win = BitConverter.GetBytes(tch.th_win);
                byte[] b_tch_sum = BitConverter.GetBytes(tch.th_sum);
                byte[] b_tch_urp = BitConverter.GetBytes(tch.th_urp);
                Array.Copy(b_tch_sport, 0, buffer, index, b_tch_sport.Length);
                index += b_tch_sport.Length;
                Array.Copy(b_tch_dport, 0, buffer, index, b_tch_dport.Length);
                index += b_tch_dport.Length;
                Array.Copy(b_tch_seq, 0, buffer, index, b_tch_seq.Length);
                index += b_tch_seq.Length;
                Array.Copy(b_tch_ack, 0, buffer, index, b_tch_ack.Length);
                index += b_tch_ack.Length;
                Array.Copy(b_tch_lenres, 0, buffer, index, b_tch_lenres.Length);
                index += b_tch_lenres.Length;
                Array.Copy(b_tch_flag, 0, buffer, index, b_tch_flag.Length);
                index += b_tch_flag.Length;
                Array.Copy(b_tch_win, 0, buffer, index, b_tch_win.Length);
                index += b_tch_win.Length;
                Array.Copy(b_tch_sum, 0, buffer, index, b_tch_sum.Length);
                index += b_tch_sum.Length;
                Array.Copy(b_tch_urp, 0, buffer, index, b_tch_urp.Length);
                index += b_tch_urp.Length;
                if (index != size)
                {
                    rtn = -1;
                    return rtn;
                }
                else
                {
                    rtn = index;
                    return rtn;
                }
            }  
        }
    }
}
