using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace MyScanner.MyClasses
{
    class CTcpFin
    {
        public int startPort;
        public int endPort;
        public int threadOrder;
        public string aimAddr;
        public int threadCount;
        MyScanner.Scanner ui;

        /// <summary>
        /// ���캯������ʼ������
        /// </summary>
        /// <param name="UI"></param>
        public CTcpFin(MyScanner.Scanner UI)
        {
            ui = UI;
            startPort = Convert.ToInt32(ui.TBStartPort.Text);
            endPort = Convert.ToInt32(ui.TBEndPort.Text);
            aimAddr = ui.aimIPAddress.Text.ToString();
            this.threadCount = Scanner.threadCount;
            Scanner.finishPort = 0;
        }

        public void socket_PacketArrival(object sender, RawSocket.PacketArrivedEventArgs args)
        {
            if (args.Protocol == "TCP" && args.OriginationAddress == aimAddr)
            {
                //�������ݰ�
                byte[] revMsg = args.ReceiveBuffer;
                byte flag = revMsg[33];
                ushort port = BitConverter.ToUInt16(revMsg, 20);
                byte[] rport = BitConverter.GetBytes(port);
                Array.Reverse(rport);
                port = BitConverter.ToUInt16(rport, 0);
                if (flag == 0x0004 || flag == 0x0014)
                {
                    Updateportlist(ui, port);
                }
                if (Scanner.finishPort == System.Math.Abs(endPort - startPort + 1))
                {
                    UpdateTBResult(ui, "Finish!\r\n");
                    socket.Shutdown();
                    UpdateBtnStart(ui, true);
                }

            }
        }
       
        public RawSocket socket = null;
        //Thread listener;
        public void listen()
        {
            

            try
            {
                //��ȡ������ַ
                string hostName = Dns.GetHostName();
                IPAddress hostAddr = (IPAddress)Dns.GetHostByName(hostName).AddressList[0];
                string myAddr = hostAddr.ToString();

                socket = new RawSocket();
                socket.CreateAndBindSocket(myAddr);
                if (socket.ErrorOccurred)
                {
                    //MessageBox.Show("�������ִ���");
                    UpdateTBResult(ui, "�������ִ���\r\n");
                    return;
                }
                socket.KeepRunning = true;
                socket.PacketArrival += socket_PacketArrival;
                socket.Run();
            }
            catch// (Exception ex)
            {
                //Console.WriteLine(ex);
                //throw;
            }
            finally
            {
                //Console.Read();
                //socket.Shutdown();
            }
            

        }
        public struct ipHeader
        {
            public byte ip_verlen; //4λ�ײ�����+4λIP�汾��  
            public byte ip_tos; //8λ��������TOS  
            public ushort ip_totallength; //16λ���ݰ��ܳ��ȣ��ֽڣ�  
            public ushort ip_id; //16λ��ʶ  
            public ushort ip_offset; //3λ��־λ  
            public byte ip_ttl; //8λ����ʱ�� TTL  
            public byte ip_protocol; //8λЭ��(TCP, UDP, ICMP, Etc.)  
            public ushort ip_checksum; //16λIP�ײ�У���  
            public uint ip_srcaddr; //32λԴIP��ַ  
            public uint ip_destaddr; //32λĿ��IP��ַ  
        }
        public struct psdHeader
        {
            public uint saddr;   //Դ��ַ  
            public uint daddr;   //Ŀ�ĵ�ַ  
            public byte mbz;
            public byte ptcl;      //Э������  
            public ushort tcpl;   //TCP����  
        }
        public struct tcpHeader
        {
            public ushort th_sport;     //16λԴ�˿�  
            public ushort th_dport;     //16λĿ�Ķ˿�  
            public int th_seq;    //32λ���к�  
            public uint th_ack;    //32λȷ�Ϻ�  
            public byte th_lenres;   //4λ�ײ�����/6λ������  
            public byte th_flag;    //6λ��־λ  
            public ushort th_win;      //16λ���ڴ�С  
            public ushort th_sum;      //16λУ���  
            public ushort th_urp;      //16λ��������ƫ����  
        }
        //==========���崫����̱�ʾ��=========BEGIN
        //private Thread SenderThread;
        //private Thread CatcherThread;
        //==========���崫����̱�ʾ��=========END
        public void SenderSocket()
        {
            try
            {
                //Thread lner = new Thread(new ThreadStart(listen));
                //lner.Start();
                for (int i = startPort; i <= endPort; i++)
                {
                    try
                    {
                        IPHostEntry pe = Dns.GetHostByName(aimAddr);
                        uint ip = Convert.ToUInt32(pe.AddressList[0].Address);//����Ҫ������ip��תΪ�����ֽ���  
                        ushort port = ushort.Parse(i.ToString());
                        IPEndPoint ep = new IPEndPoint(pe.AddressList[0], port);
                        Updateloglist(ui, port);
                        //byte[] bt = BitConverter.GetBytes(port);
                        //Array.Reverse(bt);
                        //port = BitConverter.ToUInt16(bt, 0);
                        

                        int xiancheng = 1;//!
                        Random rand = new Random();
                        Thread[] t = new Thread[xiancheng];
                        syn[] sy = new syn[xiancheng];
                        for (int j = 0; j < xiancheng; j++)
                        {
                            
                            sy[j] = new syn(ip, port, ep, rand);
                            t[j] = new Thread(new ThreadStart(sy[j].synFS));
                            t[j].Start();
                        }
                        Scanner.finishPort++;
                    }
                    catch
                    {
                        //MessageBox.Show("����δ֪����");
                        UpdateTBResult(ui, "����δ֪����\r\n");
                    }
                }
                //listen();
            }
            catch (Exception ex)
            {
                //MessageBox.Show(ex.Message);
                UpdateTBResult(ui, ex.Message.ToString() + "\r\n");
            }
        }
        

        public class syn
        {
            private uint ip;
            private ushort port;
            private EndPoint ep;
            private Random rand;
            private Socket sock;
            private ipHeader iph;
            private psdHeader psh;
            private tcpHeader tch;
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
              
            public syn(uint _ip, ushort _port, EndPoint _ep, Random _rand)
            {
                ip = _ip;
                port = _port;
                ep = _ep;
                rand = _rand;
                ipHeader iph = new ipHeader();
                psh = new psdHeader();
                tch = new tcpHeader();
                sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);
                //��2��ͦ��Ҫ�����������ſ����Լ��ṩipͷ  
            }
            //�������Ķ��߳���Ҫ�õ������캯���Ķ���  
            unsafe public void synFS()
            {
                iph.ip_verlen = (byte)(4 << 4 | sizeof(ipHeader) / sizeof(uint));                //ipv4��20�ֽ�ipͷ������̶�����69  
                iph.ip_tos = 0;                //���0������  
                //�����ipͷ+tcpͷ�ܳ���40����С���ȣ�����tcp option��Ӧ����0028���ǻ��������ֽ������Ե���������2800  
                iph.ip_id = 0x9B18;                //�����������ie���͡�ֱ����������  
                iph.ip_offset = 0x40;                //���Ҳ������ie��  
                iph.ip_ttl = 64;                //Ҳ������ie�ģ�Ҳ������128ʲô�ġ�  
                iph.ip_protocol = 6;                //6����tcpЭ��  
                iph.ip_checksum = UInt16.Parse("0");                //û����֮ǰ��д0  
                iph.ip_destaddr = ip;                //ipͷ��Ŀ���ַ����Ҫ�����ĵ�ַ�����洫�����ġ�  
                psh.daddr = iph.ip_destaddr;                //αtcp�ײ�����У��ģ�������Ŀ�ĵ�ַ����ip���Ǹ�һ����  
                psh.mbz = 0;                //�����˵0����  
                psh.ptcl = 6;                //6��tcpЭ��  
                psh.tcpl = 0x1400;                //tcp�ײ��Ĵ�С��20�ֽڣ�Ӧ����0014�������ֽ���ԭ�����1400  
                byte[] rport = BitConverter.GetBytes(port); //��ת�˿ں� -by Hamvorinf
                Array.Reverse(rport); 
                tch.th_dport = BitConverter.ToUInt16(rport,0);                //ɨ��˿ںţ����洫������  
                tch.th_ack = 0;                //��һ�η�������û�з��������ص����кţ�Ϊ0  
                tch.th_lenres = (byte)((sizeof(tcpHeader) / 4 << 4 | 0));                //tcp����  
                tch.th_flag = 1;                //1����fin  
                tch.th_win = ushort.Parse("16614");                //����ie��  
                tch.th_sum = UInt16.Parse("0");                //û����֮ǰ��Ϊ0  
                tch.th_urp = UInt16.Parse("0");                //�����ip����0���µĹ��������и����ֵ��  
                System.Net.IPAddress[] addressList = Dns.GetHostByName(Dns.GetHostName()).AddressList;
                iph.ip_srcaddr = Convert.ToUInt32(IPAddress.Parse(addressList[0].ToString()).Address);
                psh.saddr = iph.ip_srcaddr;
                ushort duankou = Convert.ToUInt16(16868);
                byte[] bt = BitConverter.GetBytes(duankou);
                Array.Reverse(bt);
                tch.th_sport = BitConverter.ToUInt16(bt, 0);
                tch.th_seq = IPAddress.HostToNetworkOrder((int)rand.Next(-2147483646, 2147483646));

                iph.ip_checksum = 0;
                tch.th_sum = 0;
                byte[] psh_buf = new byte[sizeof(psdHeader)];
                Int32 index = 0;
                index = pshto(psh, psh_buf, sizeof(psdHeader));
                if (index == -1)
                {
                    //Console.WriteLine("����tcpα�ײ�����");
                    return;
                }
                index = 0;
                byte[] tch_buf = new byte[sizeof(tcpHeader)];
                index = tchto(tch, tch_buf, sizeof(tcpHeader));
                if (index == -1)
                {
                    //Console.WriteLine("����tcp�ײ�����1");
                    return;
                }
                index = 0;
                byte[] tcphe = new byte[sizeof(psdHeader) + sizeof(tcpHeader)];
                Array.Copy(psh_buf, 0, tcphe, index, psh_buf.Length);
                index += psh_buf.Length;
                Array.Copy(tch_buf, 0, tcphe, index, tch_buf.Length);
                index += tch_buf.Length;
                tch.th_sum = chec(tcphe, index);
                index = 0;
                index = tchto(tch, tch_buf, sizeof(tcpHeader));
                if (index == -1)
                {
                    //Console.WriteLine("����tcp�ײ�����2");
                    return;
                }
                index = 0;
                byte[] ip_buf = new byte[sizeof(ipHeader)];
                index = ipto(iph, ip_buf, sizeof(ipHeader));
                if (index == -1)
                {
                    //Console.WriteLine("����ip�ײ�����1");
                    return;
                }
                index = 0;
                byte[] iptcp = new byte[sizeof(ipHeader) + sizeof(tcpHeader)];
                Array.Copy(ip_buf, 0, iptcp, index, ip_buf.Length);
                index += ip_buf.Length;
                Array.Copy(tch_buf, 0, iptcp, index, tch_buf.Length);
                index += tch_buf.Length;
                iph.ip_checksum = chec(iptcp, index);
                index = 0;
                index = ipto(iph, ip_buf, sizeof(tcpHeader));
                if (index == -1)
                {
                    //Console.WriteLine("����ip�ײ�����2");
                    return;
                }
                index = 0;
                Array.Copy(ip_buf, 0, iptcp, index, ip_buf.Length);
                index += ip_buf.Length;
                Array.Copy(tch_buf, 0, iptcp, index, tch_buf.Length);
                index += tch_buf.Length;
                if (iptcp.Length != (sizeof(ipHeader) + sizeof(tcpHeader)))
                {
                    //Console.WriteLine("����iptcp���Ĵ���");
                    return;
                }
                //������һ��Ѷ������Ǽ���У��͵ķ����ˣ�������  
                //1������һ���ֽ����飬ǰ���tcpα�ײ������tcp�ײ���Ȼ����㣬ȷ������tcp���ֵ�У���  
                //2����ȷ����У��͵�tcp�ײ����������ֽ����飬���ǾͲ���tcpα�ײ��ˣ����Թ�20�ֽ�  
                //3����40�ֽ��ֽ����飬ǰ���ip�ײ��������tcp�ײ���У�飬ȷ������ip����У���  
                //4������ȷ����ipУ��͵�ip���ֺ�tcp�����Ⱥ����40�ֽڵ��ֽ������У�����Ҫ���͵�buffer[]�ˣ�������ô�鷳  
                try
                {
                    sock.SendTo(iptcp, ep);
                    //���췢���ֽ����������鷳�����;ͼ��ˣ�socket.sendto�Ϳ�����  
                }
                catch
                {
                    //Console.WriteLine("���ʹ���");
                    return;
                }
            }
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
            //����Ǽ���У�飬����Щ���Ͳ�һ����ȫתΪ16λ�ֽ������õ�  

            public Int32 ipto(ipHeader iph, byte[] Buffer, int size)
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
            //����ǰ�ip����תΪ�ֽ������õ�  
            public Int32 pshto(psdHeader psh, byte[] buffer, int size)
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
            //����ǰ�tcpα�ײ�תΪ�ֽ������õ�  
            public Int32 tchto(tcpHeader tch, byte[] buffer, int size)
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
            //����ǰ�tcp����תΪ�ֽ������õģ���Ϊ���Ҫ�õ�2�ξͲ��������α�ײ���һ���ˡ�  
        }



        /// <summary>
        /// �������̸߳��½�����Ϣ��ί��
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public delegate void DeleUpdateloglist(Scanner ui, int port);

        /// <summary>
        /// ���̸߳��½�����Ϣ
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
                ui.loglist.Items.Add("��ɨ��˿�" + port.ToString());
            }
        }
        /// <summary>
        /// �������̸߳��½�����Ϣ��ί��
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public delegate void DeleUpdateportlist(Scanner ui, int port);

        /// <summary>
        /// ���̸߳��½�����Ϣ
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
                ui.portlist.Items.Add("δ�򿪶˿�" + port.ToString());
            }
        }
        /// <summary>
        /// �������̸߳��½�����Ϣ��ί��
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public delegate void DeleUpdateportlist1(Scanner ui, int port);

        /// <summary>
        /// ���̸߳��½�����Ϣ
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public void Updateportlist1(Scanner ui, int port)
        {
            if (ui.InvokeRequired)
            {
                Delegate d = new DeleUpdateportlist1(Updateportlist1);
                ui.Invoke(d, new Object[] { ui, port });
            }
            else
            {
                ui.portlist1.Items.Add("�Ѵ򿪶˿�" + port.ToString());
            }
        }

        /// <summary>
        /// �������̸߳��½�����Ϣ��ί��
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="txt"></param>
        public delegate void DeleUpdateTBResult(Scanner ui, string txt);

        /// <summary>
        /// ���̸߳��½�����Ϣ
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
        /// �������̸߳��½�����Ϣ��ί��
        /// </summary>
        /// <param name="ui"></param>
        /// <param name="value"></param>
        public delegate void DeleUpdateBtnStart(Scanner ui, bool value);

        /// <summary>
        /// ���̸߳��½�����Ϣ ��ʼ��ť
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
    }
}
