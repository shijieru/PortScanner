using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace MyScanner.MyClasses
{
    /// <summary>
    /// TcpConnectɨ��
    /// </summary>
    class CTcpConnect
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
        public CTcpConnect(MyScanner.Scanner UI,int threadOrder)
        {
            ui = UI;
            startPort = Convert.ToInt32(ui.TBStartPort.Text);
            endPort = Convert.ToInt32(ui.TBEndPort.Text);
            aimAddr = ui.aimIPAddress.Text.ToString();
            this.threadOrder = threadOrder;
            this.threadCount = Scanner.threadCount;
            ui.finishThread[threadOrder] = false;
        }

        /// <summary>
        /// ɨ��Ŀ���ַ�˿�
        /// </summary>
        /// <param name="aimAddr">Ŀ���ַ</param>
        /// <param name="port">�˿ں�</param>
        /// <returns></returns>
        public void ScanPorts()
        {
            //int[] openPorts;// = null;
            int[] tmpPort = new int[endPort - startPort + 1];
            //int openCount = 0;

            int p_Length = (endPort - startPort + 1) / threadCount;
            int end_Length = endPort - startPort + 1 - p_Length * (threadCount - 1);
            int p_start = p_Length * threadOrder + startPort;
            int p_Num = p_Length;

            if (threadOrder == threadCount - 1)
            {
                p_Num = end_Length;
            }


            try
            {
                //��ȡĿ��������Ϣ IP��ַ
                IPAddress ipAddr = IPAddress.Parse(aimAddr);

                for (int port = p_start; port < p_start + p_Num; port++)
                {
                    //ѭ��ɨ������˿�
                    //����ɨ���õ�socket
                    Updateloglist(ui, port);
                    Socket scanSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    scanSock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, 200);
                    scanSock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 200);

                    try
                    {
                        IPEndPoint iep = new IPEndPoint(ipAddr, port);

                        //���Դ������ӣ���������˿ڴ�������״̬���򴴽��ɹ�
                        scanSock.Connect(iep);
                        Updateportlist1(ui, port);
                        //}
                    }
                    catch
                    {
                        Updateportlist(ui, port);

                    }
                    finally
                    {
                        scanSock.Close();
                    }
                    Scanner.finishPort++;
                }
                ui.finishThread[threadOrder] = true;
                

            }
            catch
            {
                
            }
            if (Scanner.finishPort == endPort - startPort + 1)
            {
                UpdateTBResult(ui, "Finish!\r\n");
                UpdateBtnStart(ui, true);
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
                ui.loglist.Items.Add("��ɨ��˿�"+port.ToString());
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
                ui.Invoke(d, new Object[] { ui, port});
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
