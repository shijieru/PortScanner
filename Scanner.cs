using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Threading;

namespace MyScanner
{
    public partial class Scanner : Form
    {
        public Scanner()
        {
            InitializeComponent();
            CBThreadNum.Text = "10";
        }

        public bool[] finishThread;
        public static int finishPort;
        public static int threadCount;
        MyClasses.CSynFlood csFlood;
        MyClasses.CPingFlood cpFlood;

        private void BtnStart_Click(object sender, EventArgs e)
        {

            loglist.Items.Clear();
            portlist.Items.Clear();
            portlist1.Items.Clear();
            TBResult.Clear();
            if (radioBTcpConnect.Checked == true)
            {
                TcpConnectScan();
            }
            else if (radioBTcpSyn.Checked == true)
            {
                TcpSynScan();
            }
            else if (radioBTcpFin.Checked == true)
            {
                TcpFinScan();
            }
            else if (radioBSynFlood.Checked == true)
            {
                SynFloodAttack();
            }
            else if (radioBPingFlood.Checked == true)
            {
                PingFloodAttack();
            }
            else if (radioBUdpConnect.Checked == true)
            {
                UdpConnectScan();
            }
        }

        /// <summary>
        /// UdpConnect模式扫描
        /// </summary>
        private void UdpConnectScan()
        {
            string aimAddr = aimIPAddress.Text.ToString();
            int pCount = System.Math.Abs(Convert.ToInt32(TBStartPort.Text) - Convert.ToInt32(TBEndPort.Text)) + 1; //端口总数
            threadCount = Convert.ToInt32(CBThreadNum.Text); //线程总数

            finishPort = 0;
            finishThread = new bool[threadCount];
            label7.Text = "不能确定的端口";
            TBResult.Text += "\r\n开始UDP扫描...";
            BtnStart.Enabled = false;

            MyClasses.CUdpConnect[] udpConnect = new MyScanner.MyClasses.CUdpConnect[threadCount];
            Thread[] thread = new Thread[threadCount];
            for (int i = 0; i < threadCount; i++)
            {
                udpConnect[i] = new MyScanner.MyClasses.CUdpConnect(this, i);
                thread[i] = new Thread(new ThreadStart(udpConnect[i].ScanPorts));
                thread[i].Start();
            }
        }
        /// <summary>
        /// TcpConnect模式扫描
        /// </summary>
        private void TcpConnectScan()
        {
            string aimAddr = aimIPAddress.Text.ToString();
            int pCount = System.Math.Abs(Convert.ToInt32(TBStartPort.Text) - Convert.ToInt32(TBEndPort.Text)) + 1;
            threadCount = Convert.ToInt32(CBThreadNum.Text);

            finishPort = 0;
            finishThread = new bool[threadCount];
            label7.Text = "打开的端口";

            TBResult.Text += "\r\n开始TCP全连接扫描...";
            BtnStart.Enabled = false;

            MyClasses.CTcpConnect[] tcpConnect = new MyScanner.MyClasses.CTcpConnect[threadCount];
            Thread[] thread = new Thread[threadCount];
            for (int i = 0; i < threadCount; i++)
            {
                tcpConnect[i] = new MyScanner.MyClasses.CTcpConnect(this, i);
                thread[i] = new Thread(new ThreadStart(tcpConnect[i].ScanPorts));
                thread[i].Start();
            }
        }

        /// <summary>s
        /// TcpSyn模式扫描
        /// </summary>
        private void TcpSynScan()
        {
            string aimAddr = aimIPAddress.Text.ToString();
            finishPort = 0;
            label7.Text = "打开的端口";
            TBResult.Text += "\r\n开始TCP半连接扫描...";
            //BtnStart.Enabled = false;
            try
            {
                MyClasses.CTcpSyn tcpSyn = new MyScanner.MyClasses.CTcpSyn(this);
                tcpSyn.Receive();
                Thread begin = new Thread(new ThreadStart(tcpSyn.ScanPorts));
                begin.Start();
                
            }
            catch
            {
            }
        }

        /// <summary>
        /// TcpFin模式扫描
        /// </summary>
        private void TcpFinScan()
        {
            label7.Text = "打开的端口";
            TBResult.Text += "\r\n开始TCPFIN扫描...";
            MyClasses.CTcpFin tcpFin = new MyScanner.MyClasses.CTcpFin(this);
            tcpFin.listen();
            Thread begin = new Thread(new ThreadStart(tcpFin.SenderSocket));
            begin.Start();
        }

        /// <summary>
        /// SynFlood攻击
        /// </summary>
        private void SynFloodAttack()
        {
            this.BtnStart.Enabled = false;
            this.BtnStop.Enabled = true;
            threadCount = Convert.ToInt32(CBThreadNum.Text);

            TBResult.Text += "\r\n开始SynFlood攻击...\r\n";
            csFlood = new MyScanner.MyClasses.CSynFlood(this);
            csFlood.BeginSynFlood();
        }

        // <summary>
        /// PingFlood攻击
        /// </summary>
        private void PingFloodAttack()
        {
            this.BtnStart.Enabled = false;
            this.BtnStop.Enabled = true;
            threadCount = Convert.ToInt32(CBThreadNum.Text);

            TBResult.Text += "\r\n开始PingFlood攻击...\r\n";
            cpFlood = new MyScanner.MyClasses.CPingFlood(this);
            Thread begin = new Thread(new ThreadStart(cpFlood.BeginPingFlood));
            begin.Start();
            
        }

        private void BtnStop_Click(object sender, EventArgs e)
        {
            if (radioBPingFlood.Checked == true && cpFlood != null)
            {
                cpFlood.StopPingFlood();
            }
            else if (radioBSynFlood.Checked == true && csFlood != null)
            {
                csFlood.StopSynFlood();
            }
            this.BtnStart.Enabled = true;
            this.BtnStop.Enabled = false;
        }

        private void TBStartPort_KeyPress(object sender, KeyPressEventArgs e)
        {
            //验证输入为数字
            if (!(char.IsNumber(e.KeyChar) || e.KeyChar == '\b'))
            {
                e.Handled = true;
            }
        }

        private void TBEndPort_KeyPress(object sender, KeyPressEventArgs e)
        {
            //验证输入为数字
            if (!(char.IsNumber(e.KeyChar) || e.KeyChar == '\b'))
            {
                e.Handled = true;
            }
        }

        private void Scanner_Load(object sender, EventArgs e)
        {

        }

        private void convertBt_Click(object sender, EventArgs e)
        {
            Form2 tt = new Form2();
            tt.ShowDialog();
        }
    }
}