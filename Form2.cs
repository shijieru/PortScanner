using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

//
using System.Net;
using System.Net.Sockets;
using System.Threading;
//

namespace MyScanner
{
    public partial class Form2 : Form
    {
        //
        public Int32 threadnum = 0;
        public bool endscan = false;

        public AutoResetEvent asyncOpsAreDone = new AutoResetEvent(false);

        public Form2()
        {
            InitializeComponent();
        }

        private void 退出ToolStripMenuItem_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Cancel;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            //----清除列表框
            loglist.Items.Clear();
            portlist.Items.Clear();
            portlist1.Items.Clear();
            //---------
            int list = 0;
            threadnum = 0;
            endscan = false;

            //try
            //{
            //    IPHostEntry HostA = new IPHostEntry();
            //    HostA = Dns.Resolve(textBox6.Text);
            //    textBox7.Text = HostA.HostName.ToString();
            //}
            //catch
            //{
            //    MessageBox.Show("不是一个合法的地址");
            //}
            button1.Enabled = false;
            button2.Enabled = true;

            string tt=textBox6.Text;
            while(tt!=textBox1.Text)
            {
                ThreadPool.QueueUserWorkItem(new WaitCallback(Startscan), tt);
                loglist.Items.Add("扫描ip："+tt);

                string startip = tt.Substring(tt.LastIndexOf(".") + 1);//获得其ip的最后一栏数字
                int rightip=int.Parse(startip)+1;//最右栏的ip 
                string leftstr = tt.Substring(0, tt.LastIndexOf("."))+".";
                tt=leftstr+rightip.ToString();
            }
        }

        public void Startscan(Object state)
        {
            string ip = state.ToString();
            int list = 0;
            threadnum++;
            if (endscan == false)
            {
                    try
                    {
                        IPHostEntry HostA = new IPHostEntry();
                        HostA = Dns.Resolve(ip);
                        string ipt = HostA.HostName.ToString();

                        TcpClient tcp = new TcpClient();
                        tcp.Connect(ipt, int.Parse(textBox2.Text));
                       
                        //list = portlist.Items.Add(port.ToString() + "端口开放" ,false);
                        MyInvoke mi = new MyInvoke(UpdateUIport);
                        this.BeginInvoke(mi, new object[] { ip + "开放" });
                        list = list + 1;


                    }
                    catch
                    {
                        //portlist1.Items.Add(port.ToString() + "端口无法连接");
                        MyInvoke mi = new MyInvoke(UpdateUI);
                        this.BeginInvoke(mi, new object[] { ip + "无法连接" });

                    }
                    finally
                    {
                        Thread.Sleep(0);
                        //loglist.Items.Add("结束线程" + port.ToString());    
                        //委托调用
                        MyInvoke mi = new MyInvoke(UpdateUI2);
                        this.BeginInvoke(mi, new object[] { "结束线程" +ip });

                        asyncOpsAreDone.Close();
                        // label5.Text = portnum.ToString();

                        MyInvoke mi3 = new MyInvoke(UpdateUI3);
                        this.BeginInvoke(mi3, new object[] { list.ToString()});
                    }
                
            }

            if (endscan == true || ip==textBox1.Text)
            {
                // button1.Enabled = true;
                // button2.Enabled = false;
                asyncOpsAreDone.Close();
                MyInvoke mi4 = new MyInvoke(UpdateUI4);
                this.BeginInvoke(mi4, new object[] { "344" });

            }

        }

        //定义一个委托 
        public delegate void MyInvoke(string str);

        //定义一个操作界面的方法 
        private void UpdateUIport(string str)
        {
            //增加项 
            //this.lstPrime.Items.Add(str);
            portlist.Items.Add(str);
        }

        //定义一个操作界面的方法 
        private void UpdateUI(string str)
        {
            //增加项 
            //this.lstPrime.Items.Add(str);
            portlist1.Items.Add(str);
        }

        //定义一个操作界面的方法 
        private void UpdateUI2(string str)
        {
            //增加项 
            //this.lstPrime.Items.Add(str);
            loglist.Items.Add(str);
        }

        //定义一个操作界面的方法 
        private void UpdateUI3(string str)
        {
            //增加项 
            //this.lstPrime.Items.Add(str);
            label5.Text = str;
        }

        //委托调用按钮，刷新界面
        private void UpdateUI4(string str)
        {
            //增加项 
            //this.lstPrime.Items.Add(str);
            button1.Enabled = true;
            button2.Enabled = false;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            button1.Enabled = true;
            button2.Enabled = false;
            endscan = true;
        }


    }
}