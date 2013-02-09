namespace MyScanner
{
    partial class Scanner
    {
        /// <summary>
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            this.aimIPAddress = new IPAddressControlLib.IPAddressControl();
            this.BtnStart = new System.Windows.Forms.Button();
            this.TBResult = new System.Windows.Forms.TextBox();
            this.TBStartPort = new System.Windows.Forms.TextBox();
            this.TBEndPort = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.CBThreadNum = new System.Windows.Forms.ComboBox();
            this.label4 = new System.Windows.Forms.Label();
            this.BtnStop = new System.Windows.Forms.Button();
            this.radioBSynFlood = new System.Windows.Forms.RadioButton();
            this.radioBTcpFin = new System.Windows.Forms.RadioButton();
            this.radioBTcpSyn = new System.Windows.Forms.RadioButton();
            this.radioBTcpConnect = new System.Windows.Forms.RadioButton();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.label8 = new System.Windows.Forms.Label();
            this.portlist1 = new System.Windows.Forms.ListBox();
            this.label7 = new System.Windows.Forms.Label();
            this.portlist = new System.Windows.Forms.ListBox();
            this.label6 = new System.Windows.Forms.Label();
            this.loglist = new System.Windows.Forms.ListBox();
            this.label5 = new System.Windows.Forms.Label();
            this.radioBPingFlood = new System.Windows.Forms.RadioButton();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.radioBUdpConnect = new System.Windows.Forms.RadioButton();
            this.groupBox5 = new System.Windows.Forms.GroupBox();
            this.convertBt = new System.Windows.Forms.Button();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.groupBox5.SuspendLayout();
            this.SuspendLayout();
            // 
            // aimIPAddress
            // 
            this.aimIPAddress.AllowInternalTab = false;
            this.aimIPAddress.AutoHeight = true;
            this.aimIPAddress.BackColor = System.Drawing.SystemColors.Window;
            this.aimIPAddress.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.aimIPAddress.Cursor = System.Windows.Forms.Cursors.IBeam;
            this.aimIPAddress.Location = new System.Drawing.Point(58, 20);
            this.aimIPAddress.MinimumSize = new System.Drawing.Size(96, 21);
            this.aimIPAddress.Name = "aimIPAddress";
            this.aimIPAddress.ReadOnly = false;
            this.aimIPAddress.Size = new System.Drawing.Size(148, 21);
            this.aimIPAddress.TabIndex = 0;
            this.aimIPAddress.Text = "127.0.0.1";
            // 
            // BtnStart
            // 
            this.BtnStart.Location = new System.Drawing.Point(15, 20);
            this.BtnStart.Name = "BtnStart";
            this.BtnStart.Size = new System.Drawing.Size(76, 40);
            this.BtnStart.TabIndex = 1;
            this.BtnStart.Text = "开始扫描";
            this.BtnStart.UseVisualStyleBackColor = true;
            this.BtnStart.Click += new System.EventHandler(this.BtnStart_Click);
            // 
            // TBResult
            // 
            this.TBResult.Location = new System.Drawing.Point(542, 32);
            this.TBResult.Multiline = true;
            this.TBResult.Name = "TBResult";
            this.TBResult.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.TBResult.Size = new System.Drawing.Size(214, 262);
            this.TBResult.TabIndex = 2;
            // 
            // TBStartPort
            // 
            this.TBStartPort.Location = new System.Drawing.Point(264, 20);
            this.TBStartPort.MaxLength = 5;
            this.TBStartPort.Name = "TBStartPort";
            this.TBStartPort.Size = new System.Drawing.Size(47, 21);
            this.TBStartPort.TabIndex = 5;
            this.TBStartPort.Text = "1";
            this.TBStartPort.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.TBStartPort_KeyPress);
            // 
            // TBEndPort
            // 
            this.TBEndPort.Location = new System.Drawing.Point(334, 20);
            this.TBEndPort.MaxLength = 5;
            this.TBEndPort.Name = "TBEndPort";
            this.TBEndPort.Size = new System.Drawing.Size(47, 21);
            this.TBEndPort.TabIndex = 6;
            this.TBEndPort.Text = "120";
            this.TBEndPort.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.TBEndPort_KeyPress);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(317, 23);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(11, 12);
            this.label1.TabIndex = 7;
            this.label1.Text = "-";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(6, 25);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(53, 12);
            this.label2.TabIndex = 8;
            this.label2.Text = "目标地址";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(212, 25);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(53, 12);
            this.label3.TabIndex = 9;
            this.label3.Text = "目标端口";
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.CBThreadNum);
            this.groupBox1.Controls.Add(this.label4);
            this.groupBox1.Controls.Add(this.aimIPAddress);
            this.groupBox1.Controls.Add(this.label3);
            this.groupBox1.Controls.Add(this.TBStartPort);
            this.groupBox1.Controls.Add(this.label2);
            this.groupBox1.Controls.Add(this.TBEndPort);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Location = new System.Drawing.Point(12, 12);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(774, 54);
            this.groupBox1.TabIndex = 10;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "参数设置";
            // 
            // CBThreadNum
            // 
            this.CBThreadNum.FormatString = "N0";
            this.CBThreadNum.FormattingEnabled = true;
            this.CBThreadNum.Items.AddRange(new object[] {
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "10",
            "11",
            "12",
            "13",
            "14",
            "15",
            "16",
            "17",
            "18",
            "19",
            "20"});
            this.CBThreadNum.Location = new System.Drawing.Point(429, 20);
            this.CBThreadNum.Name = "CBThreadNum";
            this.CBThreadNum.Size = new System.Drawing.Size(53, 20);
            this.CBThreadNum.TabIndex = 16;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(386, 25);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(41, 12);
            this.label4.TabIndex = 15;
            this.label4.Text = "线程数";
            // 
            // BtnStop
            // 
            this.BtnStop.Enabled = false;
            this.BtnStop.Location = new System.Drawing.Point(112, 20);
            this.BtnStop.Name = "BtnStop";
            this.BtnStop.Size = new System.Drawing.Size(74, 40);
            this.BtnStop.TabIndex = 14;
            this.BtnStop.Text = "停止攻击";
            this.BtnStop.UseVisualStyleBackColor = true;
            this.BtnStop.Click += new System.EventHandler(this.BtnStop_Click);
            // 
            // radioBSynFlood
            // 
            this.radioBSynFlood.AutoSize = true;
            this.radioBSynFlood.Location = new System.Drawing.Point(9, 44);
            this.radioBSynFlood.Name = "radioBSynFlood";
            this.radioBSynFlood.Size = new System.Drawing.Size(95, 16);
            this.radioBSynFlood.TabIndex = 13;
            this.radioBSynFlood.Text = "SynFlood攻击";
            this.radioBSynFlood.UseVisualStyleBackColor = true;
            // 
            // radioBTcpFin
            // 
            this.radioBTcpFin.AutoSize = true;
            this.radioBTcpFin.Location = new System.Drawing.Point(304, 16);
            this.radioBTcpFin.Name = "radioBTcpFin";
            this.radioBTcpFin.Size = new System.Drawing.Size(59, 16);
            this.radioBTcpFin.TabIndex = 12;
            this.radioBTcpFin.Text = "TcpFin";
            this.radioBTcpFin.UseVisualStyleBackColor = true;
            // 
            // radioBTcpSyn
            // 
            this.radioBTcpSyn.AutoSize = true;
            this.radioBTcpSyn.Location = new System.Drawing.Point(215, 16);
            this.radioBTcpSyn.Name = "radioBTcpSyn";
            this.radioBTcpSyn.Size = new System.Drawing.Size(59, 16);
            this.radioBTcpSyn.TabIndex = 11;
            this.radioBTcpSyn.Text = "TcpSyn";
            this.radioBTcpSyn.UseVisualStyleBackColor = true;
            // 
            // radioBTcpConnect
            // 
            this.radioBTcpConnect.AutoSize = true;
            this.radioBTcpConnect.Checked = true;
            this.radioBTcpConnect.Location = new System.Drawing.Point(8, 16);
            this.radioBTcpConnect.Name = "radioBTcpConnect";
            this.radioBTcpConnect.Size = new System.Drawing.Size(83, 16);
            this.radioBTcpConnect.TabIndex = 10;
            this.radioBTcpConnect.TabStop = true;
            this.radioBTcpConnect.Text = "TcpConnect";
            this.radioBTcpConnect.UseVisualStyleBackColor = true;
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.label8);
            this.groupBox2.Controls.Add(this.portlist1);
            this.groupBox2.Controls.Add(this.label7);
            this.groupBox2.Controls.Add(this.portlist);
            this.groupBox2.Controls.Add(this.label6);
            this.groupBox2.Controls.Add(this.loglist);
            this.groupBox2.Controls.Add(this.label5);
            this.groupBox2.Controls.Add(this.TBResult);
            this.groupBox2.Location = new System.Drawing.Point(12, 152);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(774, 302);
            this.groupBox2.TabIndex = 11;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "扫描结果";
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(539, 18);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(53, 12);
            this.label8.TabIndex = 9;
            this.label8.Text = "运行信息";
            // 
            // portlist1
            // 
            this.portlist1.FormattingEnabled = true;
            this.portlist1.ItemHeight = 12;
            this.portlist1.Location = new System.Drawing.Point(337, 34);
            this.portlist1.Name = "portlist1";
            this.portlist1.Size = new System.Drawing.Size(145, 256);
            this.portlist1.TabIndex = 8;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(334, 18);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(65, 12);
            this.label7.TabIndex = 7;
            this.label7.Text = "打开的端口";
            // 
            // portlist
            // 
            this.portlist.FormattingEnabled = true;
            this.portlist.ItemHeight = 12;
            this.portlist.Location = new System.Drawing.Point(166, 34);
            this.portlist.Name = "portlist";
            this.portlist.Size = new System.Drawing.Size(145, 256);
            this.portlist.TabIndex = 6;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(163, 18);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(65, 12);
            this.label6.TabIndex = 5;
            this.label6.Text = "未开放端口";
            // 
            // loglist
            // 
            this.loglist.FormattingEnabled = true;
            this.loglist.ItemHeight = 12;
            this.loglist.Location = new System.Drawing.Point(12, 34);
            this.loglist.Name = "loglist";
            this.loglist.Size = new System.Drawing.Size(141, 256);
            this.loglist.TabIndex = 4;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(9, 18);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(65, 12);
            this.label5.TabIndex = 3;
            this.label5.Text = "已扫描端口";
            // 
            // radioBPingFlood
            // 
            this.radioBPingFlood.AutoSize = true;
            this.radioBPingFlood.Location = new System.Drawing.Point(127, 44);
            this.radioBPingFlood.Name = "radioBPingFlood";
            this.radioBPingFlood.Size = new System.Drawing.Size(101, 16);
            this.radioBPingFlood.TabIndex = 17;
            this.radioBPingFlood.TabStop = true;
            this.radioBPingFlood.Text = "PingFlood攻击";
            this.radioBPingFlood.UseVisualStyleBackColor = true;
            // 
            // groupBox3
            // 
            this.groupBox3.Controls.Add(this.radioBUdpConnect);
            this.groupBox3.Controls.Add(this.radioBPingFlood);
            this.groupBox3.Controls.Add(this.radioBTcpConnect);
            this.groupBox3.Controls.Add(this.radioBSynFlood);
            this.groupBox3.Controls.Add(this.radioBTcpSyn);
            this.groupBox3.Controls.Add(this.radioBTcpFin);
            this.groupBox3.Location = new System.Drawing.Point(12, 72);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(368, 74);
            this.groupBox3.TabIndex = 18;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "操作选项";
            // 
            // radioBUdpConnect
            // 
            this.radioBUdpConnect.AutoSize = true;
            this.radioBUdpConnect.Location = new System.Drawing.Point(114, 16);
            this.radioBUdpConnect.Name = "radioBUdpConnect";
            this.radioBUdpConnect.Size = new System.Drawing.Size(83, 16);
            this.radioBUdpConnect.TabIndex = 18;
            this.radioBUdpConnect.TabStop = true;
            this.radioBUdpConnect.Text = "UdpConnect";
            this.radioBUdpConnect.UseVisualStyleBackColor = true;
            // 
            // groupBox5
            // 
            this.groupBox5.Controls.Add(this.convertBt);
            this.groupBox5.Controls.Add(this.BtnStart);
            this.groupBox5.Controls.Add(this.BtnStop);
            this.groupBox5.Location = new System.Drawing.Point(481, 72);
            this.groupBox5.Name = "groupBox5";
            this.groupBox5.Size = new System.Drawing.Size(305, 74);
            this.groupBox5.TabIndex = 20;
            this.groupBox5.TabStop = false;
            this.groupBox5.Text = "按钮控制";
            // 
            // convertBt
            // 
            this.convertBt.Location = new System.Drawing.Point(204, 20);
            this.convertBt.Name = "convertBt";
            this.convertBt.Size = new System.Drawing.Size(75, 40);
            this.convertBt.TabIndex = 15;
            this.convertBt.Text = "IP段扫描";
            this.convertBt.UseVisualStyleBackColor = true;
            this.convertBt.Click += new System.EventHandler(this.convertBt_Click);
            // 
            // Scanner
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(798, 466);
            this.Controls.Add(this.groupBox5);
            this.Controls.Add(this.groupBox3);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.groupBox1);
            this.Name = "Scanner";
            this.Text = "端口扫描器";
            this.Load += new System.EventHandler(this.Scanner_Load);
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.groupBox3.ResumeLayout(false);
            this.groupBox3.PerformLayout();
            this.groupBox5.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        public IPAddressControlLib.IPAddressControl aimIPAddress;
        public System.Windows.Forms.Button BtnStart;
        public System.Windows.Forms.TextBox TBResult;
        public System.Windows.Forms.TextBox TBStartPort;
        public System.Windows.Forms.TextBox TBEndPort;
        public System.Windows.Forms.Label label1;
        public System.Windows.Forms.Label label2;
        public System.Windows.Forms.Label label3;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.RadioButton radioBTcpConnect;
        private System.Windows.Forms.RadioButton radioBTcpSyn;
        private System.Windows.Forms.RadioButton radioBTcpFin;
        private System.Windows.Forms.RadioButton radioBSynFlood;
        private System.Windows.Forms.Button BtnStop;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.ComboBox CBThreadNum;
        private System.Windows.Forms.RadioButton radioBPingFlood;
        private System.Windows.Forms.GroupBox groupBox3;
        private System.Windows.Forms.GroupBox groupBox5;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.RadioButton radioBUdpConnect;
        public System.Windows.Forms.ListBox portlist1;
        public System.Windows.Forms.ListBox portlist;
        public System.Windows.Forms.ListBox loglist;
        public System.Windows.Forms.Label label7;
        private System.Windows.Forms.Button convertBt;

    }
}

