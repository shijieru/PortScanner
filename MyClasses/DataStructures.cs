using System;
using System.Collections.Generic;
using System.Text;

namespace MyScanner.MyClasses
{
    class DataStructures
    {
        /// <summary>
        /// IPV4���ݱ�ͷ
        /// </summary>
        public class IP_HEADER
        {
            public byte ver_hlen;   //4λIP�汾��+4λ�ײ�����
            public byte TOS;   //8λ��������
            public ushort totalLen;   //���ݱ�16λ�ܳ���
            public ushort ident;   //16λ��ʶ
            public ushort frag_and_flags;   //3λ��־λ+13λ�ֶ�ƫ��
            public byte ttl;   //8λ����ʱ��   TTL
            public byte proto;   //8λ�ϲ�Э��(TCP,UDP��)
            public ushort checksum;   //16λIP�ײ�У���
            public int sourceIP;   //32λԴIP��ַ
            public int destIP;   //32λĿ��IP��ַ
        }

        /// <summary>
        /// TCP���ݱ�ͷ
        /// </summary>
        public class TCP_HEADER   //����TCP�ײ�   
        {
            public ushort sourcePort;   //16λԴ�˿�
            public ushort destPort;   //16λĿ�Ķ˿�
            public int tcp_seq;   //32λ���к�
            public int tcp_ack;   //32λȷ�Ϻ�
            public byte tcp_lenres;   //4λ�ײ�����/6λ������
            public byte tcp_flags;  //��־λ
            //public byte tcp_flag_URG;   //6λ��־λ
            //public byte tcp_flag_ACK;
            //public byte tcp_flag_PSH;
            //public byte tcp_flag_RST;
            //public byte tcp_flag_SYN;
            //public byte tcp_flag_FIN;
            public ushort tcp_win;   //16λ���ڴ�С
            public ushort tcp_checksum;   //16λУ���
            public ushort tcp_urp;   //16λ��������ƫ����
        }

        public class psd_header//����TCPα�ײ�   
        {
            public int saddr;   //Դ��ַ
            public int daddr;   //Ŀ�ĵ�ַ
            public byte mbz;
            public byte ptcl;   //Э������
            public ushort tcpl;   //TCP����
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
    }
}
