using System;
using System.Collections.Generic;
using System.Text;

namespace MyScanner.MyClasses
{
    class DataStructures
    {
        /// <summary>
        /// IPV4数据报头
        /// </summary>
        public class IP_HEADER
        {
            public byte ver_hlen;   //4位IP版本号+4位首部长度
            public byte TOS;   //8位服务类型
            public ushort totalLen;   //数据报16位总长度
            public ushort ident;   //16位标识
            public ushort frag_and_flags;   //3位标志位+13位分段偏移
            public byte ttl;   //8位生存时间   TTL
            public byte proto;   //8位上层协议(TCP,UDP等)
            public ushort checksum;   //16位IP首部校验和
            public int sourceIP;   //32位源IP地址
            public int destIP;   //32位目的IP地址
        }

        /// <summary>
        /// TCP数据报头
        /// </summary>
        public class TCP_HEADER   //定义TCP首部   
        {
            public ushort sourcePort;   //16位源端口
            public ushort destPort;   //16位目的端口
            public int tcp_seq;   //32位序列号
            public int tcp_ack;   //32位确认号
            public byte tcp_lenres;   //4位首部长度/6位保留字
            public byte tcp_flags;  //标志位
            //public byte tcp_flag_URG;   //6位标志位
            //public byte tcp_flag_ACK;
            //public byte tcp_flag_PSH;
            //public byte tcp_flag_RST;
            //public byte tcp_flag_SYN;
            //public byte tcp_flag_FIN;
            public ushort tcp_win;   //16位窗口大小
            public ushort tcp_checksum;   //16位校验和
            public ushort tcp_urp;   //16位紧急数据偏移量
        }

        public class psd_header//定义TCP伪首部   
        {
            public int saddr;   //源地址
            public int daddr;   //目的地址
            public byte mbz;
            public byte ptcl;   //协议类型
            public ushort tcpl;   //TCP长度
        }

        public struct ipHeader
        {
            public byte ip_verlen; //4位首部长度+4位IP版本号  
            public byte ip_tos; //8位服务类型TOS  
            public ushort ip_totallength; //16位数据包总长度（字节）  
            public ushort ip_id; //16位标识  
            public ushort ip_offset; //3位标志位  
            public byte ip_ttl; //8位生存时间 TTL  
            public byte ip_protocol; //8位协议(TCP, UDP, ICMP, Etc.)  
            public ushort ip_checksum; //16位IP首部校验和  
            public uint ip_srcaddr; //32位源IP地址  
            public uint ip_destaddr; //32位目的IP地址  
        }
        public struct psdHeader
        {
            public uint saddr;   //源地址  
            public uint daddr;   //目的地址  
            public byte mbz;
            public byte ptcl;      //协议类型  
            public ushort tcpl;   //TCP长度  
        }
        public struct tcpHeader
        {
            public ushort th_sport;     //16位源端口  
            public ushort th_dport;     //16位目的端口  
            public int th_seq;    //32位序列号  
            public uint th_ack;    //32位确认号  
            public byte th_lenres;   //4位首部长度/6位保留字  
            public byte th_flag;    //6位标志位  
            public ushort th_win;      //16位窗口大小  
            public ushort th_sum;      //16位校验和  
            public ushort th_urp;      //16位紧急数据偏移量  
        }
    }
}
