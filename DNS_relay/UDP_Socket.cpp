#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "main.h"

#pragma comment(lib, "ws2_32.lib")
using namespace std;

extern char* Upper_DNS;
const char* Local_Host = "127.0.0.1";
vector<struct Waiting>Buffer;//缓冲容器
extern int debug_level;
unsigned short ID = 1;

void DNSServer()
{
	//windows socket
	WORD socketVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	if (WSAStartup(socketVersion, &wsaData) != 0)//启动Windows Sockets线程
	{
		return ;
	}

	//创建套接字
	SOCKET sServer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sServer == INVALID_SOCKET)
	{
		cout << "socket error!" << endl;
		return ;
	}

	//设置中继DNS的IP和端口
	SOCKADDR_IN local;
	local.sin_family = AF_INET;
	local.sin_port = htons(PORT);
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	//serAddr.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);

	//设置原DNS的IP和端口
	SOCKADDR_IN UP_DNS;
	UP_DNS.sin_family = AF_INET;
	UP_DNS.sin_port = htons(PORT);
	UP_DNS.sin_addr.s_addr = inet_addr(Upper_DNS);

	//将socket绑定在local地址
	if (bind(sServer, (struct sockaddr*) & local, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
	{
		cout << "bind error!" << endl;
	}

	//用来存储客户端地址
	SOCKADDR_IN client;
	int len = sizeof(SOCKADDR_IN);

	while (true)
	{
		char recvData[MSGSIZE] = { '\0' };
		//接收数据报
		//接收到的数据报长度是有用的，在发送时需要
		int LEN = recvfrom(sServer, recvData, sizeof(recvData), 0, (sockaddr*)& client, &len);

		if (LEN == -1)
			continue;

		if (debug_level == 2)
		{
			cout << "\n----------------------------------------------------------------------" << endl;
			cout << "*接收到:" << inet_ntoa(client.sin_addr) << ":" << ntohs(client.sin_port) << "的消息" << endl;
		}

		cout << endl;

		if (debug_level == 1)
		{
			
		}
		else if (debug_level == 2)
		{
			DNSheader header;
			if (Get_Header(header, recvData) == true)
			{
				char _QR = 0x80, _AA = 0x04, _TC = 0x02, _RD = 0x01, _RA = 0x80;
				int QR, OPCODE, AA, TC, RD, RA, ZZ, RCODE;
				if (recvData[2] & _QR) QR = 1; else QR = 0;			// QR
				if (recvData[2] & _AA) AA = 1; else AA = 0;			// AA
				if (recvData[2] & _TC) TC = 1; else TC = 0;			// TC
				if (recvData[2] & _RD) RD = 1; else RD = 0;			// RD
				if (recvData[3] & _RA) RA = 1; else RA = 0;			// RA
				// RCODE
				if ((recvData[3] & (char)0x0f) == (char)0x03) RCODE = 3;
				else if ((recvData[3] & (char)0x0f) == (char)0x00) RCODE = 0;
				else RCODE = -1;
				// ZZ
				if ((recvData[3] & (char)0x70) == (char)0x00) ZZ = 0;
				else ZZ = -1;
				// OPCODE
				if ((recvData[2] & (char)0x78) == (char)0x00) OPCODE = 0;
				else if ((recvData[2] & (char)0x78) == (char)0x08) OPCODE = 1;
				else if ((recvData[2] & (char)0x78) == (char)0x10) OPCODE = 2;
				else OPCODE = -1;

				cout << endl;
				//cout << "----------------------------------------------------------------------" << endl;
				// 打印报文
				if (QR == 0) cout << "查询报文 ";
				if (QR == 1) cout << "响应报文 ";
				cout << "DNS: " << endl;
				for (int i = 0; i < LEN; i++)
				{
					printf("%02x ", (unsigned  char)recvData[i]);
					if ((i + 1) % 8 == 0)
						printf("\n");
				}
				// 打印参数
				cout << endl;
				cout << "*ID: " << header.ID << endl;
				cout << "*QR: " << QR << "  *OPCODE: " << OPCODE << "  *AA: " << AA << "  *TC: " << TC << "  *RD: " << RD << "  *RA: " << RA << "  *Z: " << ZZ << "  *RCODE: " << RCODE << endl;
				cout << "*QDCOUNT: " << header.QDCOUNT << "  *ANCOUNT: " << header.ANCOUNT << "  *NSCOUNT: " << header.NSCOUNT << "  *ARCOUNT: " << header.ARCOUNT << endl;
				//cout << "----------------------------------------------------------------------" << endl;
			}
			

		}

		//读取header字段
		DNSheader header;
		char DomainName[100] = { '\0' };

		//分析数据报的来源
		if (client.sin_addr.s_addr == UP_DNS.sin_addr.s_addr)//上层DNS服务器的信息
		{
			//debug
			if (debug_level == 2)
				cout << "*Packet from Upper DNS!" << endl;
			//取header
			if (Get_Header(header, recvData) == false)//将recvData接收信息中的head字段拷贝到header中
				continue;

			unsigned short temp = header.ID;//header.ID已经经过转换，为小端法，且假ID
											//tempID是小端法，假ID

			//在缓冲队列中，利用ID寻找用户，
			for (auto it = Buffer.begin(); it != Buffer.end(); it++)
				if ((*it).tempID == temp)
				{
					if (debug_level == 2) 
					{
						cout << "*发送给:" << inet_ntoa((*it).clientaddr.sin_addr) << ":" << ntohs((*it).clientaddr.sin_port) << endl;
						cout << "\n----------------------------------------------------------------------" << endl;
					}
					
					unsigned short BigID = htons((*it).ID);
					//需要将用户的小端法真ID转换为大端法，发送给客户端
					//即将网络字节顺序转变成主机字节顺序
					memcpy(recvData, &BigID, sizeof(unsigned short));

					sendto(sServer, recvData, LEN, 0, (sockaddr*)&((*it).clientaddr), len);
					//将recvData的信息，修改头部的ID信息后转发给对应的clientaddr
					Buffer.erase(it);
					//从缓存中擦去该待接收的信息

					break;
				}
		}
		else
		//从客户端收到数据
		{
			if (debug_level == 2)
				cout << "*Packet from client!" << endl;

			//取header
			if (Get_Header(header, recvData) == false)
				continue;

			//取问题字段
			QUERY_KIND query_kind = Get_Query(DomainName, recvData);//query_kind为IPV4/IPV6

			if (debug_level == 2)
			{
				if (query_kind == 0)
					cout << "*QUERY_KIND:  IPV4" << endl;
				else
					cout << "*QUERY_KIND:  NIPV4" << endl;
			}

			//问题类型
			if (query_kind == Ipv4)
				//查找IPV4的IP
			{
				if (debug_level == 2)
					cout << "*IPV4" << endl;

				char IPaddr[20] = { '\0' };
				//查表
				SEARCH_RESULT result = Search(DomainName, IPaddr);//返回结果为FIND,NFIND,BLOCK
				//如果IP地址为0.0.0.0，则result=BLOCK;

				if (result == Find)
					//找到，应发送IP
				{
					if (debug_level == 2)
						cout << "*IPV4 & Find!!!!!!!!!!" << endl;
					int index, index0 = 12;
					string recv, send;
					string	Header, Query, Answer;
					// 响应报Header
					for (int i = 0; i < LEN; i++)
						recv.push_back(recvData[i]);//把收到的报文复制到recv中
					Header = recv.substr(0, 12);//Header长度为12字节
					Header[2] = (char)0x85; 
					Header[3] = (char)0x80; 
					Header[7] = (char)0x01;
					//index = recv.find_last_of((char)0x01);	// 查找recvData中Query部分结尾的index
					//Query = recv.substr(index0, index - 11); 	// 响应报Query
					//Answer = recv.substr(index0, index - 11);
					index = recv.find_first_of((char)0x00, 12);//?
					Query = recv.substr(12, index - 7);
					Answer = recv.substr(12, index - 7);
					string TTL_L = {0x00,0x00,0x00,0x78,0x00,0x04};
					//表示资源记录可以缓存的时间
					send = Header + Query + Answer + TTL_L + get_ip(IPaddr);
					//char sendData[1024];
					char* sendData = const_cast<char*>(send.c_str());//把string类型的send转化为char类型的sendData

					if (debug_level == 2)
					{
						cout << "*发送给:" << inet_ntoa(client.sin_addr) << ":" << ntohs(client.sin_port) << endl;
						cout << "\n----------------------------------------------------------------------" << endl;
					}
					
					sendto(sServer, sendData, send.size(), 0, (sockaddr*)& client, len);
					//回复客户端

					//cout << "----------------------------------------------------------------------" << endl;
					//// 打印报文
					//
					//cout << "DNS: " << endl;
					//for (int i = 0; i < send.size(); i++)
					//{
					//	printf("%02x ", (unsigned  char)send[i]);
					//	if ((i + 1) % 8 == 0)
					//		printf("\n");
					//}
					//
					//cout << "----------------------------------------------------------------------" << endl;

					continue;
				}
				else if (result == Block)
					//应屏蔽
				{
					if (debug_level == 2)
						cout << "*IPV4 & Block!!!!!!!!!" << endl;

					// Flag位应该设置为8583
					recvData[2] = (char)0x85;
					//OR=1,AA=1,TC=0,RD=1
					recvData[3] = (char)0x83;
					//重点是rcode=3->解析出的域名不存在

					if (debug_level == 2)
					{
						cout << "*发送给:" << inet_ntoa(client.sin_addr) << ":" << ntohs(client.sin_port) << endl;
						cout << "\n----------------------------------------------------------------------" << endl;
					}
					
					sendto(sServer, recvData, LEN, 0, (sockaddr*)& client, len);
					continue;
					//发送完毕，进入下一个循环
				}
				else if (debug_level == 2)
						cout << "*IPV4 & NFind!!!!!!!!!" << endl;
			}
			
			unsigned short temp = htons(ID);//ID为小端法，temp大端法
			//设置即将发送给远程DNS的数据报的ID值
			memcpy(recvData, &temp, sizeof(unsigned short));

			//查找类型非IPV4或在对照表中未找到，应发给原DNS中继
			Waiting user;
			user.clientaddr = client;
			user.ID = header.ID;//user的真ID，小端法
			user.tempID = ID;//user的假ID，小端法
			Buffer.push_back(user);//数据来源于本地。由客户程序设置并由服务器返回结果，
			//，客户程序通过它来确定相应与查询是否匹配。
			
			ID = (ID + 1) % 2333;
			
			if (debug_level == 2)
			{
				cout << "*发送给:" << inet_ntoa(UP_DNS.sin_addr) << ":" << ntohs(UP_DNS.sin_port) << endl;
				cout << "\n----------------------------------------------------------------------" << endl;
			}

			//将原数据包直接发送给原DNS
			sendto(sServer, recvData, LEN, 0, (sockaddr*)& UP_DNS, len);
		}
	}

	closesocket(sServer);
	WSACleanup();//关闭Windows Sockets线程
	return ;
}