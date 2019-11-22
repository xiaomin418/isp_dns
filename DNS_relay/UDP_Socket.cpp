#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "main.h"

#pragma comment(lib, "ws2_32.lib")
using namespace std;

extern char* Upper_DNS;
const char* Local_Host = "127.0.0.1";
vector<struct Waiting>Buffer;//��������
extern int debug_level;
unsigned short ID = 1;

void DNSServer()
{
	//windows socket
	WORD socketVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	if (WSAStartup(socketVersion, &wsaData) != 0)//����Windows Sockets�߳�
	{
		return ;
	}

	//�����׽���
	SOCKET sServer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sServer == INVALID_SOCKET)
	{
		cout << "socket error!" << endl;
		return ;
	}

	//�����м�DNS��IP�Ͷ˿�
	SOCKADDR_IN local;
	local.sin_family = AF_INET;
	local.sin_port = htons(PORT);
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	//serAddr.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);

	//����ԭDNS��IP�Ͷ˿�
	SOCKADDR_IN UP_DNS;
	UP_DNS.sin_family = AF_INET;
	UP_DNS.sin_port = htons(PORT);
	UP_DNS.sin_addr.s_addr = inet_addr(Upper_DNS);

	//��socket����local��ַ
	if (bind(sServer, (struct sockaddr*) & local, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
	{
		cout << "bind error!" << endl;
	}

	//�����洢�ͻ��˵�ַ
	SOCKADDR_IN client;
	int len = sizeof(SOCKADDR_IN);

	while (true)
	{
		char recvData[MSGSIZE] = { '\0' };
		//�������ݱ�
		//���յ������ݱ����������õģ��ڷ���ʱ��Ҫ
		int LEN = recvfrom(sServer, recvData, sizeof(recvData), 0, (sockaddr*)& client, &len);

		if (LEN == -1)
			continue;

		if (debug_level == 2)
		{
			cout << "\n----------------------------------------------------------------------" << endl;
			cout << "*���յ�:" << inet_ntoa(client.sin_addr) << ":" << ntohs(client.sin_port) << "����Ϣ" << endl;
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
				// ��ӡ����
				if (QR == 0) cout << "��ѯ���� ";
				if (QR == 1) cout << "��Ӧ���� ";
				cout << "DNS: " << endl;
				for (int i = 0; i < LEN; i++)
				{
					printf("%02x ", (unsigned  char)recvData[i]);
					if ((i + 1) % 8 == 0)
						printf("\n");
				}
				// ��ӡ����
				cout << endl;
				cout << "*ID: " << header.ID << endl;
				cout << "*QR: " << QR << "  *OPCODE: " << OPCODE << "  *AA: " << AA << "  *TC: " << TC << "  *RD: " << RD << "  *RA: " << RA << "  *Z: " << ZZ << "  *RCODE: " << RCODE << endl;
				cout << "*QDCOUNT: " << header.QDCOUNT << "  *ANCOUNT: " << header.ANCOUNT << "  *NSCOUNT: " << header.NSCOUNT << "  *ARCOUNT: " << header.ARCOUNT << endl;
				//cout << "----------------------------------------------------------------------" << endl;
			}
			

		}

		//��ȡheader�ֶ�
		DNSheader header;
		char DomainName[100] = { '\0' };

		//�������ݱ�����Դ
		if (client.sin_addr.s_addr == UP_DNS.sin_addr.s_addr)//�ϲ�DNS����������Ϣ
		{
			//debug
			if (debug_level == 2)
				cout << "*Packet from Upper DNS!" << endl;
			//ȡheader
			if (Get_Header(header, recvData) == false)//��recvData������Ϣ�е�head�ֶο�����header��
				continue;

			unsigned short temp = header.ID;//header.ID�Ѿ�����ת����ΪС�˷����Ҽ�ID
											//tempID��С�˷�����ID

			//�ڻ�������У�����IDѰ���û���
			for (auto it = Buffer.begin(); it != Buffer.end(); it++)
				if ((*it).tempID == temp)
				{
					if (debug_level == 2) 
					{
						cout << "*���͸�:" << inet_ntoa((*it).clientaddr.sin_addr) << ":" << ntohs((*it).clientaddr.sin_port) << endl;
						cout << "\n----------------------------------------------------------------------" << endl;
					}
					
					unsigned short BigID = htons((*it).ID);
					//��Ҫ���û���С�˷���IDת��Ϊ��˷������͸��ͻ���
					//���������ֽ�˳��ת��������ֽ�˳��
					memcpy(recvData, &BigID, sizeof(unsigned short));

					sendto(sServer, recvData, LEN, 0, (sockaddr*)&((*it).clientaddr), len);
					//��recvData����Ϣ���޸�ͷ����ID��Ϣ��ת������Ӧ��clientaddr
					Buffer.erase(it);
					//�ӻ����в�ȥ�ô����յ���Ϣ

					break;
				}
		}
		else
		//�ӿͻ����յ�����
		{
			if (debug_level == 2)
				cout << "*Packet from client!" << endl;

			//ȡheader
			if (Get_Header(header, recvData) == false)
				continue;

			//ȡ�����ֶ�
			QUERY_KIND query_kind = Get_Query(DomainName, recvData);//query_kindΪIPV4/IPV6

			if (debug_level == 2)
			{
				if (query_kind == 0)
					cout << "*QUERY_KIND:  IPV4" << endl;
				else
					cout << "*QUERY_KIND:  NIPV4" << endl;
			}

			//��������
			if (query_kind == Ipv4)
				//����IPV4��IP
			{
				if (debug_level == 2)
					cout << "*IPV4" << endl;

				char IPaddr[20] = { '\0' };
				//���
				SEARCH_RESULT result = Search(DomainName, IPaddr);//���ؽ��ΪFIND,NFIND,BLOCK
				//���IP��ַΪ0.0.0.0����result=BLOCK;

				if (result == Find)
					//�ҵ���Ӧ����IP
				{
					if (debug_level == 2)
						cout << "*IPV4 & Find!!!!!!!!!!" << endl;
					int index, index0 = 12;
					string recv, send;
					string	Header, Query, Answer;
					// ��Ӧ��Header
					for (int i = 0; i < LEN; i++)
						recv.push_back(recvData[i]);//���յ��ı��ĸ��Ƶ�recv��
					Header = recv.substr(0, 12);//Header����Ϊ12�ֽ�
					Header[2] = (char)0x85; 
					Header[3] = (char)0x80; 
					Header[7] = (char)0x01;
					//index = recv.find_last_of((char)0x01);	// ����recvData��Query���ֽ�β��index
					//Query = recv.substr(index0, index - 11); 	// ��Ӧ��Query
					//Answer = recv.substr(index0, index - 11);
					index = recv.find_first_of((char)0x00, 12);//?
					Query = recv.substr(12, index - 7);
					Answer = recv.substr(12, index - 7);
					string TTL_L = {0x00,0x00,0x00,0x78,0x00,0x04};
					//��ʾ��Դ��¼���Ի����ʱ��
					send = Header + Query + Answer + TTL_L + get_ip(IPaddr);
					//char sendData[1024];
					char* sendData = const_cast<char*>(send.c_str());//��string���͵�sendת��Ϊchar���͵�sendData

					if (debug_level == 2)
					{
						cout << "*���͸�:" << inet_ntoa(client.sin_addr) << ":" << ntohs(client.sin_port) << endl;
						cout << "\n----------------------------------------------------------------------" << endl;
					}
					
					sendto(sServer, sendData, send.size(), 0, (sockaddr*)& client, len);
					//�ظ��ͻ���

					//cout << "----------------------------------------------------------------------" << endl;
					//// ��ӡ����
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
					//Ӧ����
				{
					if (debug_level == 2)
						cout << "*IPV4 & Block!!!!!!!!!" << endl;

					// FlagλӦ������Ϊ8583
					recvData[2] = (char)0x85;
					//OR=1,AA=1,TC=0,RD=1
					recvData[3] = (char)0x83;
					//�ص���rcode=3->������������������

					if (debug_level == 2)
					{
						cout << "*���͸�:" << inet_ntoa(client.sin_addr) << ":" << ntohs(client.sin_port) << endl;
						cout << "\n----------------------------------------------------------------------" << endl;
					}
					
					sendto(sServer, recvData, LEN, 0, (sockaddr*)& client, len);
					continue;
					//������ϣ�������һ��ѭ��
				}
				else if (debug_level == 2)
						cout << "*IPV4 & NFind!!!!!!!!!" << endl;
			}
			
			unsigned short temp = htons(ID);//IDΪС�˷���temp��˷�
			//���ü������͸�Զ��DNS�����ݱ���IDֵ
			memcpy(recvData, &temp, sizeof(unsigned short));

			//�������ͷ�IPV4���ڶ��ձ���δ�ҵ���Ӧ����ԭDNS�м�
			Waiting user;
			user.clientaddr = client;
			user.ID = header.ID;//user����ID��С�˷�
			user.tempID = ID;//user�ļ�ID��С�˷�
			Buffer.push_back(user);//������Դ�ڱ��ء��ɿͻ��������ò��ɷ��������ؽ����
			//���ͻ�����ͨ������ȷ����Ӧ���ѯ�Ƿ�ƥ�䡣
			
			ID = (ID + 1) % 2333;
			
			if (debug_level == 2)
			{
				cout << "*���͸�:" << inet_ntoa(UP_DNS.sin_addr) << ":" << ntohs(UP_DNS.sin_port) << endl;
				cout << "\n----------------------------------------------------------------------" << endl;
			}

			//��ԭ���ݰ�ֱ�ӷ��͸�ԭDNS
			sendto(sServer, recvData, LEN, 0, (sockaddr*)& UP_DNS, len);
		}
	}

	closesocket(sServer);
	WSACleanup();//�ر�Windows Sockets�߳�
	return ;
}