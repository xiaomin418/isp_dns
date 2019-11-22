#define _CRT_SECURE_NO_WARNINGS

#pragma once
#include <WinSock2.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <cstring>
#include <fstream>
#include <iomanip>
using namespace std;

#define PORT 53							//�˿ں�
#define MSGSIZE 1024					//������ݳ���

using namespace std;

//��ѯ����	QTYPE
enum QUERY_KIND{Ipv4, NIpv4};
//����DNSrelay.txt�Ĳ��ҽ��
enum SEARCH_RESULT{Find, NFind, Block};

//DNS���ĵ�header
typedef struct DNSheader
{
	unsigned short ID;				//ID�ֶ�
	unsigned short CtrlCode;		//��16λ�����ֶ�
	unsigned short QDCOUNT;			//Number of entries in the question section
	unsigned short ANCOUNT;			//Number of RRs in the answer section
	unsigned short NSCOUNT;			//Number of name server RRs in authority records section
	unsigned short ARCOUNT;			//Number of RRs in additional records section
}DNSheader, *PtrDNSH;


typedef struct Waiting
{
	struct sockaddr_in clientaddr;
	unsigned short ID;
	unsigned short tempID;
	//char query[100];
}Waiting;

//bool MyDEBUG = true;

//������src�е�header�ֶο�����dest�У����غ����Ƿ�ִ�гɹ�
bool Get_Header(DNSheader& header, const char* src);
//������src�е�query�ֶ��еĲ�ѯ����������dest�У�ͬʱ����QTYPE
QUERY_KIND Get_Query(char* dest, char* src);
//�ڱ��в�������name�� ���ҵ���IP��ַ����IP�����ز��ҽ��
SEARCH_RESULT Search(const char* name, char* IP);
string get_ip(const char* IPaddr);
void DNSServer();

//����DNS��ַ+���������ṹ��
typedef struct localrecord
{
	string IP_Addr;
	string Domain_Name;
}LocalRecord;


