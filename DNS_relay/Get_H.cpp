#include"main.h"
//������5������ɣ�
//Header,question,answer, authority, additional
bool Get_Header(DNSheader& header, const char* src)//��ȡheaders
{
	// src�е�header���ֹ����������֣���12���ֽ�: 
	unsigned short tmp;			
	char* ptr = (char*)&tmp;	// �Ƚ�����ת����unsigned short������ntohs����ת��Ϊ���صĸ�ʽ(��˷�->С�˷�)
	// 1��ID: src[0]-src[1]: 2bytes
	*ptr = src[0];
	*(ptr + 1) = src[1];
	header.ID = ntohs(tmp);
	// 2) CtrlCode: src[2]-src[3]: 2bytes
	*ptr = src[2];
	*(ptr + 1) = src[3];
	header.CtrlCode = ntohs(tmp);
	// 3) Questions: src[4]-src[5]: 2bytes
	*ptr = src[4];
	*(ptr + 1) = src[5];
	header.QDCOUNT = ntohs(tmp);
	// 4) Answer RRs: src[6]-src[7]: 2bytes
	*ptr = src[6];
	*(ptr + 1) = src[7];
	header.ANCOUNT = ntohs(tmp);
	// 5) Authority RRs: src[8]-src[9]: 2bytes
	*ptr = src[8];
	*(ptr + 1) = src[9];
	header.NSCOUNT = ntohs(tmp);
	// 6) Additional RRs: src[10]-src[11]: 2bytes
	*ptr = src[10];
	*(ptr + 1) = src[11];
	header.ARCOUNT = ntohs(tmp);

	return true;
}


//������src�е�query�ֶ��еĲ�ѯ����������dest�У�ͬʱ����QTYPE
QUERY_KIND Get_Query(char* dest, char* src)//��ȡquestion�е�������ͬʱ����QTYPE
{
	char* query = src + 12;
	while (*query != '\0')
	{
		unsigned char number = *query;
		query++;
		for (unsigned char i = (char)0x00; i < number; i++)
		{
			*dest = *query;
			dest++;
			query++;
		}
		*dest = '.';
		dest++;
	}
	dest--;
	*dest = '\0';
	query++;

	unsigned short temp;
	char* ptr = (char*)&temp;
	*ptr = *query;
	*(ptr + 1) = *(query + 1);

	unsigned short query_kind = ntohs(temp);
	if (query_kind == 1)
		return Ipv4;
	else
		return NIpv4;  
}

string get_ip(const char* IPaddr)
{
	unsigned char tmp = 0;
	char num[5];
	string result;
	int i = 0, j = 0;
	while (IPaddr[i] != '\0')
	{
		if (IPaddr[i] != '.')
		{
			tmp = tmp * 10 + IPaddr[i] - '0';
		}
		else
		{
			num[j] = tmp;
			result.push_back(num[j]);
			tmp = 0;
			j++;
		}
		i++;
	}
	num[3] = tmp;
	result.push_back(num[3]);
	//num[4] = '\0';
	//cout << num << endl;
	return result;
}


//string get_ip(string IPaddr)
//{
//	int index1, index2, index3;
//	string field, ip;
//	index1 = IPaddr.find_first_of(".", 0);
//	//cout << index1 << endl;
//	index2 = IPaddr.find_first_of(".", index1 + 1);
//	//cout << index2 << endl;
//	index3 = IPaddr.find_first_of(".", index2 + 1);
//	//cout << index3 << endl;
//	field = dec2hex(stoi(IPaddr.substr(0, index1)));
//	ip += field;
//	field = dec2hex(stoi(IPaddr.substr(index1 + 1, index2 - index1 - 1)));
//	ip += field;
//	field = dec2hex(stoi(IPaddr.substr(index2 + 1, index3 - index2 - 1)));
//	ip += field;
//	field = dec2hex(stoi(IPaddr.substr(index3 + 1, IPaddr.size() - index3 - 1)));
//	ip += field;
//	return ip;
//}
//
//string dec2hex(int i) //��intת��16�����ַ���
//{
//	stringstream ioss; //�����ַ�����
//	string s_temp; //���ת�����ַ�
//	ioss << setiosflags(ios::uppercase) << hex << i; //��ʮ����(��д)��ʽ���
//	ioss >> s_temp;
//	return s_temp;
//}