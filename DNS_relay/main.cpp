#include "main.h"
#include "Get_H.cpp"
#include "UDP_Socket.cpp"
using namespace std;

char a[] = "192.168.1.1";	//Ĭ��IP
char* Upper_DNS = a;	//�ϲ�DNS IP��ַ
string List_Name = "dnsrelay.txt";		//Ĭ���б���


int debug_level;	//������Ϣ����ȼ�
vector <LocalRecord> LocalList;//�����洢LocalRecord

//�ж�debug����
void initProgram(int count, char* value[]) {
	//�жϲ�������
	switch (count)
	{
		//�޲���
	case 1:
		debug_level = 0;
		break;
		//��ָ�����Եȼ����ϲ�DNS
	case 2:
		if (strcmp(value[1], "-d") == 0)
			debug_level = 1;
		else
			if (strcmp(value[1], "-dd") == 0)
				debug_level = 2;
			else {
				debug_level = 0;
				Upper_DNS = value[1];
			}
		break;
		//ָ�����Եȼ����ϲ�DNS �� Ĭ�ϵ��Եȼ�Ϊ0��ָ���ϲ�DNS���ļ�
	case 3:
		if (strcmp(value[1], "-d") == 0) {
			debug_level = 1;
			Upper_DNS = value[2];
		}
		else
			if (strcmp(value[1], "-dd") == 0) {
				debug_level = 2;
				Upper_DNS = value[2];
			}
			else {
				debug_level = 0;
				Upper_DNS = value[1];
				List_Name = value[2];
			}
		break;
		//��������
	case 4:
		if (strcmp(value[1], "-d") == 0) {
			debug_level = 1;
			Upper_DNS = value[2];
			List_Name = value[3];
		}
		else
			if (strcmp(value[1], "-dd") == 0) {
				debug_level = 2;
				Upper_DNS = value[2];
				List_Name = value[3];
			}
			else
				debug_level = -1;
		break;
	default:
		debug_level = -1;
		break;
	}
}

//��ӡ�����б�
void printList() {
	for (unsigned int i = 0; i < LocalList.size(); i++) {
		cout << "\t" << i << ":" << LocalList[i].IP_Addr << "\t" << LocalList[i].Domain_Name << endl;
	}
}

//��ȡ�����б���ӡ�����Ϣ
void readList() {
	cout << "Try to load table \"" << List_Name << "\" ... ";
	LocalRecord temp;
	ifstream inList(List_Name, ifstream::in);

	//�ж϶�ȡ�Ƿ�ɹ�
	if (inList.good())
		cout << "OK!" << endl;
	else
		cout << "Ignored!" << endl;
	
	//��ȡ�ļ�������������
	for (int i = 0; inList >> temp.IP_Addr; i++) {
		inList >> temp.Domain_Name;//inList�ļ������뵽temp.Doamin_Name
		LocalList.push_back(temp);//��������
	}
	inList.close();

	//��ӡ�б�
	if (debug_level == 2)
		printList();
	cout << LocalList.size() << " names" << endl;
}

//��ӡ��ʼ��Ϣ
void printMsg() {
	cout << "DNSRELAY, Version 1.0beta, Build: May 31 2019, By 223" << endl;
	cout << "Usage: dnsrelay[-d | -dd][<dns - server>][<db - file>]" << endl;
	cout << "Name Server " << Upper_DNS << endl;//
	cout << "\tDebug Level " << debug_level << endl;  
	cout << "\tBind UDP port " << PORT << " ...OK!" << endl;  //�˿�
}

//�ڱ����б��а���������
SEARCH_RESULT Search(const char* name, char* IP) {
	SEARCH_RESULT result = NFind;
	string NAME = name;
	for (unsigned int i = 0; i < LocalList.size(); i++) {
		if (NAME == LocalList[i].Domain_Name)
			if (LocalList[i].IP_Addr == "0.0.0.0")
				result = Block;
			else {
				result = Find;
				strcpy(IP, LocalList[i].IP_Addr.c_str());
			}
	}
	return result;
}



//�����ú���
void testSearch() {
	char ininin[100] = { '\0' };
	char IPaddr[20] = { '\0' };
	while (true) {
		cin >> ininin;
		SEARCH_RESULT res = Search(ininin, IPaddr);

		if (res == Find)
			cout << IPaddr << endl;
		if (res == NFind)
			cout << "Upper" << endl;
		if (res == Block)
			cout << "Block" << endl;
		cout << endl;
		//system("pause");
	}
}



int main(int argc, char* argv[]) {

	initProgram(argc, argv);//�Է�������ַ�ȵȲ������г�ʼ��
	printMsg();//��ӡ�����Ϣ
	readList();//����dnsrelay.txt�Ļ�����Ϣ
	
//	printList();
//	testSearch();

	DNSServer();

	return 0;
}