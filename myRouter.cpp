#include "pcap.h"
#include <stdio.h>
#include <WinSock.h>
#include <time.h>
#include <Cstring>
#include <iostream>
#include <map>
#include <windows.h>
#include <string>
#include <direct.h>
using namespace std;
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")

#define ETH_ARP 0x0806
#define ETH_IP  0x0800
#define ARP_HARDWARE 1
#define ARP_REQUEST 1
#define ARP_RESPONSE 2
#define MAX_WAIT 20
//IP���ݱ�
#pragma pack(1)
typedef struct EthernetHeader
{
	u_char DestMAC[6];
	u_char SourMAC[6];
	u_short EthType;
}EthernetHeader;
typedef struct IPHeader {
	BYTE Ver_Hlen;//��4λΪ�汾������λΪ�ײ�����
	BYTE TOS;//��������
	WORD Totalen;//�ܳ���
	WORD ID;//��ʶ
	WORD Flag_Segment;//��־��Ƭƫ��
	BYTE TTL;//����ʱ��
	BYTE Proctocol;//�ϲ�Э��
	WORD Checksum;//�ײ�У���
	ULONG SrcIP;//Դip
	ULONG DstIP;//Ŀ��ip
}IPHeader;
typedef struct IPPacket {
	EthernetHeader *EHeader;
	IPHeader *IHeader;
}IPPacket;
//icmp
typedef struct icmp{
	u_char type;
	u_char code;
	WORD checksum;
	WORD id;
	WORD seq;
	char data[64];
}icmp;
typedef struct pData{
	EthernetHeader eh;
	IPHeader ih;
	icmp ic;
}pData;
//ARP
typedef struct ArpHeader
{
	unsigned short hdType;
	unsigned short proType;
	unsigned char hdSize;
	unsigned char proSize;
	unsigned short op;
	u_char smac[6];
	ULONG sip;
	u_char dmac[6];
	ULONG dip;
}ArpHeader;
typedef struct ArpPacket {
	EthernetHeader ed;
	ArpHeader ah;
}ArpPacket;
//�ȴ�
typedef struct wait
{
	const struct pcap_pkthdr* head;
	pData* data;
	wait* next;
}wait;
#pragma pack()
pcap_t* adh;
//·�ɱ���
typedef struct route_item
{
	ULONG dstIP;//Ŀ��ip
	ULONG dstMK;//Ŀ������
	ULONG nextR;//��һ����ַ
	int prot;//�Ƿ񱻱������������������ɾ��
	route_item* next;
}route_item;
//·�ɱ�
route_item* route_table;
route_item* head;
route_item* tail;
//IP-MAC��
map<ULONG,u_char*>IP_MAC;
map<ULONG,u_char*>::iterator finder;
//�ȴ�ת����
wait* waiting = new wait;
wait* whead = waiting;
wait* wtail = waiting;
int waitlen = 0;

u_char* hostMac = new u_char[6];
int firstnet = 0;

wait* newait(const struct pcap_pkthdr* h,pData* d)
{
	wait* t = new wait;
	t->head = h;
	t->data = d;
	t->next = NULL;
	return t;
}
string GetIpFromULong(unsigned long uIp)
{
	in_addr addr;

	memcpy(&addr, &uIp, sizeof(uIp));

	string strIp = inet_ntoa(addr);

	return strIp;
}
//д������־
char dName[128] = "C:/myrouter/";
char dfName[128] = "C:/myrouter/wlog.txt";
char fName[128] = "wlog.txt";
int worknum = 1;
void log_write(int op, ULONG dip, ULONG sip)
{
	FILE* p = NULL;
	p = fopen(dfName, "ab");
	//����ARP-1,����ARP-2,�������ݰ�-3,ת�����ݰ�-4,�ݴ�-5
	if (op == 1)//����ARP
	{
		fprintf(p, "[%d]: send ARP from %s to %s\r\n", worknum, GetIpFromULong(sip).c_str(), GetIpFromULong(dip).c_str());
		worknum++;
	}
	else if (op == 2)//����ARP
	{
		fprintf(p, "[%d]: recv ARP from %s to %s\r\n", worknum, GetIpFromULong(sip).c_str(), GetIpFromULong(dip).c_str());
		worknum++;
	}
	else if (op == 3)//�������ݰ�
	{
		fprintf(p, "[%d]: recv Packet(to %s) from %s \r\n", worknum, GetIpFromULong(dip).c_str(), GetIpFromULong(sip).c_str());
		worknum++;
	}
	else if (op == 4)//ת�����ݰ�
	{
		fprintf(p, "[%d]: trans Packet(from %s) to %s\r\n", worknum, GetIpFromULong(sip).c_str(), GetIpFromULong(dip).c_str());
		worknum++;
	}
	else if (op == 5)//�ݴ�
	{
		fprintf(p, "[%d]: store Packet(from %s to %s)\r\n", worknum, GetIpFromULong(sip).c_str(), GetIpFromULong(dip).c_str());
		worknum++;
	}
	fclose(p);
}
u_char* getMac(pcap_t* ad, ULONG desip, ULONG srcip, u_char* srcmac)
{
	// ���������
	unsigned char sendbuf[42];
	EthernetHeader eh;
	ArpHeader ah;
	memcpy(eh.SourMAC, srcmac, 6);
	memset(eh.DestMAC, 0xff, 6);
	memcpy(ah.smac, srcmac, 6);
	memset(ah.dmac, 0x00, 6);
	ah.sip = srcip;
	ah.dip = desip;
	eh.EthType = htons(ETH_ARP);
	ah.hdType = htons(ARP_HARDWARE);
	ah.proType = htons(ETH_IP);
	ah.hdSize = 6;
	ah.proSize = 4;
	ah.op = htons(ARP_REQUEST);
	memset(sendbuf, 0, sizeof(sendbuf));   //ARP����
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));

	if (pcap_sendpacket(ad, sendbuf, 42) == 0) {
		;
	}
	
	log_write(1,desip ,srcip);
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	ArpHeader* arph=new ArpHeader;
	ArpPacket* arp =new ArpPacket;
	int count = 0;
	while ((res = pcap_next_ex(ad, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
		{
			continue;
		}
		arph = (ArpHeader*)(pkt_data + 14);
		arp = (ArpPacket*)pkt_data;
		if (arph->sip == desip)
		{
			log_write(2, arph->dip, arph->sip);
			break;
		}

	}
	IP_MAC[desip] = arph->smac;//��ӳ���ϵ��ӵ�����
	return arph->smac;
}
//����У���
WORD add(WORD a, WORD b) {
    WORD sum = ((a + b) & 0xFFFF) + ((a + b) >> 16);
    return sum;
}
WORD check_sum(pData data) {
    WORD sum;
    struct in_addr src;
    memcpy(&src, &data.ih.SrcIP, 4);
    struct in_addr dst;
    memcpy(&dst, &data.ih.DstIP, 4);

    sum = add((data.ih.Ver_Hlen << 8) + data.ih.TOS, ntohs(data.ih.Totalen));
    sum = add(sum, ntohs(data.ih.ID));
    sum = add(sum, ntohs(data.ih.Flag_Segment));
    sum = add(sum, (data.ih.TTL << 8) + data.ih.Proctocol);
    sum = add(sum, ntohs(src.S_un.S_un_w.s_w1));
    sum = add(sum, ntohs(src.S_un.S_un_w.s_w2));
    sum = add(sum, ntohs(dst.S_un.S_un_w.s_w1));
    sum = add(sum, ntohs(dst.S_un.S_un_w.s_w2));
    return ~sum;
}

//���´��
void repack(pData* p,u_char* smac,u_char* dmac)
{

	p->ih.TTL--;
	memset(&(p->ih.Checksum), '\0', sizeof(WORD));
	p->ih.Checksum = htons(check_sum(*p));

	memcpy(p->eh.SourMAC, smac, sizeof(u_char) * 6);
	memcpy(p->eh.DestMAC, dmac, sizeof(u_char) * 6);
}
//�½�·�ɱ���
route_item* newitem(ULONG dstIP, ULONG dstMK, ULONG nextR, int prot)
{
	route_item* temp = new route_item;
	temp->dstIP = dstIP;
	temp->dstMK = dstMK;
	temp->nextR = nextR;
	temp->prot = prot;
	temp->next = NULL;
	return temp;
}
//��ʼ��ֱ��Ͷ��·�ɱ�����ɾ��
void route_init(ULONG hostnet,ULONG mask,ULONG hostip)
{
	//Ĭ��·��
	route_table = newitem(hostnet, mask, hostip, 1);
	head = route_table;
	tail = route_table;
	//����·�ɱ���
}
//��ɾ���·�ɱ�
void route_add(ULONG dstIP, ULONG dstMK, ULONG nextR)
{
	tail->next = newitem(dstIP, dstMK, nextR, 0);
	tail = tail->next;
	printf("������ӳɹ�");
}
void route_delete(ULONG dstIP, ULONG dstMK, ULONG nextR)
{
	route_item* temp = head;
	for (; temp->next != NULL; temp = temp->next)
	{
		route_item* a = temp->next;
		if ((a->dstIP == dstIP) && (a->dstMK == dstMK) && (a->nextR == nextR))
		{
			if (a->prot == 1)
			{
				printf("���Ǹ��������ı���,�޷�ɾ��,����������\n");
				return;
			}
			else
			{
				//ɾ���м����
				if (a->next != NULL)
				{
					route_item* b = a->next;
					temp->next = b;
					printf("����ɾ���ɹ�");
					return;
				}
				//ɾ��ĩβ����
				else
				{
					temp->next = NULL;
					tail = temp;
					printf("����ɾ���ɹ�");
					return;
				}
				//��ʼ���������������
			}
		}
	}
	if ((head->dstIP == dstIP) && (head->dstMK == dstMK) && (head->nextR == nextR))
	{
		printf("���Ǹ��������ı���,�޷�ɾ��,����������\n");
		return;
	}
	printf("�������,�޷�ɾ��,����������\n");
}
void route_show()
{
	printf("\n++++++++++++++++++++\t��ǰ·�ɱ�����\t++++++++++++++++++++\n");
	printf("%-15s\t%-15s\t%-15s\n","Ŀ��IP","Ŀ������","����ӿ�");
	route_item* temp = head;
	for (; temp != NULL; temp = temp->next)
	{
		printf("%-15s\t%-15s\t%-15s\n", GetIpFromULong(temp->dstIP).c_str(), GetIpFromULong(temp->dstMK).c_str(), GetIpFromULong(temp->nextR).c_str());
	}
	printf("++++++++++++++++++++\t���������б���\t++++++++++++++++++++\n");
}
ULONG route_find(ULONG ip)
{
	//�ƥ��
	route_item* temp = head;
	ULONG longest=0;//�������ULONG���
	ULONG ret=inet_addr("255.255.255.255");
	for (; temp != NULL; temp = temp->next)
	{
		ULONG tmk = temp->dstMK;
//		cout << GetIpFromULong(tmk);
		if((ip&tmk)==temp->dstIP)//�������������Ľ������dstIP
		{
			if(tmk>=longest)//����ȵ�ǰ���볤(��)
			{
				ret = temp->nextR;
				longest = tmk;
			}
		}
	}
	return ret;
}
//·��ת��
void route_trans(u_char *param, const struct pcap_pkthdr *header,const u_char *pkt_data)
{
	/*
		���յ������ȼ���У��ͣ�����ɹ��Ժ�ִ�����²���
		1.���ݵ�ǰ����dstip��·�ɱ��ҵ���һ��ip nextR
		2.����nextR��IP_MAC���ҵ���Ӧӳ���ϵ
		3.����鵽ֱ�ӷ�
		4.���û�в鵽��ӦMAC��Ϣ������ARP�����ȡMAC�����ѵ�ǰ���ӵ��ȴ�����
		5.���յ�ARP���󣬱����ȴ�����,���´����
	*/

	time_t local_tv_sec = header->ts.tv_sec;
	struct tm *ltime = localtime(&local_tv_sec);
	char timestr[16];
	pData *Packet = new pData;
	Packet = (pData *)pkt_data;
	//memcpy(Packet, pkt_data, sizeof(pData));
	//unsigned char sendbuf[34];//���ͻ�����

	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	//����У���
	if (!check_sum(*Packet))
	{
		cout << "Checksum is wrong,throw the packet" << endl;
		return;
	}
	
	//����Ǹ�TTL=0��tracert
	//if (Packet->ih.TTL==0)
	//{
	//	pData* sendback = new pData;
	//	//��̫��
	//	memcpy(sendback->eh.DestMAC, Packet->eh.SourMAC, sizeof(BYTE) * 6);
	//	memcpy(sendback->eh.DestMAC, hostMac, sizeof(BYTE) * 6);
	//	sendback->eh.EthType = Packet->eh.EthType;
	//	//IP��
	//	sendback->ih.Ver_Hlen = Packet->ih.Ver_Hlen;
	//	//ICMP
	//}
	
	//��·�ɱ�
	ULONG nextIP;
	//cout << "DstIP:" << GetIpFromULong(Packet->ih.DstIP) << endl;
	nextIP = route_find(Packet->ih.DstIP);
	if (nextIP == inet_addr("255.255.255.255"))
	{
		//cout << "���ڱ��У�ֱ���ӵ�" << endl;
		memset(Packet, '\0', sizeof(Packet));
		return;
	}
	log_write(3, Packet->ih.DstIP, Packet->ih.SrcIP);
	//cout << "nextIP:" << GetIpFromULong(nextIP) << endl;
	//���Ӧmac
	finder = IP_MAC.find(nextIP);
	//�ҵ��� ���´��
	if(finder != IP_MAC.end())
	{
		u_char* nextmac = finder->second;
		repack(Packet,hostMac,nextmac);
		int f = 1;
    	if (pcap_sendpacket(adh,(u_char*)Packet,header->len) != 0)
    	{
			f = 0;
			cout<<"����ʧ��"<<endl;
    	}
		if (f)
		{
			log_write(4, Packet->ih.DstIP, Packet->ih.SrcIP);
		}
	} 
	//û�ҵ� �Ӷ���
	else
	{
		if(++waitlen>=MAX_WAIT)//���������󳤶ȣ��Ƴ���һ��
		{
			whead->next = whead->next->next;
			waitlen--;
		}
		wtail->next = newait(header,Packet);
		log_write(5, Packet->ih.DstIP, Packet->ih.SrcIP);
		//��arp
		u_char* gmac = getMac(adh,nextIP,(ULONG)param,hostMac);
		wait* wtemp = whead;
		wait* wt = wtemp->next;
		for(;wtemp->next!=NULL;wtemp=wtemp->next,wt=wt->next)
		{
			if(nextIP == route_find(wt->data->ih.DstIP))
			{
				//����
				//repack(wt->data,hostMac,gmac);
				int f = 1;
				if (pcap_sendpacket(adh,(u_char*)Packet,wt->head->len) != 0)
				{
					f = 0;
					cout<<"����ʧ��"<<endl;
				}
				if (f)
				{
					log_write(4, Packet->ih.DstIP, Packet->ih.SrcIP);
				}
				//�Ƴ�
				wtemp->next = wt->next;
				waitlen--;
			}
		}

	}

}

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	pcap_t* adhandle;
	int inum;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;    //��������
	string packet_filter = "arp or (ip and icmp and not dst host (";//arp����ȡ�Լ���mac��ַ,ip��icmp��ת���õ�
	struct bpf_program fcode;   //pcap_compile�����õĽṹ��
	mkdir(dName);
	FILE* p = NULL;
	p = fopen(dfName, "w");
	fclose(p);
	// ��ʼ��
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	int printflag = 1;
	int num = 0;
	for (d = alldevs; d != NULL; d = d->next)
	{
		i++;
		for (a = d->addresses; a != NULL; a = a->next)
		{
			// �ж��Ƿ���IP��ַ
			if (a->addr->sa_family == AF_INET)
			{
				if (firstnet == 0) 
				{
					firstnet = i;
				}
			}
		}
		if (!printflag) 
		{ 
			printf("\n"); 
		}

		printflag = 1;
	}
	inum = firstnet;//
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	int h = 0;
	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			h++;
		}
	}
	ULONG *hostip = new ULONG[h];
	ULONG *mask = new ULONG[h];
	int n = 0;
	for (a = d->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			num++;
			hostip[n] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			if (a->netmask)
			{
				mask[n] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			}
			n++;
		}	
	}
	//���ù�������
	for (int t = 0; t < num; t++)
	{
		packet_filter = packet_filter+GetIpFromULong(hostip[t]);
		if (t != num - 1)
		{
			packet_filter = packet_filter + " or ";
		}
		else
		{
			packet_filter = packet_filter + " ))";
		}
		
	}
	//cout << packet_filter << endl;
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 10000, NULL, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	adh = adhandle;
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;
	if (pcap_compile(adhandle, &fcode, packet_filter.c_str(), 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//��ȡ��Ҫ����Ϣ
	u_char tempmac[6] = { 0xff,0xff,0xff,0xff,0xff,0xf0 };
	printf("�ȴ�·�ɳ����ʼ��......\n");
	hostMac = getMac(adhandle, hostip[0], inet_addr("122.122.122.122"), tempmac);
	printf("��ѡ����豸: %s\n����%d��ip\n", d->name,num);
	for (int t = 0; t < num; t++)
	{
		if (t == 0)
		{
			route_init(hostip[t]&mask[t],mask[t],hostip[t]);
		}
		else
		{
			route_add(hostip[t] & mask[t], mask[t], hostip[t]);
		}
		cout<<"IP��ַ: "<< GetIpFromULong(hostip[t])<<endl;
		cout <<"��������: " << GetIpFromULong(mask[t]) << endl;
		IP_MAC[hostip[t]] = hostMac;
	}
	printf("MAC��ַ��%02X-%02X-%02X-%02X-%02X-%02X\n", hostMac[0], hostMac[1], hostMac[2], hostMac[3], hostMac[4], hostMac[5]);
	
	// �ֶ�����·�ɱ�
	printf("��ʼ���ɹ�����ʼ�ֶ����ý׶�:");

	
	route_show();
	while (true)
	{
		int opt;
		printf("�����Ҫ�޸�·�ɱ���,������1�������Ҫ����·�ɳ���������2: ");
		cin >> opt;
		if (opt == 2)
		{
			printf("\n\n����ʼ���У�����·�ɱ�\n���յ�·�ɱ�����\n");
			route_show();
			break;
		}
		else if (opt == 1)
		{
			int type;
			printf("�����Ҫ����·�ɱ���,������1�������Ҫɾ��·�ɱ��������2: ");
			cin >> type;
			if (type == 1)
			{
				ULONG dstip; char dip[15];
				ULONG dstmk; char dmk[15];
				ULONG nextR; char nrt[15];
				cout << "������Ŀ��IP: ";
				cin >> dip;
				cout << "������Ŀ������: ";
				cin >> dmk;
				cout << "��������һ·��: ";
				cin >> nrt;
				dstip = inet_addr(dip);
				dstmk = inet_addr(dmk);
				nextR = inet_addr(nrt);
				for (int i = 0; i < num; i++)
				{
					if ((nextR&mask[i]) == (hostip[i]&mask[i]))
					{
						cout << "�ȴ���ȡ�Է�MAC��ַ" << endl;
						getMac(adhandle, nextR, hostip[i], hostMac);
						break;
					}
				}

				route_add(dstip,dstmk,nextR);
				route_show();
			}
			else if (type == 2)
			{
				ULONG dstip; char dip[15];
				ULONG dstmk; char dmk[15];
				ULONG nextR; char nrt[15];
				cout << "������Ŀ��IP: ";
				cin >> dip;
				cout << "������Ŀ������: ";
				cin >> dmk;
				cout << "��������һ·��: ";
				cin >> nrt;
				dstip = inet_addr(dip);
				dstmk = inet_addr(dmk);
				nextR = inet_addr(nrt);
				route_delete(dstip, dstmk, nextR);
				route_show();
			}
		}

	}

	//·�ɳ�������
	pcap_freealldevs(alldevs);
	pcap_loop(adhandle,-1,route_trans,(u_char*)hostip[0]);

	return 0;
}
