#include "stdio.h"
#include <map>
#include <set>
#include <vector>
#include <string>
#include <algorithm>
#include "winsock2.h"

using namespace std;

#define HAVE_REMOTE
#include "pcap.h" 

#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib , "wpcap.lib") //For winpcap


void ProcessPacket(u_char*, int); 

void print_ethernet_header(u_char*);
void PrintIpHeader(u_char*, int);
void PrintIcmpPacket(u_char*, int);
void print_udp_packet(u_char*, int);
void PrintTcpPacket(u_char*, int);
void PrintData(u_char*, int);
void printStatistic();
string getIpAddress(unsigned char* Buffer, int Size);

typedef struct infoIp
{
	unsigned int byteCount = 0;
	unsigned int packageCount = 0;
	std::set<unsigned short> udpPorts;
	std::set<unsigned short> tcpPorts;
};

std::map<string, infoIp> currentInfo;
std::map<string, infoIp>::iterator currentInfoIt;

// Size of data of one package without headers
int data_size;
// Total size of all packages(with headers)
int totalSize = 0;

//Ethernet Header
typedef struct ethernet_header
{
	UCHAR dest[6];
	UCHAR source[6];
	USHORT type;
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

//Ip header (v4)
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;

//UDP header
typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
								   This indicates where the data begins.
								   The length of the TCP header is always a multiple
								   of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag


	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;

int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;
struct sockaddr_in source, dest;
char hex[2];

ETHER_HDR *ethhdr;
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;
u_char *data;



int main()
{
	u_int i, res, inum;
	//u_char errbuf[PCAP_ERRBUF_SIZE], buffer[100]; 
	char *errbuf = new char(256);
	char *buffer = new char(256);
    const u_char *pkt_data;
	time_t seconds;
	struct tm tbreak;
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	struct pcap_pkthdr *header;


	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}

	i = 0;
	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);

		if (d->description)
		{
			printf(" (%s)\n", d->description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}

	if (i == 0)
	{
		fprintf(stderr, "No interfaces found! Exiting.\n");
		return -1;
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf_s("%d", &inum);


	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((fp = pcap_open(d->name,
		100 /*snaplen*/,
		PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
		20 /*read timeout*/,
		NULL /* remote authentication */,
		errbuf)
		) == NULL)
	{
		fprintf(stderr, "\nError opening adapter\n");
		return -1;
	}

	// packets read
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
		{
			// Timeout elapsed
			continue;
		}
		totalSize += header->len;
		ProcessPacket(const_cast<u_char*>(pkt_data), header->caplen);
		printStatistic();
	}

	if (res == -1)
	{
		fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}
	
	return 0;
}


bool myfunction(int i, int j) { return (i>j); }

std::vector<string> get5topIps()
{
	std::vector<int> bytes;
	std::map<int, string> ipMap;
	std::vector<string> result;

	for (currentInfoIt = currentInfo.begin(); currentInfoIt != currentInfo.end(); currentInfoIt++)
	{
		ipMap[currentInfoIt->second.byteCount] = currentInfoIt->first;
		bytes.push_back(currentInfoIt->second.byteCount);
	}

	if (bytes.size() > 4)
	{
		std::partial_sort(bytes.begin(), bytes.begin() + 5, bytes.end(), myfunction);
		for (int i = 0; i < 5; i++) result.push_back(ipMap.at(bytes.at(i)));
	}
	return result;
}



void printStatistic()
{

	printf("\n");
	printf("\n");
	printf("Average length of package: %d\n", totalSize/total);
	printf("\n");
	printf("Top 5 ip addresses:\n Address\t\tBytes\n");
	std::vector<string> topIps = get5topIps();
	for (int i = 0; i < topIps.size(); i++)
	{
		printf("%s\t\t%d\n", topIps.at(i).c_str(),
			currentInfo.at(topIps.at(i)).byteCount);
	}
	printf("\n");
	printf("General Statistic\n");
	printf("Address\t\t || Total bytes \t\t || TCP ports \t\t || UDP ports\n");
	for (currentInfoIt = currentInfo.begin(); currentInfoIt != currentInfo.end(); currentInfoIt++)
	{
		printf("%s\t\t || %d\t\t || ", currentInfoIt->first.c_str(),
			(currentInfoIt->second).byteCount);
		for (auto f : (currentInfoIt->second).tcpPorts) {
			printf("%u;", ntohs(f));
		}
		printf("\t\t || ");
		for (auto f : (currentInfoIt->second).udpPorts) {
			printf("%u;", ntohs(f));
		}
		printf("\n");
	}
}



void ProcessPacket(u_char* Buffer, int Size)
{
	//Ethernet header
	ethhdr = (ETHER_HDR *)Buffer;
	++total;
	data_size = 0;
	bool isTcp = false, isUdp = false;
	unsigned short source_port_tcp;
	unsigned short source_port_udp;


	//Ip packets
	if (ntohs(ethhdr->type) == 0x0800)
	{
		//ip header
		iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
		unsigned short iphdrlen = iphdr->ip_header_len * 4;
		data_size = (Size - sizeof(ETHER_HDR)-iphdrlen) * 4;

		switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
		{
		case 6: //TCP Protocol
			iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
			iphdrlen = iphdr->ip_header_len * 4;
			tcpheader = (TCP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));
			source_port_tcp = tcpheader->source_port;
			isTcp = true;
			break;

		case 17: //UDP Protocol
			iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
			iphdrlen = iphdr->ip_header_len * 4;
			udpheader = (UDP_HDR*)(Buffer + iphdrlen + sizeof(ETHER_HDR));
			source_port_udp = udpheader->source_port;
			isUdp = true;
			break;

		default: 
			break;
		}
		string currentIp = getIpAddress(Buffer, Size);
		currentInfoIt = currentInfo.find(currentIp);
		if (currentInfoIt == currentInfo.end())
		{
			infoIp temp;
			temp.packageCount++;
			temp.byteCount = data_size;
			if (isTcp) temp.tcpPorts.insert(source_port_tcp);
			if (isUdp) temp.udpPorts.insert(source_port_udp);
			currentInfo[currentIp] = temp;
		}
		else
		{
			currentInfoIt->second.packageCount++;
			currentInfoIt->second.byteCount += data_size;
			if (isTcp) currentInfoIt->second.tcpPorts.insert(source_port_tcp);
			if (isUdp) currentInfoIt->second.udpPorts.insert(source_port_udp);
		}
	}
}

string getIpAddress(unsigned char* Buffer, int Size)
{
	int iphdrlen = 0;

	iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
	iphdrlen = iphdr->ip_header_len * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	return inet_ntoa(source.sin_addr);
}