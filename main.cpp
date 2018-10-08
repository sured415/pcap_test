#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#define LIBNET_LIL_ENDIAN 1
#include <header.h>


int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf("syntax: pcap_test <interface>\n");
		printf("sample: pcap_test wlan0\n");
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	char  ipaddrbuf[20];

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		printf("\n%u bytes captured\n", header->caplen);
		struct libnet_ethernet_hdr* ehtH = (struct libnet_ethernet_hdr *)packet;
		printf("dst mac : %02X:%02X:%02X:%02X:%02X:%02X\n",ehtH->ether_dhost[0],ehtH->ether_dhost[1],ehtH->ether_dhost[2],ehtH->ether_dhost[3],ehtH->ether_dhost[4],ehtH->ether_dhost[5]);
		printf("src mac : %02X:%02X:%02X:%02X:%02X:%02X\n",ehtH->ether_shost[0],ehtH->ether_shost[1],ehtH->ether_shost[2],ehtH->ether_shost[3],ehtH->ether_shost[4],ehtH->ether_shost[5]);
		printf("Ether Type : 0x%04x\n",ntohs(ehtH->ether_type));

		if(ntohs(ehtH->ether_type) == ETHERTYPE_IP){
			packet += sizeof(struct libnet_ethernet_hdr);
			struct libnet_ipv4_hdr* ipH = (struct libnet_ipv4_hdr *)packet;

			printf("src ip : %s\n",inet_ntop(AF_INET, &ipH->ip_src, ipaddrbuf, sizeof(ipaddrbuf)));
		        printf("dst ip : %s\n",inet_ntop(AF_INET, &ipH->ip_dst, ipaddrbuf, sizeof(ipaddrbuf)));

			if(ipH->ip_p == IP_PROTOCOL_TCP){
				packet += (ipH->ip_hl * 4);
				struct libnet_tcp_hdr* tcpH = (struct libnet_tcp_hdr *)packet;
				printf("src prot : %d\n",ntohs(tcpH->th_sport));
				printf("des prot : %d\n",ntohs(tcpH->th_dport));
				packet += (tcpH->th_off * 4);
				u_int16_t len = (ipH->ip_hl * 4)+(tcpH->th_off * 4);
				if(ntohs(ipH->ip_len) > len) {
					u_int16_t count = 16;
					if(ipH->ip_len - len < count) count = ipH->ip_len - len;
					for(int i=1; i<count; i++) printf("%02x ", packet[i-1]);
				}
				printf("\n");
			}
		}
	}
	pcap_close(handle);
	return 0;
}
