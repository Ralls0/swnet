#include <stdio.h>  	// Standard C 
#include <pcap.h>	// libpcap/WinPcap

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
/* Ethernet length */
#define ETHER_LEN 14
/* Ip length */
#define IP_LEN 20

/* Eth header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP address */
struct ipaddr {
      u_char s_b1;
      u_char s_b2;
      u_char s_b3;
      u_char s_b4;
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct ipaddr ip_src,ip_dst; /* source and dest address */
};

/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_int16_t th_sport;	/* source port */
		u_int16_t th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

int main(int argc, char **argv) {
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	struct sniff_ethernet *eth;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;
	const u_char *pkt_data;
	u_int i=0;
	int res;
	u_int16_t ethtype;
	pcap_if_t *alldevsp, *temp;
	
	if (argc != 2)
	{	
		fprintf(stderr, "[e] Error: invalid parameters\n");
		fprintf(stdout, "[i] Usage: %s interface\n", argv[0]);
		fprintf(stdout, "[i] Interfaces:\n");
		if(pcap_findalldevs(&alldevsp, errbuf)==-1) {
        		fprintf(stderr, "[e] Error in pcap findall devs");
        		return -1;   
    		}

    		for(temp=alldevsp; temp; temp=temp->next) {
		        printf("%d  :  %s\n",i++,temp->name);
       
    		}
			
		return -1;
	}
	
	/* Open the capture file */
	if ((fp = pcap_open_live(argv[1],	// name of the interface
				2000,		// eth is 1500 Byte, so a little more
				1, 		// promiscuous
				1000, 		// 1s timeout
	 			errbuf		// error buffer
				)) == NULL)
	{
		fprintf(stderr,"[e] Unable to open the file %s.\n\n", argv[1]);
		return -1;
	}
	
	/* Retrieve the packets from the file */
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		eth = (struct sniff_ethernet *) pkt_data;
		
		/* print pkt timestamp */
		fprintf(stdout, "%ld:%ld ", header->ts.tv_sec, header->ts.tv_usec);
		
		/* print pkt source mac */
		fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x -> ", 
			eth->ether_shost[0], 
			eth->ether_shost[1],
			eth->ether_shost[2],
			eth->ether_shost[3],
			eth->ether_shost[4],
			eth->ether_shost[5]
		);
		
		/* print pkt destination mac */
		fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x ", 
			eth->ether_dhost[0], 
			eth->ether_dhost[1],
			eth->ether_dhost[2],
			eth->ether_dhost[3],
			eth->ether_dhost[4],
			eth->ether_dhost[5]
		);

		ethtype = ntohs(eth->ether_type);

		if (ethtype == 0x0800) {
			
			ip = (struct sniff_ip *) (pkt_data + ETHER_LEN);
			
			/* print pkt source ip */
			fprintf(stdout, "%d.%d.%d.%d -> ", 
				ip->ip_src.s_b1,
				ip->ip_src.s_b2,
				ip->ip_src.s_b3,
				ip->ip_src.s_b4
			);	

			/* print pkt destination ip */
			fprintf(stdout, "%d.%d.%d.%d ", 
				ip->ip_dst.s_b1,
				ip->ip_dst.s_b2,
				ip->ip_dst.s_b3,
				ip->ip_dst.s_b4
			);

			/* print pkt protocol */
			fprintf(stdout, "%d ", ip->ip_p);

			if (ip->ip_p == 6) {

			tcp = (struct sniff_tcp *)(pkt_data + ETHER_LEN + IP_LEN);

			/* print pkt source port */
			fprintf(stdout, "%d -> ", ntohs(tcp->th_sport));
	
			/* print pkt source port */
			fprintf(stdout, "%d -> ", ntohs(tcp->th_dport));

			}

		}
	
		fprintf(stdout, "\n");

	}
	
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}
	
	pcap_close(fp);
	return 0;
}

