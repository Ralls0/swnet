#include <stdio.h>  	// Standard C 
#include <pcap.h>	// libpcap/WinPcap

#define LINE_LEN 16

int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i=0;
	int res;
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
		/* print pkt timestamp and pkt len */
		printf("%ld:%ld (%d)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
		
		/* Print the packet */
		for (i=1; (i < header->caplen + 1 ) ; i++)
		{
			printf("%.2x ", pkt_data[i-1]);
			if ( (i % LINE_LEN) == 0) printf("\n");
		}
		
		printf("\n\n");
	}
	
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}
	
	pcap_close(fp);
	return 0;
}

