/* To compile: gcc simplesniffer.c -o simplesniffer -lpcap  */

#include <pcap.h> 
#include <string.h> 
#include <stdlib.h> 

#define MAXBYTES2CAPTURE 2048 


/* Callback function called by pcap_loop() everytime a packet arrives */
/* at the network card. This function prints the captured raw data in hex */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{
	int i = 0;
	int *counter = (int *)arg;

	printf("Packet Count: %d\n", ++(*counter));
	printf("Received Packet Size: %d\n", pkthdr->len);
	printf("Payload:\n"); 

	for (i = 0; i < pkthdr->len; ++i)
	{
		if (isprint(packet[i]))
			printf("%c ", packet[i]);
		else 
			printf(". ");

		if((i % 16 == 0 && i!=0) || i == pkthdr->len - 1)
			printf("\n"); 
	}

	printf("\n");

	return;
}



/* Opens network interface and calls pcap_loop() */
int main(int argc, char *argv[] )
{
	int i = 0;
	int count = 0;
	pcap_t *descr = NULL; 
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device = NULL; 
	memset(errbuf,0,PCAP_ERRBUF_SIZE);

	/* If user supplied interface name, use it. */
	if( argc > 1)
	{
		device = argv[1];
	}
	else
	{
		/* Get the name of the first device suitable for capture */
		if ((device = pcap_lookupdev(errbuf)) == NULL)
		{
			fprintf(stderr, "ERROR: %s\n", errbuf);
			exit(1);
		}
	}

	printf("Opening device %s\n", device); 

	/* Open device in promiscuous mode */
	if ((descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL)
	{
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	/* Loop forever & call processPacket() for every received packet*/
	if (pcap_loop(descr, -1, processPacket, (u_char *)&count) == -1)
	{
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}

	return 0;
}
