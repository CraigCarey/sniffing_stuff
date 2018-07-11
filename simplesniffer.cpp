// g++ simplesniffer.cpp -o simplesniffer -lpcap

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <pcap.h>

// Callback function called by pcap_loop() everytime a packet arrives
// at the network card. This function prints the captured raw data in hex
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	int *counter = (int *) arg;

	printf("Packet Count: %d\n", ++(*counter));
	printf("Received Packet Size: %d\n", pkthdr->len);
	printf("Payload:\n");

	for (uint32_t i = 0; i < pkthdr->len; ++i)
	{
		if (isprint(packet[i]))
			printf("%c ", packet[i]);
		else
			printf(". ");

		if ((i % 16 == 0 && i != 0) || i == pkthdr->len - 1)
			printf("\n");
	}

	printf("\n");
}


int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	char *device = nullptr;

	// If user supplied interface name, use it
	if (argc > 1)
	{
		device = argv[1];
	}
	else
	{
		// Get the name of the first device suitable for capture
		if ((device = pcap_lookupdev(errbuf)) == nullptr)
		{
			fprintf(stderr, "ERROR: %s\n", errbuf);
			exit(1);
		}
	}

	printf("Opening device %s for live capture\n", device);

	pcap_t *descr = nullptr;
	const int MaxBytesToCapture = 2048;

	// Open device in promiscuous mode
	if ((descr = pcap_open_live(device, MaxBytesToCapture, 1, 512, errbuf)) == nullptr)
	{
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	// Loop forever & call processPacket() for every received packet
	int count = 0;
	if (pcap_loop(descr, -1, processPacket, (u_char *) &count) == -1)
	{
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr));
		exit(1);
	}

	return 0;
}
