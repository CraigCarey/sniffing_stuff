// g++ simplesniffer.cpp -o simplesniffer -lpcap

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <pcap.h>

using byte = uint8_t;
const uint32_t TypeSubtypeByte = 26;

// Callback function called by pcap_loop() everytime a packet arrives
// at the network card. This function prints the captured raw MAC address data in hex
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	if (packet[TypeSubtypeByte] == 0x40)
	{	
		printf("MAC: ");
		for (uint32_t i = 36; i <= 41; ++i)
		{
			printf("%02X", packet[i]);

			if(i != 41)
				putchar(':');
		}

		puts("");
	}
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

	printf("Opening device %s for live capture...", device);

	pcap_t *descr = nullptr;
	const int MaxBytesToCapture = 2048;

	// Open device in promiscuous mode
	if ((descr = pcap_open_live(device, MaxBytesToCapture, 1, 512, errbuf)) == nullptr)
	{
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	puts("\tdone");

	// Loop forever & call processPacket() for every received packet
	int count = 0;
	if (pcap_loop(descr, -1, processPacket, (u_char *) &count) == -1)
	{
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr));
		exit(1);
	}

	return 0;
}
