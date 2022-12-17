#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <string.h>
#include <signal.h>
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // for inet_ntoa

int tcp_packets = 0;
int udp_packets = 0;
int skipped_packets = 0;
int total_packets = 0;

void usage(void)
{
	printf(
			"\n"
			"usage:\n"
			"\t./pcap_ex \n"
			"Options:\n"
			"-i eth0 (save the packets in log.txt)\n"
			"-r test_pcap_5mins.pcap (print the outputs in terminal)\n"
			"-i eth0 -f “port 8080”\n"
			"-h, Help message\n\n"
			);

	exit(1);
}


void print_ip_addresses(struct ip *ip_header,const u_char *packet) {
    // Get the source and destination IP addresses
    struct in_addr src_addr = ip_header->ip_src;
    struct in_addr dst_addr = ip_header->ip_dst;

    // Convert the IP addresses to strings
    char *src_ip = inet_ntoa(src_addr);
    char *dst_ip = inet_ntoa(dst_addr);

    // Print the source and destination IP addresses
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);

    // Get the header length in bytes
    int header_length = ip_header->ip_hl * 4;

    ++total_packets;
    // Print the protocol of the packet
    printf("Protocol: ");
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            printf("TCP\n");
            ++tcp_packets;

            // Get the TCP header
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + header_length);

            // Print the source and destination port numbers
            printf("Source port: %d\n", ntohs(tcp_header->source));
            printf("Destination port: %d\n", ntohs(tcp_header->dest));

            // Print the header length and payload length in bytes
            printf("Header length: %d\n", tcp_header->doff * 4);
            printf("Payload length: %d\n", ntohs(ip_header->ip_len) - header_length - (tcp_header->doff * 4));
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            ++udp_packets;

            // Get the UDP header
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + header_length);

            // Print the source and destination port numbers
            printf("Source port: %d\n", ntohs(udp_header->source));
            printf("Destination port: %d\n", ntohs(udp_header->dest));

            // Print the header length and payload length in bytes
            printf("Header length: %d\n", 8);
            printf("Payload length: %d\n", ntohs(udp_header->len) - 8);
            break;
        default:
            printf("Other\n");
            ++skipped_packets;
            // Ignore other protocols
            break;
    }
}



// This function will be called every time a packet is received
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	struct ether_header *eth_header;
	struct ip *ip_header;
	u_int ip_len;

	/* retrieve the position of the ethernet header */
	eth_header = (struct ether_header *) packet;

	/* check if the packet is an IP packet */
	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
	/* retrieve the position of the IP header.Could also use struct iphdr */
    ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    // Get the header length in bytes
    int header_length = ip_header->ip_hl * 4;
  
  
	 ++total_packets;
    // Print the protocol of the packet
    printf("Protocol: ");
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            printf("TCP\n");
            ++tcp_packets;

            // Get the TCP header
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + header_length);

            // Print the source and destination port numbers
            printf("Source port: %d\n", ntohs(tcp_header->source));
            printf("Destination port: %d\n", ntohs(tcp_header->dest));

            // Print the header length and payload length in bytes
            printf("Header length: %d\n", tcp_header->doff * 4);
            printf("Payload length: %d\n", ntohs(ip_header->ip_len) - header_length - (tcp_header->doff * 4));
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            ++udp_packets;

            // Get the UDP header
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + header_length);

            // Print the source and destination port numbers
            printf("Source port: %d\n", ntohs(udp_header->source));
            printf("Destination port: %d\n", ntohs(udp_header->dest));

            // Print the header length and payload length in bytes
            printf("Header length: %d\n", 8);
            printf("Payload length: %d\n", ntohs(udp_header->len) - 8);
            break;
        default:
            printf("Other\n");
            ++skipped_packets;
            // Ignore other protocols
            break;
    }
	//printf("TCP : %d   UDP : %d    Others : %d   Total : %d\r", tcp_packets , udp_packets , skipped_packets , total_packets);
}
}

void live_monitor(const char* device){
  pcap_t *handle;  // Handle for the pcap session
  char errbuf[PCAP_ERRBUF_SIZE];
  // Open the network interface for packet capture
  handle = pcap_open_live(device, 65535, 1, 0, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "Could not open interface: %s\n", errbuf);
    return 1;
  }

  // Start capturing packets
  pcap_loop(handle, 0, packet_handler, NULL);

  // Close the pcap session
  pcap_close(handle);

}

void offline_monitor(const char* filename){
  pcap_t *handle;  // Handle for the pcap session
  char errbuf[PCAP_ERRBUF_SIZE];
  // Open the network interface for packet capture
  handle = pcap_open_offline(filename, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "Could not open file: %s\n", errbuf);
    return 1;
  }

  // Start capturing packets
  pcap_loop(handle, 0, packet_handler, NULL);

  // Close the pcap session
  pcap_close(handle);


}







int main( int argc , char* argv[] )
{
	char filter[256];
	int opt;


	if (argc != 3 )
		usage();

	// 1. Select interface or pcap file
	while ( ( opt = getopt( argc , argv , "hirf:" ) ) != -1 )
	{
		switch (opt)
		{		
		case 'i':
			live_monitor(optarg);
			break;
		case 'r':
			offline_monitor(optarg);
			break;
        case 'f':

		// Get the packet capture filter expression, if any.
    	for (int i = optind; i < argc; i++)
    	{
        	strcat(filter, argv[i]);
        	strcat(filter, " ");
    	}	
            break;

		default:
			usage();
		}
	}
	
}