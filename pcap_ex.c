#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <string.h>
#include <signal.h>
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // for inet_ntoa

#define BUFFER_SIZE 100000

struct network_flow
{
	char* source_ip;
	char* destination_ip;
	unsigned int source_port;
	unsigned int destination_port;
	unsigned int protocol;
};

char *filter = NULL;
int flag =0;
int total_network_flows = 0;
int tcp_flows = 0;
int udp_flows = 0;
int tcp_packets = 0;
int udp_packets = 0;
int total_packets = 0;
long tcp_bytes = 0;
long udp_bytes = 0;

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


// void tcp_info(struct ip *ip_header, const u_char *packet) {

//     // Get the header length in bytes
//     int header_length = ip_header->ip_hl * 4; 

//     // Get the TCP header
//     struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + header_length); 

//     printf("Protocol: TCP\n");

//     // get the source and destination IP addresses
//     char src_ip[INET_ADDRSTRLEN];
//     char dst_ip[INET_ADDRSTRLEN];
//     inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
//     inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
//     // print the source and destination IP addresses
//     printf("Source IP: %s\n", src_ip);
//     printf("Destination IP: %s\n", dst_ip);


//     // Print the source and destination port numbers
//     printf("Source port: %d\n", ntohs(tcp_header->source));
//     printf("Destination port: %d\n", ntohs(tcp_header->dest));

//     // Print the header length and payload length in bytes
//     printf("Header length: %d\n", tcp_header->doff * 4);
//     printf("Payload length: %d\n", ntohs(ip_header->ip_len) - header_length - (tcp_header->doff * 4));

//     tcp_bytes += header_length;
    
// }

void tcp_info(struct ip *ip_header, const u_char *packet) {

    

    if(flag == 0){
    /* Create a circular buffer to store the sequence numbers of the packets that have been received and acknowledged */
    int acknowledged_packets[BUFFER_SIZE];
    int head = 0;
    int tail = 0;
    

    // Get the header length in bytes
    int header_length = ip_header->ip_hl * 4; 

    // Get the TCP header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + header_length); 

    // Write the protocol to the file
    printf( "Protocol: TCP\n");

    // get the source and destination IP addresses
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    // Write the source and destination IP addresses to the file
    printf( "Source IP: %s\n", src_ip);
    printf( "Destination IP: %s\n", dst_ip);

    // Write the source and destination port numbers to the file
    printf( "Source port: %d\n", ntohs(tcp_header->source));
    printf( "Destination port: %d\n", ntohs(tcp_header->dest));

    // Write the header length and payload length in bytes to the file
    printf( "Header length: %d\n", tcp_header->doff * 4);
    printf( "Payload length: %d\n", ntohs(ip_header->ip_len) - header_length - (tcp_header->doff * 4));
    printf("\n");

    tcp_bytes += header_length;

    // Check if the packet is a retransmission
        if (head == tail) {
          // The buffer is empty, so this is not a retransmission
          acknowledged_packets[head] = tcp_header->th_seq;
          head = (head + 1) % BUFFER_SIZE;
        } else {
          // Check if the packet's sequence number is in the buffer
          int found = 0;
          for (int i = tail; i != head; i = (i + 1) % BUFFER_SIZE) {
            if (acknowledged_packets[i] == tcp_header->th_seq) {
              found = 1;
              break;
            }
          }
          if (found) {
            printf("Retransmitted\n");
          } else {
            // Add the packet's sequence number to the buffer
            acknowledged_packets[head] = tcp_header->th_seq;
            head = (head + 1) % BUFFER_SIZE;
          }
        }
    }
    else{
        FILE *log_file = fopen("log.txt", "a");
         /* Create a circular buffer to store the sequence numbers of the packets that have been received and acknowledged */
        int acknowledged_packets[BUFFER_SIZE];
        int head = 0;
        int tail = 0;
    

        // Get the header length in bytes
        int header_length = ip_header->ip_hl * 4; 

        // Get the TCP header
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + header_length); 

        // Write the protocol to the file
        fprintf(log_file,"Protocol: TCP\n");

        // get the source and destination IP addresses
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        // Write the source and destination IP addresses to the file
        fprintf(log_file,"Source IP: %s\n", src_ip);
        fprintf(log_file,"Destination IP: %s\n", dst_ip);

        // Write the source and destination port numbers to the file
        fprintf(log_file,"Source port: %d\n", ntohs(tcp_header->source));
        fprintf(log_file,"Destination port: %d\n", ntohs(tcp_header->dest));

        // Write the header length and payload length in bytes to the file
        fprintf(log_file,"Header length: %d\n", tcp_header->doff * 4);
        fprintf(log_file,"Payload length: %d\n", ntohs(ip_header->ip_len) - header_length - (tcp_header->doff * 4));
        fprintf(log_file,"\n");

        tcp_bytes += header_length;

        // Check if the packet is a retransmission
        if (head == tail) {
          // The buffer is empty, so this is not a retransmission
          acknowledged_packets[head] = tcp_header->th_seq;
          head = (head + 1) % BUFFER_SIZE;
        } else {
          // Check if the packet's sequence number is in the buffer
          int found = 0;
          for (int i = tail; i != head; i = (i + 1) % BUFFER_SIZE) {
            if (acknowledged_packets[i] == tcp_header->th_seq) {
              found = 1;
              break;
            }
          }
          if (found) {
            fprintf(log_file,"Retransmitted\n");
          } else {
            // Add the packet's sequence number to the buffer
            acknowledged_packets[head] = tcp_header->th_seq;
            head = (head + 1) % BUFFER_SIZE;
          }
        }
    // Close the file
    fclose(log_file);

    }


    // if (tcp_flows == 0)
	// {
	// 	add_network_flow(inet_ntoa(source_ip.sin_addr), inet_ntoa(destination_ip.sin_addr), ntohs(tcph->source), ntohs(tcph->dest), iph->protocol, &network_flows);
	// 	tcp_flows++;
	// 	total_network_flows++;
	// }

	// if (!network_flow_exists_in_array(inet_ntoa(source_ip.sin_addr), inet_ntoa(destination_ip.sin_addr), ntohs(tcph->source), ntohs(tcph->dest), iph->protocol, &network_flows))
	// {
	// 	add_network_flow(inet_ntoa(source_ip.sin_addr), inet_ntoa(destination_ip.sin_addr), ntohs(tcph->source), ntohs(tcph->dest), iph->protocol, &network_flows);
	// 	tcp_flows++;
	// 	total_network_flows++;
	// }

}














void udp_info(struct ip *ip_header, const u_char *packet) {

    

    if(flag == 0){
    // Get the header length in bytes
    int header_length = ip_header->ip_hl * 4; 

    // Get the UDP header
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + header_length);

    printf("Protocol: UDP\n");

    // get the source and destination IP addresses
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    // print the source and destination IP addresses
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);

    // Print the source and destination port numbers
    printf("Source port: %d\n", ntohs(udp_header->source));
    printf("Destination port: %d\n", ntohs(udp_header->dest));

    // Print the header length and payload length in bytes
    printf("Header length: %ld\n", sizeof udp_header);
    printf("Payload length: %ld\n", ntohs(udp_header->len) - sizeof udp_header);
    printf("\n");
    udp_bytes += header_length;
    }
    else{
        FILE *log_file = fopen("log.txt", "a");
        // Get the header length in bytes
        int header_length = ip_header->ip_hl * 4; 

        // Get the UDP header
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + header_length);

        fprintf(log_file,"Protocol: UDP\n");

        // get the source and destination IP addresses
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        // print the source and destination IP addresses
        fprintf(log_file,"Source IP: %s\n", src_ip);
        fprintf(log_file,"Destination IP: %s\n", dst_ip);

        // Print the source and destination port numbers
        fprintf(log_file,"Source port: %d\n", ntohs(udp_header->source));
        fprintf(log_file,"Destination port: %d\n", ntohs(udp_header->dest));

        // Print the header length and payload length in bytes
        fprintf(log_file,"Header length: %ld\n", sizeof udp_header);
        fprintf(log_file,"Payload length: %ld\n", ntohs(udp_header->len) - sizeof udp_header);
        fprintf(log_file,"\n");
        udp_bytes += header_length;

        // Close the file
        fclose(log_file);
    }


    // if (udp_flows == 0)
	// {
	// 	add_network_flow(inet_ntoa(source_ip.sin_addr), inet_ntoa(destination_ip.sin_addr), ntohs(udph->source), ntohs(udph->dest), iph->protocol, &network_flows);
	// 	udp_flows++;
	// 	total_network_flows++;
	// }

	// if (!network_flow_exists_in_array(inet_ntoa(source_ip.sin_addr), inet_ntoa(destination_ip.sin_addr), ntohs(udph->source), ntohs(udph->dest), iph->protocol, &network_flows))
	// {
	// 	add_network_flow(inet_ntoa(source_ip.sin_addr), inet_ntoa(destination_ip.sin_addr), ntohs(udph->source), ntohs(udph->dest), iph->protocol, &network_flows);
	// 	udp_flows++;
	// 	total_network_flows++;
	// }
    
}



// This function will be called every time a packet is received
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    if(filter[0] == '\0')
        printf("String empty\n");
    else
        printf("%s",filter);
  struct ether_header *eth_header;
  struct ip *ip_header;

  /* retrieve the position of the ethernet header */
  eth_header = (struct ether_header *) packet;

  /* check if the packet is an IP packet */
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP || ntohs(eth_header->ether_type) != ETHERTYPE_IPV6) {
    /* retrieve the position of the IP header.Could also use struct iphdr */
    ip_header = (struct ip *)(packet + sizeof(struct ether_header)); 
  
    ++total_packets;
    switch (ip_header->ip_p) {
      case IPPROTO_TCP:
        ++tcp_packets;
        tcp_info(ip_header,packet);
        break;

      case IPPROTO_UDP:
        ++udp_packets;
        udp_info(ip_header,packet);
        break;
      default:
        printf("Other\n");
        // Ignore other protocols
        break;
    }
  }
}


void print_statistics()
{
	
	printf(" Total network flows captured: %d\n", total_network_flows);
	printf(" Total TCP network flows captured: %d\n", tcp_flows);
	printf(" Total UDP network flows captured: %d\n", udp_flows);
	printf(" Total packets captured: %d\n", total_packets);
	printf(" Total TCP packets captured: %d\n", tcp_packets);
	printf(" Total UDP packets captured: %d\n", udp_packets);
	printf(" Total bytes of TCP packets captured: %ld\n", tcp_bytes);
	printf(" Total bytes of UDP packets captured: %ld\n", udp_bytes);
}

void live_monitor(const char* device){
  pcap_t *handle;  // Handle for the pcap session
  char errbuf[PCAP_ERRBUF_SIZE];
  // Open the network interface for packet capture
  handle = pcap_open_live(device, 65535, 1, -1, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "Could not open interface: %s\n", errbuf);
    exit(1);
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
  }

  // Start capturing packets
  pcap_loop(handle, 0, packet_handler, NULL);

  // Close the pcap session
  pcap_close(handle);

}







int main( int argc , char* argv[] )
{
	int opt;

	if (argc != 3 )
		usage();

	// 1. Select interface or pcap file
	while ( ( opt = getopt( argc , argv , ":i:r:fh" ) ) != -1 )
	{
		switch (opt)
		{	  
		case 'i':
        flag =1;
            live_monitor(optarg);
			break;
		case 'r':
        flag = 0;
			offline_monitor(optarg);
			break;
        case 'f':
		// Get the packet capture filter expression, if any.
            printf(" filename: %s\n", optarg);
            filter = optarg;
            break;  

		default:
			usage();
		}
	}
	
}
