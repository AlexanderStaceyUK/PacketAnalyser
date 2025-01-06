#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>

// Analyses packet for SYN, ARP, URL backlist and returns a count
void analyse(int length,
             const unsigned char *packet,
             struct Count *count){

	// Stripping packet down into the appropiate layers for analysis
  	struct ether_header *eth_header = (struct ether_header *) packet;
	struct ip *ip_header = (struct ip *) (packet + ETH_HLEN);
	struct tcphdr *tcp_header = (struct tcphdr *) (packet + ETH_HLEN + (ip_header -> ip_hl * 4));

	// Analysing TCP header to see if it is a SYN packet
	if (tcp_header -> syn && !(tcp_header -> urg && tcp_header -> ack && tcp_header -> psh && tcp_header -> rst && tcp_header -> fin)){
    	count -> syn = count -> syn + 1;
    }
		
	// Analysing network layer to see if an ARP packet is present
	if (ntohs(eth_header -> ether_type) == ETH_P_ARP){
    	struct ether_arp *hdr = (struct ether_arp *) (packet + ETH_HLEN);
    	struct arphdr *arpHeader = (struct arphdr *) (&hdr -> ea_hdr);
		if (ntohs(arpHeader -> ar_op) == ARPOP_REPLY){
			count -> arp = count -> arp + 1;
		}
  	}

	//Analysing the application layer to see if it is a HTTP request to a blacklisted URL
	if (ntohs(tcp_header -> dest) == 80 && ntohs(eth_header -> ether_type) == ETH_P_IP){
		// Stripping packet down into the HTTP header
		const char *httpHdr = (char *) (packet + 14 + (ip_header->ip_hl * 4) + (tcp_header->doff * 4));
		int httpHdrLength = length - (sizeof(struct ether_header) + (ip_header->ip_hl * 4) + (tcp_header->doff * 4));
		char *HTTPString = malloc(sizeof(char) * (httpHdrLength + 1));
		int i;

		// Constructing the HTTP packet into ASCII format
		for (i = 0; i < httpHdrLength; i++){
			HTTPString[i] = (char) httpHdr[i];
		}
		HTTPString[httpHdrLength] = '\0';
		// Checking whether the HTTP data has the following blacklisted URLs
		if (strstr(HTTPString, "www.google.co.uk") != NULL){
			printf("============================== \n");
			printf("Blacklisted URL violation detected \n");
			printf("Source IP address: %s \n", inet_ntoa(ip_header->ip_src));
			printf("Destination IP address: %s (google)\n", inet_ntoa(ip_header->ip_dst));
			printf("============================== \n");
			count -> google = count -> google + 1;
		}
		if (strstr(HTTPString, "www.bbc.co.uk") != NULL){
			printf("============================== \n");
			printf("Blacklisted URL violation detected \n");
			printf("Source IP address: %s \n", inet_ntoa(ip_header->ip_src));
			printf("Destination IP address: %s (bbc)\n", inet_ntoa(ip_header->ip_dst));
			printf("============================== \n");
			count -> bbc = count -> bbc + 1;
		}
	}

}
