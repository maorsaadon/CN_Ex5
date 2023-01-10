#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <string.h>
#include <errno.h>

#include "myheader.h"

#define PACKET_LEN 1500

/*************************************************************

  Given an IP packet, send it out using a raw socket.

**************************************************************/
void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: set socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed info about destination
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: send the packet out
       printf("\nSending spoofd IP packet...");

    if (sendto(sock, ip, ntohs(ip->iph_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info)) < 0){

    	fprintf(stderr, "sendto() failed with error: %d", errno);

    	}

    	else{

    	printf("\n---------------------------\n");

    	printf("\tFrom: %s\n", inet_ntoa(ip->iph_sourceip));

    	printf("\tTo: %s\n", inet_ntoa(ip->iph_destip));

    	printf("\n---------------------------\n");

	}
    close(sock);
}

/*******************************

  Spoof an ICMP echo request

********************************/
void send_reply_packet(struct ipheader * ip) {
  
  char buffer[PACKET_LEN];
  int ip_header_len = ip->iph_ihl * 4;

  //Make copy from the sniffed packet
  memset((char *)buffer, 0, PACKET_LEN);
  memcpy((char *)buffer, ip, ntohs(ip->iph_len));
  struct ipheader* new_ip = (struct ipheader*) buffer;
  struct icmpheader* new_icmp = (struct icmpheader*) (buffer + sizeof(ip_header_len));

  //Swap source and destination for echo reply
  new_ip->iph_sourceip = ip->iph_destip;
  new_ip->iph_destip   = ip->iph_sourceip;
  new_ip->iph_ttl = 128;

  //ICMP echo reply type is 0
  new_icmp->icmp_type = 0;

  send_raw_ip_packet(new_ip);
}

void got_packet(u_char *args, const struct pcap_pkthdr * header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader*) packet;

  if(ntohs(eth->ether_type) == 0x0800) { // 0x0800 = IP TYPE
    struct ipheader *ip = (struct ipheader*) (packet + sizeof(struct ethheader));
    printf("\nSniffing packet...");
    printf("\n---------------------------\n");
    printf("\tFrom: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("\tTo: %s\n", inet_ntoa(ip->iph_destip));   
    printf("\n---------------------------\n");
  // Determine protocol
  switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
        	    send_reply_packet(ip);
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }

  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);
  return 0;  
}