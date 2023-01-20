#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include "header.h"
#define PACKET_LEN 1500


void got_packet(u_char *args, const struct pcap_pkthdr *header,  const u_char *packet);
void send_echo_reply(struct ip_hdr * ip);
void send_raw_ip_packet(struct ip_hdr* ip, struct icmp_hdr* icmp);
unsigned short calculate_checksum (unsigned short *buf, int length);

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp[icmptype] = 8";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;

}


void got_packet(u_char *args, const struct pcap_pkthdr *header,  const u_char *packet) {

//Get the IP Header part of this packet , excluding the ethernet header

    struct ip_hdr *ip = (struct ip_hdr *) (packet + sizeof(struct eth_hdr));

    unsigned short iphdrlen = ip->ihl * 4;

    struct icmp_hdr *icmp = (struct icmp_hdr *) (packet + iphdrlen + sizeof(struct eth_hdr));

    if ((unsigned int) (icmp->type) == 8) {
        send_echo_reply(ip);
    }
}

/*******************************
   Spoof an ICMP echo request
********************************/
void send_echo_reply(struct ip_hdr * ip) {

    const char buffer[PACKET_LEN];
    memset((char *) buffer, 0, PACKET_LEN);


    struct icmp_hdr *new_icmp = (struct icmp_hdr *)(buffer + sizeof(struct ip_hdr));
    new_icmp->type = 0;
    new_icmp->checksum = calculate_checksum((unsigned short *)new_icmp,sizeof(struct icmp_hdr));

    struct ip_hdr *new_ip = (struct ip_hdr *) buffer;
    new_ip->version = 4;
    new_ip->ihl = 5;
    new_ip->ttl = 20;
    new_ip->saddr.s_addr = inet_addr(inet_ntoa(ip->daddr));
    new_ip->daddr.s_addr= inet_addr(inet_ntoa(ip->saddr));
    new_ip->protocol = IPPROTO_ICMP;
    new_ip->tot_len= htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));

    // Fill in the ICMP header
    //ICMP type 8 for request and 0 for replay
    new_icmp->type = 0;

    // Calculate checksum
    new_icmp->checksum = 0;
    new_icmp->checksum = calculate_checksum((unsigned short *) new_icmp, sizeof(struct icmp_hdr));


    send_raw_ip_packet (new_ip, new_icmp);
}

/*************************************************************
      Given an IP packet, send it out using a raw socket.
**************************************************************/
void send_raw_ip_packet(struct ip_hdr* ip, struct icmp_hdr* icmp) {
    struct sockaddr_in dest;
    int enable = 1;

    // Step 1: create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
        printf("Error with the socket.");

    // Step 2: set socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed info about destination
    dest.sin_family = AF_INET;
    dest.sin_addr = ip->daddr;

    // Step 4: send the packet out

    sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *) &dest, sizeof(dest));

    printf("\nSending spoofd IP packet...\n");
    printf("\n\n***********************ICMP Packet*************************\n");

    printf("\nIP Header\n");
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(ip->tot_len));
    printf("   |-Source IP        : %s\n", inet_ntoa(ip->saddr));
    printf("   |-Destination IP   : %s\n", inet_ntoa(ip->daddr));

    printf("\nICMP Header\n");
    printf("   |-Type : %d\n", (icmp->type));
    printf("   |-Seq  : %d\n", (icmp->seq));

    printf("\n###########################################################");


    close(sock);
}

/*******************************
        Calculate Checksum
********************************/

unsigned short calculate_checksum (unsigned short *buf, int length) {
    int nleft = length;
    int sum = 0;
    unsigned short *w = buf;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    // add back carry-outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}



