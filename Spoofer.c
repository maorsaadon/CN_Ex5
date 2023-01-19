#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "header.h"

#define PACKET_LEN 1500

int check_ip(char *ip);
void send_raw_ip_packet(struct ip_hdr* ip);
unsigned short calculate_checksum (unsigned short *buf, int length);

int main(int argc, char *argv[]){
    if (argc == 1) {
        argv[1] = "1.1.1.1";
    }

    if(!check_ip(argv[1]))
    {
        printf(" Sorry but this is not a valid ip please try again. \n");
        exit(1);

    }
    char buffer[PACKET_LEN];

    memset(buffer, 0, PACKET_LEN);

    struct icmp_hdr *icmp = (struct icmp_hdr *)(buffer + sizeof(struct ip_hdr));
    icmp->type = 8;
    icmp->checksum = calculate_checksum((unsigned short *)icmp,sizeof(struct icmp_hdr));

    struct ip_hdr *ip = (struct ip_hdr *) buffer;
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 20;
    ip->saddr.s_addr = inet_addr(argv[1]);
    ip->daddr.s_addr = inet_addr("1.2.3.4");
    ip->protocol = IPPROTO_ICMP;
    ip->tot_len= htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));

    printf("\nSending spoofd IP packet...\n");
    printf("\n\n**********************ICMP Packet************************\n");

    printf("\nIP Header\n");
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(ip->tot_len));
    printf("   |-Source IP        : %s\n", inet_ntoa(ip->saddr));
    printf("   |-Destination IP   : %s\n", inet_ntoa(ip->daddr));

    printf("\nICMP Header\n");
    printf("   |-Type : %d", (unsigned int) (icmp->type));
    printf("   |-Seq  : %d", (unsigned int) (icmp->seq));

    printf("\n###########################################################\n");

    send_raw_ip_packet(ip);

    return 0;
}

/*******************************
          IP Check
********************************/

int check_ip(char *ip){
    struct sockaddr_in sock_in;
    int check = inet_pton(AF_INET , ip , &(sock_in.sin_addr));
    return check!=0;
}

/*************************************************************
         Given an IP packet, send it out using a raw socket.
**************************************************************/

void send_raw_ip_packet(struct ip_hdr* ip) {
    struct sockaddr_in dest_info;
    int enable;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->daddr;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->tot_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

/*******************************
        Calculate Checksum
********************************/

unsigned short calculate_checksum (unsigned short *buf, int length) {
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp=0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short)(~sum);
}