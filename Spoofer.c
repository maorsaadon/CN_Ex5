#include <stdio.h>
#include <string.h>
#include <errno.h>
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<netinet/ip_icmp.h>	//Provides declarations for icmp headereader
#include<netinet/ip.h>	//Provides declarations for ip header
#include <netinet/in.h>
#include <unistd.h>

#define DST_IP "127.0.0.1"


unsigned short calculate_checksum(unsigned short *buf, int length);

int main(int argc, char *argv[]){
    //check the IP
    if (argc == 1) {
        argv[1] = "1.1.1.1";
    }

    /*******************************
       Spoof an ICMP echo request
    ********************************/

    char packet[IP_MAXPACKET];// Combine the packet
    memset(packet, 0, IP_MAXPACKET);

    //Fill in the IP header
    struct iphdr *ip = (struct iphdr *)( packet );
    unsigned short iphdrlen = ip->ihl*4;

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 16;
    ip->ttl= 20;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr(argv[1]);
    ip->daddr = inet_addr(DST_IP);
    ip->tot_len= htons(sizeof(struct iphdr));


    // Fill in the ICMP header
    struct icmphdr *icmp = (struct icmphdr *)(packet + iphdrlen);
    int header_size =  iphdrlen + sizeof(struct icmphdr) ;

    icmp->type = ICMP_ECHO;//ICMP type 8 for request and 0 for replay
    icmp->code = 0;
    icmp->un.echo.id =18;
    icmp->un.echo.sequence =0;

    // Calculate checksum
    icmp->checksum= calculate_checksum((unsigned short *) (packet), header_size);


    /*************************************************************
          Given an IP packet, send it out using a raw socket.
    **************************************************************/

    //send the spoofed packet

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    // Step 2: Set socket option.
    int enable = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,&enable, sizeof(enable));

    // Step 3: Provide needed information about destination
    struct sockaddr_in source,dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;
    dest.sin_family = AF_INET;



    // Step 4: Send the packet out.
    printf("Sending spoofd IP packet...\n");
    if (sendto(sock, packet, sizeof(packet) , 0, (struct sockaddr *)&dest, sizeof(dest))< 0)
    {
        fprintf(stderr, "sendto() failed with error: %d", errno);
    }
    else
    {
        printf("\n---------------------------\n");
        printf("\nSending spoofd IP packet from : %s to : ", inet_ntoa(source.sin_addr));
        printf("%s" , inet_ntoa(dest.sin_addr));
        printf("\n---------------------------\n");

    }
    close(sock);

    return 0;
}

/*******************************
            Helper
********************************/

unsigned short calculate_checksum(unsigned short *buf, int length)
{
    int nleft = length;
    int sum = 0;
    unsigned short *w = buf;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry-outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}


