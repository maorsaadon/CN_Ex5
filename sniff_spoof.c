#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

#define PACKET_LEN 1500

unsigned short calculate_checksum(unsigned short *buf, int length);
void send_reply_packet(struct iphdr * ip);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);



FILE *output;

int main()
{
    pcap_if_t *alldevsp , *device;
    pcap_t *handle; //Handle of the device that shall be sniffed
    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;

    //First get the list of available devices
    printf("Finding available devices ... \n");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        exit(1);
    }

    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }

    //Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];

    //Open the device for sniffing
    printf("Opening device %s for sniffing ... \n" , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }

    output=fopen("output.txt","w");
    if(output==NULL)
    {
        printf("Unable to create file.\n");
    }

    //Put the device in sniff loop
    pcap_loop(handle , -1 , got_packet , NULL);

    pcap_close(handle);

}

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


void send_reply_packet(struct iphdr *ip) {

    /*******************************
       Spoof an ICMP echo request
    ********************************/

    char packet[PACKET_LEN];

    //Make copy from the sniffed packet
    memset(packet, 0, PACKET_LEN);
    memcpy((char *)packet, ip, ntohs(ip->tot_len));

    //Fill in the IP header
    struct iphdr *new_ip = (struct iphdr *)( packet );
    unsigned short iphdrlen = ip->ihl*4;
    new_ip->version = 4;
    new_ip->ihl = 5;
    new_ip->tos = 16;
    new_ip->ttl= 20;
    new_ip->protocol = IPPROTO_ICMP;

    //Swap source and destination for echo reply
    new_ip->saddr = ip->daddr;
    new_ip->daddr = ip->saddr;
    new_ip->tot_len= htons(sizeof(struct iphdr));

    // Fill in the ICMP header
    struct icmphdr *new_icmp = (struct icmphdr *)(packet + iphdrlen);
    int header_size =  iphdrlen + sizeof(struct icmphdr) ;

    new_icmp->type = ICMP_ECHO;//ICMP type 8 for request and 0 for replay
    new_icmp->code = 0;
    new_icmp->un.echo.id =18;
    new_icmp->un.echo.sequence =0;

    // Calculate checksum
    new_icmp->checksum= calculate_checksum((unsigned short *) (packet),header_size);

    /*************************************************************
          Given an IP packet, send it out using a raw socket.
    **************************************************************/

    //send the spoofed packet
    struct sockaddr_in new_ip_source, new_ip_dest;
    memset(&new_ip_source, 0, sizeof(new_ip_source));
    new_ip_source.sin_addr.s_addr = new_ip->saddr;

    //Provide needed info about destination
    memset(&new_ip_dest, 0, sizeof(new_ip_dest));
    new_ip_dest.sin_family = AF_INET;
    new_ip_dest.sin_addr.s_addr = new_ip->daddr;

    //create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    //set socket option
    int enable = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    //send the packet out

    if (sendto(sock, packet, sizeof(packet) , 0, (struct sockaddr *)&new_ip_dest, sizeof(new_ip_dest))< 0)
    {
        fprintf(stderr, "sendto() failed with error: %d", errno);

    }
    else{

        fprintf(output,"Sending spoofd IP packet...\n");
        fprintf(output,"\n\n***********************ICMP Packet*************************\n");

        fprintf(output,"\nIP Header\n");
        fprintf(output,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(new_ip->tot_len));
        fprintf(output,"   |-Source IP        : %s\n" , inet_ntoa(new_ip_source.sin_addr) );
        fprintf(output,"   |-Destination IP   : %s\n" , inet_ntoa(new_ip_dest.sin_addr) );

        fprintf(output,"\nICMP Header\n");
        fprintf(output,"   |-Type : %d",(unsigned int)(new_icmp->type));

        if((unsigned int)(new_icmp->type) == 11)
        {
            fprintf(output,"  (TTL Expired)\n");
        }
        else if((unsigned int)(new_icmp->type) == ICMP_ECHOREPLY)
        {
            fprintf(output,"  (ICMP Echo Reply)\n");
        }

        fprintf(output,"   |-Code : %d\n",(unsigned int)(new_icmp->code));
        fprintf(output,"   |-Checksum : %d\n",ntohs(new_icmp->checksum));

        fprintf(output,"\n###########################################################");
    }
    close(sock);

}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
    if (ip->protocol == IPPROTO_ICMP) //Check the Protocol and do accordingly...
    {
            send_reply_packet(ip);
            return;


    }

}


