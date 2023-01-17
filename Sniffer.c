#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void print_packet_level(const u_char *Buffer, int Size);
void PrintData (const u_char * data , int Size);


FILE *output;
struct sockaddr_in source,dest;
int tcp=0,i,j;

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

    output=fopen("318532421_305677494.txt","w");
    if(output==NULL)
    {
        printf("Unable to create file.\n");
    }

    //Put the device in sniff loop
    pcap_loop(handle , -1 , got_packet , NULL);

    pcap_close(handle);

    printf("we catch total %d TCP packets\n", tcp );

    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    if (iph->protocol == IPPROTO_TCP)  //Check the Protocol and do accordingly...
    {
        ++tcp;
        print_packet_level(buffer , size);

    }
}

void print_packet_level(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    unsigned short iphdrlen =iph->ihl*4 ;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;


    fprintf(output , "\n\n***********************TCP Packet*************************\n");

    //IP Header
    fprintf(output , "\nIP Header\n");
    fprintf(output , "   |-IP Version            : %d\n",(unsigned int)iph->version);
    fprintf(output , "   |-IP Header Length      : %d WORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(output , "   |-Type Of Service       : %d\n",(unsigned int)iph->tos);
    fprintf(output , "   |-IP Total Length       : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(output , "   |-Identification        : %d\n",ntohs(iph->id));
    fprintf(output , "   |-TTL                   : %d\n",(unsigned int)iph->ttl);
    fprintf(output , "   |-Protocol              : %d\n",(unsigned int)iph->protocol);
    fprintf(output , "   |-Checksum              : %d\n",ntohs(iph->check));
    fprintf(output , "   |-Source IP             : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(output , "   |-Destination IP        : %s\n" , inet_ntoa(dest.sin_addr) );
    fprintf(output , "\n");

    //TCP Header
    fprintf(output , "TCP Header\n");
    fprintf(output , "   |-Source Port           : %u\n",ntohs(tcph->source));
    fprintf(output , "   |-Destination Port      : %u\n",ntohs(tcph->dest));
    fprintf(output , "   |-Sequence Number       : %u\n",ntohl(tcph->seq));
    fprintf(output , "   |-Acknowledge Number    : %u\n",ntohl(tcph->ack_seq));
    fprintf(output , "   |-Header Length         : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(output , "   |-Urgent Flag           : %d\n",(unsigned int)tcph->urg);
    fprintf(output , "   |-Acknowledgement Flag  : %d\n",(unsigned int)tcph->ack);
    fprintf(output , "   |-Push Flag             : %d\n",(unsigned int)tcph->psh);
    fprintf(output , "   |-Reset Flag            : %d\n",(unsigned int)tcph->rst);
    fprintf(output , "   |-Cache Flag            : %d\n",(unsigned int)tcph->syn);
    fprintf(output , "   |-Finish Flag           : %d\n",(unsigned int)tcph->fin);
    fprintf(output , "   |-Window                : %d\n",ntohs(tcph->window));
    fprintf(output , "   |-Checksum              : %d\n",ntohs(tcph->check));
    fprintf(output , "   |-Urgent Pointer        : %d\n",tcph->urg_ptr);
    fprintf(output , "   |-Timestamp             : %ld \n",(long)(tcph->th_x2));

    fprintf(output , "\n");
    fprintf(output , "                        DATA Dump                         ");
    fprintf(output , "\n");

    fprintf(output , "IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(output , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    fprintf(output , "Data Payload\n");
    PrintData(Buffer + header_size , Size - header_size );

    fprintf(output , "\n###########################################################");

}


void PrintData (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(output , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(output , "%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(output , "."); //otherwise print a dot
            }
            fprintf(output , "\n");
        }

        if(i%16==0) fprintf(output , "   ");
        fprintf(output , " %02X",(unsigned int)data[i]);

        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
                fprintf(output , "   "); //extra spaces
            }

            fprintf(output , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                    fprintf(output , "%c",(unsigned char)data[j]);
                }
                else
                {
                    fprintf(output , ".");
                }
            }

            fprintf(output ,  "\n" );
        }
    }
}












