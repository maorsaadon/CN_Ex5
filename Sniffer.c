#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<arpa/inet.h> // for inet_ntoa()
#include "header.h"

#define PCAP_ERROR -1
#define SIZE_ETHERNET 14

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void print_packet_level(const u_char *Buffer, int Size);
void PrintData (const u_char * data , int Size);




int main()
{

    pcap_t *handle; /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    struct bpf_program fp; /* The compiled filter expression */
    char filter_exp[] = "proto TCP and dst port 9999 or src port 9999 or dst port 9998 or src port 9998"; /* The filter expression */
    char nameDevice[] = "lo"; /* Device to sniff on. loopback device-its name is lo. */
    bpf_u_int32 net;

    //Open live pcap session on NIC with name lo
    handle = pcap_open_live(nameDevice, BUFSIZ, 1, 1000, errbuf);

    //Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    //Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    //Close the handle
    pcap_close(handle);
    return 0;

}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    FILE *output;
    output = fopen("318532421_305677494.txt","a");
    if(output==NULL)
    {
        printf("Unable to create file.\n");
    }

    const struct eth_hdr *ethernet = (struct eth_hdr *)(packet); /* The ethernet header */

    const struct ip_hdr *iph = (struct ip_hdr *)(packet + SIZE_ETHERNET); /* The IP header */
    u_int iphdrlen = IP_HL(iph)*4;

    const struct tcp_hdr *tcph = (struct tcp_hdr*)(packet + iphdrlen + SIZE_ETHERNET); /* The TCP header */
    u_int tcphlen = TH_OFF(tcph)*4;



    fprintf(output , "\n\n***********************TCP Packet*************************\n");

    fprintf(output , "\n                        Packet Data                           \n\n");
    fprintf(output , "   |Packet Total Length    : %u Bytes\n",header->len);

    //IP Header
    fprintf(output , "\n                        IP Header                           \n");
    fprintf(output , "   |-Source IP             : %s\n" , inet_ntoa(iph->saddr) );
    fprintf(output , "   |-Destination IP        : %s\n" , inet_ntoa(iph->daddr) );
    fprintf(output , "\n");

    //TCP Header
    fprintf(output , "\n                        TCP Header                           \n\n");
    fprintf(output , "   |-Source Port           : %u\n",ntohs(tcph->source));
    fprintf(output , "   |-Destination Port      : %u\n",ntohs(tcph->dest));
    fprintf(output , "   |-Cache Flag            : %u\n",tcph->cache_flag);
    fprintf(output , "   |-Steps Flag            : %u\n",tcph->steps_flag);
    fprintf(output , "   |-Type Flag             : %u\n",tcph->type_flag);
    fprintf(output , "   |-Status Code           : %u\n",tcph->status_code);
    fprintf(output , "   |-Cache Control         : %u\n",ntohs(tcph->check));
    fprintf(output , "   |-Timestamp             : %u\n", ntohl(tcph->timestamp));
    fprintf(output , "\n                        DATA                           \n");

    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * header->len);
    if (!data)
    {
        return;
    }

    for (int i = 0; i < header->len; i++)
    {
        if (!(i & 15)){
            fprintf(output, "\n%04X: ", i);
        }
        fprintf(output, "%02X ", (uint8_t)data[i]);
    }

    fprintf(output, "\n");

    fprintf(output , "\n###########################################################");


    fclose(output);
}












