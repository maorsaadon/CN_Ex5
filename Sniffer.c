#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "header.h"


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *) packet;
    FILE *file;
    char my_id[20] = "318532421_305677494";
    char filename[28];
    snprintf(filename, sizeof(filename), "%s.txt", my_id);
    file = fopen(filename, "a"); // opening the file in append mode
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));
        if(ip->iph_protocol == IPPROTO_TCP){
            struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ethheader) + sizeof(struct ipheader));
            char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->iph_sourceip), source_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->iph_destip), dest_ip, INET_ADDRSTRLEN);
            fprintf(file, "{\n source_ip: %s\n dest_ip: %s\n source_port: %u\n dest_port: %u\n timestamp: %lu\n total_length: %u\n cache_flag: %u\n steps_flag: %u\n type_flag: %u\n status_code: %u\n cache_control: %u\n data: ", source_ip, dest_ip, ntohs(tcp->source), ntohs(tcp->dest), header->ts.tv_sec, header->len, 0, 0, 0, 0, 0);
//            printf( "{\n source_ip: %s\n dest_ip: %s\n source_port: %u\n dest_port: %u\n timestamp: %lu\n total_length: %u\n cache_flag: %u\n steps_flag: %u\n type_flag: %u\n status_code: %u\n cache_control: %u\n data: ", source_ip, dest_ip, ntohs(tcp->source), ntohs(tcp->dest), header->ts.tv_sec, header->len, 0, 0, 0, 0, 0);
            for (int i = 0; i < header->len; i++) {
                fprintf(file, "%02x", packet[i]);
//                printf("%02x", packet[i]);
            }
            fprintf(file, "\n}\n");
//            printf("\n}\n");
        }
    }
    fclose(file);
}
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp and portrange 10-100";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}










