#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>

#include <errno.h>

#define PORT  50000
#define PORT_1  50001





struct sockaddr_in dest,server;

int main()
{

    // Create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Error creating socket");
        return 1;
    }


    memset(&server, 0, sizeof(server));

    dest.sin_family = AF_INET;
    dest.sin_port = htons(PORT);
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");
    // Bind socket to IP and port
//    if (bind(sock_ip, (struct sockaddr *) &server, sizeof(server)) < 0) {
//        perror("Error binding socket to IP and port");
//        return 1;
//    }
    char packet[] = "wonderfully world";
    int size = strlen(packet);

    if(sendto(sock, packet, size , 0, (struct sockaddr *) &dest, sizeof(dest)) < 0){
        perror("Error with sendto() the packet\n");

    }
    printf("UDP packet successfully sent!\n");
    close(sock);
    return 0;
}




