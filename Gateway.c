#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include <arpa/inet.h>

#define PORT  50000
#define PORT_1  50001



void send_udp_packet(unsigned char *packet, int size , char *ip);

int sockAny , sockIp;
struct sockaddr_in receiver,sender;

int main(int argc , char *argv[])
{

    // Create socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockIp < 0) {
        perror("Error creating socket");
        return 1;
    }

    int receiverSize , dataSize;

    struct in_addr in;

    unsigned char *buffer = (unsigned char *)malloc(65536);



    printf("Starting the gateway process..\n");
    //Create a raw socket that shall sniff
    sockAny = socket(AF_INET , SOCK_DGRAM , 0);
    if(sockAny < 0)
    {
        printf("Socket Error\n");
        return 1;
    }

    receiver.sin_port = htons(PORT);
    receiver.sin_addr.s_addr = INADDR_ANY;
    receiver.sin_family = AF_INET;
    receiverSize = sizeof receiver;

    if (bind(sockAny, (struct sockaddr *) &receiver, receiverSize) < 0) {
        perror("Error binding socket to IP and port");
        return 1;
    }
    while(1)
    {

        printf("Receiving UDP packets\n");
        //Receive a packet
        dataSize = recvfrom(sockAny , buffer , 65536 , 0 , NULL , 0);
        if(dataSize <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        printf("Transfer the data to: %s\n" , argv[1]);
        double randomNum = ((float)random())/((float)RAND_MAX);
        if (randomNum > 0.5)
        {
            //Now process the packet
            send_udp_packet(buffer , dataSize , argv[1]);
            printf("The number is : %f ,congratulation! you packet will be transfer through the Gateway..\n" , randomNum);
            printf("The gateway transfer the packet.\n");
        }
        else{
            printf("The number is : %f ,sorry luck is not with you today, try again later!\n" , randomNum);
        }

    }
    close(sockAny);
    printf("Done");
    return 0;
}



void send_udp_packet(unsigned char *packet, int size , char *ip)
{

    printf("\n\n*******UDP Packet******\n");

    // Set the destination address
    memset(&sender, 0, sizeof(sender));
    sender.sin_family = AF_INET;
    sender.sin_port = htons(PORT_1);
    sender.sin_addr.s_addr = inet_addr(ip);


    if(sendto(sock_ip, packet, size , 0, (struct sockaddr *) &sender, sizeof(sender)) < 0){
        perror("Error with sendto() the packet\n");

    }
    printf("Succeed with send the packet!\n");
    return;
}