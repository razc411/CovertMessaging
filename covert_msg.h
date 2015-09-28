#include<stdio.h> //for printf
#include<string.h> //memset
#include<sys/socket.h>    //for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<unistd.h>
#include<netdb.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<net/ethernet.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#define BUFFER_SIZE 65536
#define TCP 6
#define IP_LEN 16
#define DATA_LEN 16
#define EOT 4

/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

struct pseudo_packet
{
  char * datagram;
  struct iphdr * ip_header;
  struct sockaddr_in * sockaddr_in;
};

int check_list(char * source);
char process_packet(unsigned char * buffer, int data_size, char * listener);
void recieve_message(char * listener);
void send_message(char * address, char * data);
const char * grab_random_addr();
void send_packet(char * address, int sockfd, char c);
struct pseudo_packet craft_packet(char * source, char * destination, char msg);

unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

