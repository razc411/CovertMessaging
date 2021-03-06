/*
  Covert Messaging through TCP
  By Ramzi Chennafi
  covert_msg.c
  
  Functions:

  int check_list(char * source);
  char process_packet(unsigned char * buffer, char * listener);
  void recieve_message(char * listener);
  void send_message(char * address, char * data);
  const char * grab_random_addr();
  void send_packet(char * address, int sockfd, char c);
  struct pseudo_packet craft_packet(char * source, char * destination, char msg);
  
  Contains main code bodies for the covert messaging program.

  Sends data between two points covertly by hiding it within the source port of SYN packets using raw socekts while 
  hiding from view by randomizing the source address for the SYNs.

  Using the program
     TO send a file type this at execution "covertsnd send [destination address] [filename]"
     TO recieve a file type this at execution "covertsnd listen [host address]"
  The program will terminate once message transfer is completed. The final message is saved to the file dump in
  the same directory as the program.

  Compiling the program
    TO compile the program execute the following on the main directory
      gcc *.c -o covertsnd
*/

#include "covert_msg.h"

/*
  Interface:
  int main(int argc, char ** argv)
  Arguments:
  int argc - number of arguments
  char ** argv - arguments
  Returns:
  int, 0 on program end
  
  About:
  The main body of argument. Either takes the program into sender or reciever mode. Also loads in the 
  ip listings for checking later.
*/

char ** ip_listing; // IP listing global variable
size_t size; // size of ip_listing

int main (int argc, char ** argv)
{
    size_t i;
    FILE *fp;
    char * line = NULL;
    size_t len, count = 0, read;
   
    if(argc < 2){
	printf("Requires either a send or listen command in the form\n -listen '192.19.1.1.'\n or \n -send '192.19.1.1 'message'");
	exit(0);
    }

    fp = fopen("ip_listing.txt", "r");
    if(!fp){
	perror("Failure to open listings");
	exit(1);
    }
  
    getline(&line, &len, fp);
    size = atoi(line);
    ip_listing =  malloc(size * sizeof(char*));
    for(i = 0; i < size; i++)
	ip_listing[i] = malloc(IP_LEN);
  
    while ((read = getline(&line, &len, fp)) != -1){
	strncpy(ip_listing[count++], line, strlen(line) - 1);
    }

    
    if (strcmp(argv[1], "listen") == 0){
	recieve_message(argv[2]);
    }
    else if(strcmp(argv[1], "send") == 0){
	send_message(argv[2], argv[3]);
    }
    else{
	printf("Requires either a send or listen command in the form\n -listen\n or \n -send");
    }

    for(i = 0; i < size; i++)
	free(ip_listing[i]);
    
    free(ip_listing);
    
    return 0;
}

/*
  Interface:
  void recieve_message(char * listener) 
  Arguments;
  char * listener - the address of the machine
  Returns:
  Nothing, void
   
  About:
  Sits in a loop waiting for incoming data from the sender. Returns when the message has been completely
  sent.
*/ 
void recieve_message(char * listener) 
{
    int serv_size , data_size, sockfd;
    struct sockaddr serv_addr;
    FILE *fp;
    unsigned char *buffer = (unsigned char *) malloc(BUFFER_SIZE);
    char msgbit;

    sockfd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
   
    if (sockfd < 0){
	perror("ERROR opening socket");
	exit(1);
    }

    fp = fopen("dump", "w");
    if(!fp){
	perror("Failed to open file");
	exit(1);
    }
  
    while(1){
     
	serv_size = sizeof(serv_addr);
	data_size = recvfrom(sockfd, buffer , BUFFER_SIZE, 0, &serv_addr, (socklen_t*)&serv_size);
     
	if(data_size < 0){
	    printf("recv , failed to get packets\n");
	    exit(2);
	}
	msgbit = process_packet(buffer, listener);
	if(msgbit == 0){
	  continue;
	}
	else if(msgbit == EOT || msgbit == -1){
	    break;
	}
	else{
	    fputc(msgbit, fp);
	    printf("%c", msgbit);
	}
    }
    
    fclose(fp);
    printf("Message recieved from %s and completed.\n", listener);
    close(sockfd);
}
/*
  Interface:
    int process_packet(unsigned char * buffer, char * listener)
  Arguments:
    unsigned char * buffer - the buffer containing the packet data
    char * listener - the ip of the host
  Returns:
    int, returns 0 when the packet doesnt belong to the message stream, returns the character
    from the source port if the packet is part of the stream.

  About:
    Processes incoming packets and retrieves each piece of data from the packets
    source port until the termination EOT packet is found.
*/
char process_packet(unsigned char * buffer, char * listener)
{
    char msgbit;
   
    struct iphdr *iph = (struct iphdr*)buffer;
    struct tcphdr * tcph = (struct tcphdr*)(buffer + sizeof(struct iphdr));
    char source_addr[IP_LEN];
    char dest_addr[IP_LEN];
    
    sprintf(source_addr, "%s",inet_ntoa(*(struct in_addr *)&iph->saddr));
    sprintf(dest_addr, "%s",inet_ntoa(*(struct in_addr *)&iph->daddr));
    
    if(iph->protocol == TCP && check_list(source_addr) && strcmp(dest_addr, listener) == 0 ){
    	msgbit = tcph->source;

	return msgbit;
    }
    
    return 0;
}
/*
  Interface:
    int check_list(char * source)
  Arguments:
    char * source - the source ip to check against
  Returns:
    int, 1 if the ip is in the list, 0 if it is not

  About:
    Checks if the source ip of the packet matches one on the list and returns the 
    corresponding int.
*/
int check_list(char * source)
{
    size_t i;
    for(i = 0; i < size; i++){
	if(strcmp(ip_listing[i], source) == 0)
	    return 1;
    }

    return 0;
}
/*
  Interface:
    void send_message(char * address, char * data)
  Arguments:
    char * address - the address to send the message to
    char * data - the filename to send
  Returns
    Nothing, void

  About:
    Sends a message a character at a time by hiding it in the source port of the tcp header.
    Sends SYN floods from a list of ips in random order. Also reads in the list of IPs to be used
    as false source ips.
*/
void send_message(char * address, char * data)
{    
    FILE *data_file;
    int n = 1;
    const int *val = &n;
    char ch;

    data_file = fopen(data, "r");
    if(!data_file){
	perror("Failure to open data file.");
	exit(1);
    }
  
    int sockfd = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
     
    if(sockfd == -1){
	perror("Failed to create socket");
	exit(1);
    }

    if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (n)) < 0){
	perror("Error setting IP_HDRINCL");
	exit(0);
    }
     
    while ((ch=fgetc(data_file)) !=EOF){
	send_packet(address, sockfd, ch);
	usleep(100000);
    }

    send_packet(address, sockfd, EOF);
    printf("Finished sending packets to %s, message completed.\n", address);
    close(sockfd);
    fclose(data_file);
}
/*
  Interface
    void send_packet(char* address, int sockfd, char c)
  Arguments
    char * address - the address to send to
    int sockfd - the socket to send through
    char c - the character to be sent
  Returns 
    nothing, void

  About
    Sends a packet to the specified address with the specified character using raw sockets.
*/
void send_packet(char * address, int sockfd, char c)
{
    struct pseudo_packet pseudogram =  craft_packet(ip_listing[rand() % (size-1)], address, c);
    
    if (sendto (sockfd, pseudogram.datagram, pseudogram.ip_header->tot_len ,  0, (struct sockaddr *) pseudogram.sockaddr_in, sizeof (*pseudogram.sockaddr_in)) < 0){
	perror("sendto failed");
    }
}
/*
  Interface:
    struct pseudo_packet craft_packet(char * source, char * destination, char msg)
  Arguments:
    char * source - the source to send packets from
    char * destination - the destination to send the packet to
    char msg - the character to insert into the source port of the tcp header
  Returns:
    struct pseudo_packet, a packet created for sending raw

  About:
    Crafts a false syn packet from an address to a destination to with a character
    from the message encoded in the source port.
*/
struct pseudo_packet craft_packet(char * source, char * destination, char msg)
{
    char datagram[4096] , source_ip[32] , *data , *pseudogram;
     
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
     
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data, "");

    strcpy(source_ip , source);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr (destination);
     
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
    iph->id = 0; 
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;     
    iph->saddr = inet_addr (source);    
    iph->daddr = sin.sin_addr.s_addr;
     
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    tcph->source = msg;
    tcph->dest = htons (80);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;  //tcp header size
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (8192); 
    tcph->check = 0; 
    tcph->urg_ptr = 0;
     
    psh.source_address = inet_addr(source);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
     
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    pseudogram = malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
     
    tcph->check = csum( (unsigned short*) pseudogram , psize);

    struct pseudo_packet packet_package;
    packet_package.datagram = &datagram;
    packet_package.ip_header = iph;
    packet_package.sockaddr_in = &sin;
    
    return packet_package;
}
