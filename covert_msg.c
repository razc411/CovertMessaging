/*
  Covert Messaging through TCP
  By Ramzi Chennafi
  covert_msg.c
  
  Functions:

    int process_packet(unsigned char * buffer, int data_size, char * listener);
    void recieve_message(char * listener);
    void send_message(char * address, char * data);
    char * grab_random_addr(char ** ip_listing, int size);
    struct pseudo_packet craft_packet(char * source, char * destination, char msg);

  Contains main code bodies for the covert messaging program.

  Sends data between two points covertly by hiding it within the source port of SYN packets using raw socekts while hiding from view by
  randomizing the source address for the SYNs.
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
     The main body of argument. Either takes the program into sender or reciever mode.
*/
int main (int argc, char ** argv)
{
  struct sockaddr_in comm_addr;
  int listener_sock = create_listener();
  int csock = 0, commlen = 0;
  
  if(argc != 2){
      printf("Requires either a send or listen command in the form\n -listen '192.19.1.1.'\n or \n -send '192.19.1.1 'message'");
      exit(0);
  }
  
  if (strcmp(argv[1], "listen")){
    recieve_message(argv[2]);
  }
  else if(strcmp(argv[1], "send")){
    send_message(argv[2], argv[3]);
  }
  else{
    printf("Requires either a send or listen command in the form\n -listen\n or \n -send");
  }
  
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
   int serv_size , data_size, sockfd, n;
   struct sockaddr serv_addr;
   unsigned char *buffer = (unsigned char *) malloc(BUFFER_SIZE);
   
   sockfd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
   
   if (sockfd < 0){
     perror("ERROR opening socket");
     exit(1);
   }
   
   while(1){
     
     serv_size = sizeof(serv_addr);
     data_size = recvfrom(sockfd, buffer , BUFFER_SIZE, 0, &saddr, (socklen_t*)&saddr_size);
     
     if(data_size < 0){
       printf("recv , failed to get packets\n");
       exit(2);
     }
     
     if(!process_packet(buffer, data_size, listener))
       break;
   }
   
   printf("Message recieved from %s and completed.", listener);
   close(sockfd);
}
/*
  Interface:
    int process_packet(unsigned char * buffer, int data_size, char * listener)
  Arguments:
    unsigned char * buffer - the buffer containing the packet data
    int data_size - the size of the buffer
    char * listener - the ip of the host
  Returns:
    int, returns 0 when the last packet has been found and 1 when it hasn't.

  About:
    Processes incoming packets and retrieves each piece of data from the packets
    source port until the termination EOT packet is found.
*/
int process_packet(unsigned char * buffer, int data_size, char * listener)
{
  char msgbit;
  FILE *fp;
  fp = fopen("dump", "w");
  if(!fp){
    perror("Failed to open file");
    exit(1);
  }
  
  struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
  struct tcphdr * tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
  char source_addr[IP_LEN], dest_addr[IP_LEN];
 
  snprintf(source_addr, IP_LEN, "%pI4", &iph->saddr);
  snprintf(dest_addr, IP_LEN, "%pI4", &ip_header->daddr);

  if(iph->protocol == TCP && check_list(source_addr) && strcmp(dest_addr, listener) == 0 ){
    
    msgbit = tcph->source;

    if(tcph->source == EOT){
      return 0;
      close(fp);
    }
    
    fprintf(fp,"%c", msgbit);
  }

  return 1;
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
  FILE *fp, *data_file;
  int n = 1, count = 1;
  const int *val = &n;
  char * line = NULL;
  size_t len = 0, read;
  char ch;

  fp = fopen("ip_listing.txt", "r");
  if(!fp){
    perror("Failure to open listings");
    exit(1);
  }

  data_file = fopen(data, "r");
  if(!data_file){
    perror("Failure to open data file.");
    exit(1);
  }
  
  getline(&line, &len, fp);
  int size = atoi(line);
  char ip_listing[size][IP_LEN];
  
  while ((read = getline(&line, &len, fp)) != -1){
     ip_listing[count++] == line;
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
    struct pseudo_packet pseudogram =  craft_packet(address, grab_random_addr(ip_listing, size), ch);
    
    if (sendto (sockfd, pseudogram.datagram, pseudogram.ip_header->tot_len ,  0, (struct sockaddr *) pseudogram.sockaddr_in, sizeof (*pseudogram.sockaddr_in)) < 0){
      perror("sendto failed");
    }
    else{
      printf ("Packet Send. Length : %d \n" , pseudogram.ip_header->tot_len);
    }
    
    usleep(10000);
  }
     
  return 0;
}

/*
  Interface 
    char * grab_random_addr(char ** ip_listing, int size)
  Arguments:
    char ** ip_listing - the list of ips to choose
    int size - the size of the ip list
  Returns:
    char *, the IP that was chosen.

  About:
    Grabs a random ip address from the IP listing array and returns it.
*/
char * grab_random_addr(char ** ip_listing, int size)
{
  int n;
  time_t t;
  srand((unsigned) time(&t));
  
  return ip_listing[rand() % size];
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
  
  char temp[3];
  temp[0] = *message
  temp[1] = *message + 1;
  temp[2] = *message + 2;
  
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
  tcph->window = htons (5840); /* maximum allowed window size */
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
