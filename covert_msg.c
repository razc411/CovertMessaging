/*
  Covert Messaging through TCP HTTP
  By Ramzi Chennafi
*/

#include "covert_msg.h"

//switches
// eg -cip 192.168.0.1
//in process loop
// sndf filename - completetion message once done
// sndm message to send - completetion message once done
// recieve file or message - say processing incoming data, save to file (todo message v file mode)

char[16] communicator_addr;
memset(communicator_addr, 0, strlen(communicator_addr));

int main (int argc, char ** argv)
{
  initscr();

  struct sockaddr_in comm_addr;
  int listener_sock = create_listener();
  int csock = 0, commlen = 0;
  
  if(argc != 2){
      printf("requires a client ip argument in the form cmsg -cip '111.111.111.11'");
      exit(0);
  }
  else{
      communicator_addr = argv[1];
  }
  
  nodelay(stdscr, TRUE);
  
  while(1){  
    if(kbhit()){
      handle_command();
    }

    csock = accept4(listener_sock, (struct sockaddr *)&comm_addr, &commlen, SOCK_NONBLOCK);
    if(csock > 0){    
      //process connection
      csock = 0;
    }
    else if(errno == (EAGAIN || EWOULDBLOCK)) {
	csock = 0;
    }
    else {
      perror("Failure in accept4()");
      exit(0);
    }
  }
}

int kbhit(void)
{
    int ch = getch();

    if (ch != ERR) {
        ungetch(ch);
        return 1;
    } else {
        return 0;
    }
}

void handle_command()
{
  char[10] cmd, char[1000] csmg;
  scanf(%s%s, cmd, cmsg);
  if(strcmp(cmd, FILE_MSG_CMD)){
    intiate_session(FILE_FLAG, cmsg);
    printf("Sending file %s sneakily...", cmsg);
  }
  else if(strcmp(cmd, MSG_CMD) == 0){
    intiate_session(MSG_FLAG, cmsg);
    printf("Sending message %s sneakily...", cmsg);
  }
  else{
    printf("%s : is not a valid command, please use cmsg or fmsg", cmd);
  }
}

int create_listener()
{
   char buffer[256];
   struct sockaddr_in serv_addr, cli_addr;
   int  n, sockfd;
   
   /* First call to socket() function */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   
   if (sockfd < 0)
      {
      perror("ERROR opening socket");
      exit(1);
      }
   
   /* Initialize socket structure */
   bzero((char *) &serv_addr, sizeof(serv_addr));
   portno = 80;
   
   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);
   
   /* Now bind the host address using bind() call.*/
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
      {
      perror("ERROR on binding");
      exit(1);
      }

   listen(sockfd,5);
   
   return sockfd;
}

int post_covert_http()
{
  //loop, for each ack send new fragment of data in http post
}

int intiate_session(int mode, char * message)
{
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
     
  if(s == -1){
      //socket creation failed, may be because of non-root privileges
      perror("Failed to create socket");
      exit(1);
  }
    
  struct pseudo_packet pseudogram =  craft_packet(communicator_addr, "1.2.4.3", message);

  int one = 1;
  const int *val = &one;
     
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
      perror("Error setting IP_HDRINCL");
      exit(0);
  }
     
  while (1){
      if (sendto (s, pseudogram.datagram, pseudogram.ip_header->tot_len ,  0, (struct sockaddr *) pseudogram.sockaddr_in, sizeof (*pseudogram.sockaddr_in)) < 0){
	  perror("sendto failed");
      }
      else{
	  printf ("Packet Send. Length : %d \n" , pseudogram.ip_header->tot_len);
      }
  }
     
  return 0;
}

int intiate_session_server()
{
  //open socket for listening
  //crafted syn recieved, begin session
  //send synack
  //wait for ack,
  //send message
  //for each message part, send different http data, send part in etag
  //once complete, wait for more connections
}
 
struct pseudo_packet craft_packet(char * source, char * destination, char * message)
{
  char datagram[4096] , source_ip[32] , *data , *pseudogram;
     
  memset (datagram, 0, 4096);
     
  struct iphdr *iph = (struct iphdr *) datagram;
  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
  struct sockaddr_in sin;
  struct pseudo_header psh;
     
  data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
  strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
     
  strcpy(source_ip , source);
  sin.sin_family = AF_INET;
  sin.sin_port = htons(80);
  sin.sin_addr.s_addr = inet_addr (destination);
     
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
  iph->id = htonl (54321); //Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      //Set to 0 before calculating checksum
  iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
  iph->daddr = sin.sin_addr.s_addr;
     
  iph->check = csum ((unsigned short *) datagram, iph->tot_len);
     
  tcph->source = htons (1234);
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
  tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
  tcph->urg_ptr = 0;
     
  psh.source_address = inet_addr( source_ip );
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
