/*
    Raw TCP packets
    Silver Moon (m00n.silv3r@gmail.com)
*/

#include "covert_msg.h"

/*
    Generic checksum calculation function
*/

int main (void)
{
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
     
    if(s == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }
    
    struct pseudo_packet pseudogram =  craft_packet("192.168.0.32", "1.2.4.3", 0);
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }
     
    while (1)
    {
      if (sendto (s, pseudogram.datagram, pseudogram.ip_header->tot_len ,  0, (struct sockaddr *) pseudogram.sockaddr_in, sizeof (*pseudogram.sockaddr_in)) < 0)
        {
            perror("sendto failed");
        }
        else
        {
            printf ("Packet Send. Length : %d \n" , pseudogram.ip_header->tot_len);
        }
    }
     
    return 0;
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
