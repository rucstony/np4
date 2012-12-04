#include  "unp.h"
#include <netinet/ip.h>
#include    "ping.h"
#include "hw_addrs.h"
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#define ETH_FRAME_LEN 1514
#define IDENTIFIER 72217
#define MAX_PAYLOAD_SIZE 1500
#define USID_PROTO 0x4481  
#define HOSTNAME_LEN 255

struct proto proto_v4 = { proc_v4, send_v4, NULL, NULL, NULL, 0, IPPROTO_ICMP };
int pg_sock, packet_socket, if_index ;

char  source_hw_mac_address[6], destination_hw_mac_address[6], source_ip_address[INET_ADDRSTRLEN], destination_ip_address[INET_ADDRSTRLEN];


struct payload
{
    char IPaddress_list[MAX_PAYLOAD_SIZE];
    int last_visited_index;
};

void readloop()
{
    int             size;
    char            recvbuf[BUFSIZE];
    char            controlbuf[BUFSIZE];
    struct msghdr   msg;
    struct iovec    iov;
    ssize_t         n;
    struct timeval  tval;


    size = 60 * 1024;       /* OK if setsockopt fails */
    setsockopt(pg_sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    sig_alrm(SIGALRM);      /* send first packet */

    iov.iov_base = recvbuf;
    iov.iov_len = sizeof(recvbuf);
    msg.msg_name = pr->sarecv;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = controlbuf;
    for ( ; ; ) {
        msg.msg_namelen = pr->salen;
        msg.msg_controllen = sizeof(controlbuf);
        n = recvmsg(pg_sock, &msg, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            else
                err_sys("recvmsg error");
        }

        Gettimeofday(&tval, NULL);
        proc_v4(recvbuf, n, &msg, &tval);
    }
}

void proc_v4(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv)
{
    int             hlen1, icmplen;
    double          rtt;
    struct ip       *ip;
    struct icmp     *icmp;
    struct timeval  *tvsend;

    ip = (struct ip *) ptr;     /* start of IP header */
    hlen1 = ip->ip_hl << 2;     /* length of IP header */
    if (ip->ip_p != IPPROTO_ICMP)
        return;             /* not ICMP */

    icmp = (struct icmp *) (ptr + hlen1);   /* start of ICMP header */
    if ( (icmplen = len - hlen1) < 8)
        return;             /* malformed packet */

    if (icmp->icmp_type == ICMP_ECHOREPLY) {
        if (icmp->icmp_id != pid)
            return;         /* not a response to our ECHO_REQUEST */
        if (icmplen < 16)
            return;         /* not enough data to use */

        tvsend = (struct timeval *) icmp->icmp_data;
        tv_sub(tvrecv, tvsend);
        rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

        printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
                icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
                icmp->icmp_seq, ip->ip_ttl, rtt);

    } else if (verbose) {
        printf("  %d bytes from %s: type = %d, code = %d\n",
                icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
                icmp->icmp_type, icmp->icmp_code);
    }
}

void send_v4(void)
{
    int         len;
    struct icmp *icmp;

    icmp = (struct icmp *) sendbuf;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = pid;
    icmp->icmp_seq = nsent++;
    memset(icmp->icmp_data, 0xa5, datalen); /* fill with pattern */
    Gettimeofday((struct timeval *) icmp->icmp_data, NULL);

    len = 8 + datalen;      /* checksum ICMP header and data */
   // icmp->icmp_cksum = 0;
   // icmp->icmp_cksum = in_cksum((u_short *) icmp, len);
    sendPingPacket( packet_socket ,icmp, source_hw_mac_address, destination_hw_mac_address , if_index , source_ip_address, destination_ip_address);

    //Sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

void sig_alrm(int signo)
{
    send_v4();

    alarm(1);
    return;
}


/*
  Retrieve the destination canonical IP address in presentation format. 
*/

int retrieveDestinationCanonicalIpPresentationFormat(const char *server_vm, char *destination_canonical_ip_presentation_format)
{
  struct hostent *hptr;
  char *ptr, **pptr;
  if((hptr=gethostbyname(server_vm))==NULL)
  {
    err_msg("gethostbyname error for host: %s : %s",server_vm,hstrerror(h_errno));
    return -1;
  }
  if(hptr->h_addrtype==NULL)
  {
    fprintf(stderr,"Invalid IP address\n");
    return -1;
  }
  printf("Address type: ....%ld\n",hptr->h_addrtype);

  switch(hptr->h_addrtype)
  {
    case AF_INET:
    //printf("AF_INET type");

    pptr=hptr->h_addr_list;
    if(pptr!=NULL)
    {
      inet_ntop(hptr->h_addrtype,*pptr,destination_canonical_ip_presentation_format,100);
     // printf("Destination canonical IP in presentation format: %s\n", destination_canonical_ip_presentation_format);
      return 1;
    }
    break;

    default:
    fprintf(stderr,"unknown address type\n");
    return -1;
    break;
  }
}

void retrieveOwnCanonicalIPAddress( char * IPaddress )  
{
    char own_vm_name[HOSTNAME_LEN];   
    gethostname( own_vm_name, sizeof(own_vm_name) );
    retrieveDestinationCanonicalIpPresentationFormat(own_vm_name, IPaddress);      
    return;
}

/*
    Stores the IP addresses of the vm-tour in a comma-separated string to be passed as payload to the tour-members.
*/
int createIPTourString( char * IPaddress_list, char *argv[], char * IPmulticast_address, int port)
{
    int i;
    char IPaddress[INET_ADDRSTRLEN];
    char own_vm_name[HOSTNAME_LEN];
    /* Return the current node's eth0 interface's IP address. */
    gethostname( own_vm_name, sizeof(own_vm_name) );
    retrieveDestinationCanonicalIpPresentationFormat(own_vm_name, IPaddress_list);      

    if( strcmp(argv[1], own_vm_name) == 0 )
    {
        return -1;
    }    
        
    for( i=1; argv[i] != NULL; i++ )
    {
        /* Subsequent nodes should not be same. */
        if( strcmp(argv[i], argv[i-1]) == 0 )
        {
            return -1;
        }     
        retrieveDestinationCanonicalIpPresentationFormat( argv[i], IPaddress );
        strcat(IPaddress_list, "|");
        strcat(IPaddress_list, IPaddress);
    }   
    return 1;
}

struct payload * createPayload( char * IPaddress_list )
{
    struct payload * p = (struct payload *)malloc( sizeof(struct payload) );
    strcpy(p->IPaddress_list, IPaddress_list);
    p->last_visited_index = 0;
    return p;
}

/*
    last_visited_index = 0 when starting from source. 
        incremented when at each node of the tour. 
*/
char * retrieveNextTourIpAddress( char * IPaddress_list, int last_visited_index )
{
    int i;
    char * p;

    p = strtok( IPaddress_list,"|" );
 //   if( last_visited_index == -1 )
  //  {
   //     return p;
   // }    
    for(i=0;i<=last_visited_index;i++)
    {
        printf("%s\n",p );
        p = strtok( NULL,"|" );         
    }    
    printf("Next IP address to be sent to : %s\n", p);
    return p;
}

/*
    Retrieves the Multicast address and port number from the string. 
*/
int retrieveMulticastIpAddress( char * IPaddress_list )
{
    int i;
    char * p,* prev, * port;

    p = strtok( IPaddress_list,"|" );

    while( p != NULL )
    {
        prev = p;
        p = strtok( NULL,"|" );         
    }    
    p = strtok(prev,":");
    port = atoi( strtok(NULL, ":") );

    printf("Multicast Address to  : %s\n", prev);
    printf("Port number : %d\n", port );
    return 1;
}

void sendTourPacket( int sockfd, struct payload * p, char * destination_address, char * source_address )
{
    struct ip       *ip;
    char            sendbuf[BUFSIZE];
    size_t          len;
    socklen_t       servlen;
    struct sockaddr_in servaddr;

    /* Pointer to beginning of payload */
    char * data = sendbuf+20; 
  
    ip = (struct ip *) sendbuf;     /* start of IP header */
    ip->ip_p = htons(IPPROTO_ICMP);
    ip->ip_id = htons(IDENTIFIER);
    ip->ip_sum = htons(0);
    inet_aton(source_address, &ip->ip_src);
    inet_aton(destination_address, &ip->ip_dst);
        
    memcpy( (void *)data,(void *)p,sizeof(*p) ); 
    len = sizeof(sendbuf);

    bzero( &servaddr, sizeof( servaddr ) );
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons( 61616 );
    inet_pton( AF_INET, destination_address, &servaddr.sin_addr );
    
    servlen = sizeof(servaddr);

    printf("Sending tour packet to %s from source : %s \n", destination_address, source_address);
    Sendto(sockfd, sendbuf, len, 0, &servaddr, servlen);
    printf("DONE SENDINGS WOOOO.\n");

}


/*
    
The definition of struct ip_mreq is as follows:

    struct ip_mreq 
    {
        struct in_addr imr_multiaddr; 
        struct in_addr imr_interface; 
    }
*/
int joinMulticastGroup( int sock, char * multicast_ip_address, char * joining_local_interface_ip_address )
{
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr =  inet_addr( multicast_ip_address );
    mreq.imr_interface.s_addr = inet_addr( joining_local_interface_ip_address );
 
    if( setsockopt(sock,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq)) == -1 )
    {
        printf("Unable to join multicast group.. Error code : %d\n", errno );
        return  0;
    }       

    return 1;
}

void sendPingPacket( int s , struct icmp * populated_icmp_frame , char * source_hw_mac_address, char * destination_hw_mac_address , int if_index ,char * source_ip_address, char * destination_ip_address)
{
    
    int j,i;
    /*target address*/
    struct sockaddr_ll socket_address;

    /*buffer for ethernet frame*/
    void* buffer = (void*)malloc(ETH_FRAME_LEN);
     
    /*pointer to ethenet header*/
    unsigned char* etherhead = buffer;

    /*pointer to ethenet header*/
    unsigned char* iphead = buffer + 14;
        
    /*pointer to userdata in ethernet frame*/
    unsigned char* data = buffer + 34;
        
    /*another pointer to ethernet header*/
    struct ethhdr *eh = (struct ethhdr *)etherhead;
     
/*another pointer to ethernet header*/
    struct ip *iph = (struct ip *)iphead;
    

    int send_result = 0,k=0;

    /*our MAC address*/
    unsigned char src_mac[6], dest_mac[6]; 

    char * src_mac1=source_hw_mac_address; 
    char * dest_mac1=destination_hw_mac_address; 


//  unsigned char src_mac[6] = {0x00, 0x0c, 0x29, 0x11, 0x58, 0xa2};
    
    /*Broadcast MAC address*/
    //unsigned char dest_mac[6] = {0x00, 0x0c, 0x29, 0x24, 0x8f, 0x70};
    //unsigned char dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    i = IF_HADDR;
    printf("\n\nSending Ping Packet to  \n\t Destination H/W Address :\n");
    do 
    {   
        dest_mac[k] = *destination_hw_mac_address++ & 0xff;
        k++;
        printf("%.2x%s", *dest_mac1++ & 0xff, (i == 1) ? " " : ":");
    } while (--i > 0);
    printf("\n");
    

    printf("\tsending frame on socket: %d\n",s );
    //printf("\tpopulated_odr_frame: %d bytes.\n",sizeof(*populated_odr_frame));
    /*prepare sockaddr_ll*/
    
    printf("\t Source H/W Address :\n");
    i = IF_HADDR;
    k=0;
    do 
    {   
        src_mac[k] = *source_hw_mac_address++ & 0xff;
        k++;
        printf("%.2x%s", *src_mac1++ & 0xff, (i == 1) ? " " : ":");
    } while (--i > 0);


    /*RAW communication*/
    socket_address.sll_family   = PF_PACKET;    
    /*we don't use a protocoll above ethernet layer
      ->just use anything here*/
    socket_address.sll_protocol = htons(ETH_P_IP);  

    /*ARP hardware identifier is ethernet*/
    socket_address.sll_hatype   = ARPHRD_ETHER;
        
    /*target is another host*/
    socket_address.sll_pkttype  = PACKET_OTHERHOST;

    /*index of the network device
    see full code later how to retrieve it*/
    socket_address.sll_ifindex  = if_index;

    /*address length*/
    socket_address.sll_halen    = ETH_ALEN;     

    printf("Before socket_address..\n");    
    /*MAC - begin*/
    socket_address.sll_addr[0]  = dest_mac[0];      
    socket_address.sll_addr[1]  = dest_mac[1];      
    socket_address.sll_addr[2]  = dest_mac[2];
    socket_address.sll_addr[3]  = dest_mac[3];
    socket_address.sll_addr[4]  = dest_mac[4];
    socket_address.sll_addr[5]  = dest_mac[5];
    /*MAC - end*/
    socket_address.sll_addr[6]  = 0x00;/*not used*/
    socket_address.sll_addr[7]  = 0x00;/*not used*/

    /*set the frame header*/
    memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
    memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
    eh->h_proto = htons(USID_PROTO);

    //fill ip header
    iph->ip_id=htons(IDENTIFIER);
    iph->ip_p=htons(IPPROTO_ICMP);
    iph->ip_hl=htons(20);
    iph->ip_sum=htons(0);
    inet_aton(source_ip_address, &iph->ip_src);
    inet_aton(destination_ip_address, &iph->ip_dst);
    /*fill the frame with some datip_src,a*/
    memcpy((void*)data,(void*)populated_icmp_frame, sizeof( struct icmp ));

    printf("Just before send.. \n");
    /*send the packet*/
    send_result = sendto(s, buffer, ETH_FRAME_LEN, 0, 
              (struct sockaddr*)&socket_address, sizeof(socket_address));
    if (send_result == -1){ perror("sendto"); }
    printf("Done sending..WOO\n");
}

void recievePacketFromRTSock(int rt_sock)
{
    struct sockaddr rtaddr;
    int rtlen, n;
    void* buffer = (void*)malloc(BUFSIZE); 
    rtlen = sizeof( struct sockaddr );    


    if((n=recvfrom(rt_sock,buffer, BUFSIZE, 0, &rtaddr, &rtlen)>0))
    {
        printf("Recieved %d bytes from whoever..\n",n );
    } 
    return;   
}

void recievePacketFromPGSock(int pg_sock)
{
    struct sockaddr pgaddr;
    int pglen,n;
    
    void* buffer = (void*)malloc(BUFSIZE); 
    pglen = sizeof( struct sockaddr );   

    if((n=recvfrom(pg_sock,buffer, BUFSIZE, 0, &pgaddr, &pglen)>0))
    {
        printf("Recieved %d bytes from whoever..\n",n );
    } 
    return;   
}

int main(int argc, char const *argv[])
{
    int   rt_sock,  iptour_return, maxfd;
    const int   on = 1;
    char IPaddress_list[MAX_PAYLOAD_SIZE], IPmulticast_address[INET_ADDRSTRLEN] = "239.108.175.37", host[INET_ADDRSTRLEN];
    char source_address[INET_ADDRSTRLEN];
    int port_number = 17537;
    fd_set          rset;
    int             c, nready;
    struct addrinfo *ai;
    char *h;
    int datalen = 56;
    struct payload * p;
    char * destination_address;

    if((packet_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP) ) )==-1)
    {
        printf("Error in creation of socket for PF_PACKET\n");
        perror("socket");
        return 0;
    }
 
    if((rt_sock = socket(AF_INET, SOCK_RAW, IDENTIFIER))==-1)
    {
        printf("Error in creation of IP raw socket.rt_sock\n");
        perror("socket");
        return;
        
    }
    if((pg_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))==-1)
    {
        printf("Error in creation of IP raw socket.pg_sock\n");
        perror("socket");
        return;
        
    }

    /* Setting the socket options to IP_HDRINCL */ 
    if( setsockopt( rt_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1 )
    {
        printf("Unable to set socket to SO_REUSEADDR. Error code : %d\nExiting..\n", errno );
    }       
    
    if( argc > 1 )
    {    
        if( createIPTourString(IPaddress_list, argv, IPmulticast_address, port_number) == -1 )
        {
            printf("Error : Same node should not appear consequentively in the tour list..Exiting..\n");
            exit(1);
        }    
        else
            printf("\nIP Tour List : %s\n",IPaddress_list);
        
        p = createPayload( IPaddress_list );
        retrieveOwnCanonicalIPAddress( source_address );
        destination_address =  retrieveNextTourIpAddress(IPaddress_list,0);
        sendTourPacket( rt_sock, p, destination_address,source_address );

    }    

//    exit(0); 
       
    printf("<time>   received source routing packet from <hostname>.\n");

    FD_ZERO( &rset );
    maxfd = max( pg_sock, rt_sock );
   // maxfd = max( maxfd, pg_sock ) + 1;

    for ( ; ; ) 
    {
         //   FD_SET( packet_socket, &rset );
            FD_SET( rt_sock, &rset );
            FD_SET( pg_sock, &rset );

            if( ( nready = select( maxfd, &rset, NULL, NULL, NULL ) ) < 0 )
            {
                    if( errno == EINTR )
                    {
                            fputs("Encountered EINTR.. retrying..\n", stdout);
                            continue;
                    }       
                    else
                    {
                            fputs("Select call failed..Exiting..\n", stdout);
                            exit(1);
                    }
            }       

 //           if ( FD_ISSET(packet_socket, &rset)  ) 
   //         {
     //          printf("What the crap is this shit doing here ? \n");     
       //     }
            else if( FD_ISSET(rt_sock, &rset) )
            {
                printf("Recieving packet from rt_sock..\n");
                recievePacketFromRTSock(rt_sock);
            }   
            else if( FD_ISSET(pg_sock, &rset) )
            {
                printf("Recieving packet from pg_sock..\n");
                recievePacketFromPGSock(pg_sock);
            } 

    }

    //pinging**************************
    

   strcpy(host, "192.168.1.101");

    pid = IDENTIFIER & 0xffff;  /* ICMP ID field is 16 bits */
    Signal(SIGALRM, sig_alrm);

    ai = Host_serv(host, NULL, 0, 0);

    h = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
    printf("PING %s (%s): %d data bytes\n",
            ai->ai_canonname ? ai->ai_canonname : h,
            h, datalen);

        /* 4initialize according to protocol */
    if (ai->ai_family == AF_INET) 
    {
        pr = &proto_v4;

    } 
    else
        err_quit("unknown address family %d", ai->ai_family);

    pr->sasend = ai->ai_addr;
    pr->sarecv = Calloc(1, ai->ai_addrlen);
    pr->salen = ai->ai_addrlen;
    pr->icmpproto = IPPROTO_ICMP;
    readloop();





    //pinging**************************

}

/*
Tour application module specifications

    The application will create a total of four sockets: two IP raw sockets, a PF_PACKET socket and a UDP socket for multicasting.

        We shall call the two IP raw sockets the ‘rt ’ (‘route traversal’) and ‘pg ’ (‘ping’) sockets, respectively. 
        The rt socket should have the IP_HDRINCL option set. You will only be receiving ICMP echo reply messages 
        through the pg socket (and not sending echo requests), so it does not matter whether it has the IP_HDRINCL option set or not.

        The pg socket should have protocol value (i.e., protocol demultiplexing key in the IP header) IPPROTO_ICMP.

        The rt socket should have a protocol value that identifies the application - i.e., some value other than
        the IPPROTO_XXXX values in  /usr/include/netinet/in.h. However, remember that you will all be running your
        code using the same root account on the vm1 , . . . . . , vm10 nodes. So if two of you happen to choose 
        the same protocol value and happen to be running on the same vm node at the same time, your applications
        will receive each other’s IP packets. For that reason, try to choose a protocol value for your rt socket
        that is likely to be unique to yourself.

        The PF_PACKET socket should be of type SOCK_RAW (not SOCK_DGRAM). This socket should have a protocol value
        of  ETH_P_IP = 0x0800 (IPv4).

        The UDP socket for multicasting will be discussed below. Note that, depending on how you choose to bind that
        socket, you might actually need to have two UDP sockets for multicast communication – see bottom of  p. 576, Section 21.10.

    Your application will, of course, have to be running on every vm node that is included in the tour.

        When evoking the application on the source node, the user supplies a sequence of vm node names 
        (not IP addresses) to be visited in order. This command line sequence starts with the next node
        to be visited from the source node (i.e., it does not start with the source node itself). 
        The sequence can include any number of repeated visits to the same node. For example, suppose 
        that the source node is vm3 and the executable is called badr_tour :

        [root@vm3/root]# badr_tour vm2 vm10 vm4 vm7 vm5 vm2 vm6 vm2 vm9 vm4 vm7 vm2 vm6 vm5 vm1 vm10 vm8

        (but note that the tour does not necessarily have to visit every vm node; and the same node should not
        appear consequentively in the tour list – i.e., the next node on the tour cannot be the current node itself).

        The application turns the sequence into a list of IP addresses for source routing. It also adds the IP 
        address of the source node itself to the beginning of the list. The list thus produced will be carried 
        as the payload of an IP packet, not as a SSRR option in the packet header. It is our application which
        will ensure that every node in the sequence is visited in order, not the IP SSRR capability.

        The source node should also add to the list an IP multicast address and a port number of its choice.
        It should also join the multicast group at that address and port number on its UDP socket. 
        The TTL for outgoing multicasts should be set to 1.

        The application then fills in the header of an IP packet, designating itself as the IP source, and the next node to be visited as the IP destination. The packet is sent out on the rt socket. Note that on Linux, all the fields of the packet header must be in network byte order (Stevens, Section 28.3, p. 737, the fourth bullet point).

        When filling in the packet header, you should explicitly fill in the identification field (recall that, with the IP_HDRINCL socket option, if the identification field is given value 0, then the kernel will set its value). Try to make sure that the value you choose is likely to be unique to yourself (for reasons similar to those explained with respect to the IPPROTO_XXXX in 1. above).

    When a node receives an IP packet on its rt socket, it should first check that the identification field carries the right value (this implies that you will hard code your choice of identification field value determined in item 2 above in your code). If the identification field value does not check out, the packet is ignored. For a valid packet :

        Print out a message along the lines of:

                <time>   received source routing packet from <hostname>

        <time> is the current time in human-readable format (see lines 19 & 20 in Figure 1.9,  p. 14, and the corresponding explanation on  p. 14f.), and <hostname> is the host name corresponding to the source IP address in the header of the received packet.

        If this is the first time the node is visited, the application should use the multicast address and port number in the packet received to join the multicast group on its UDP socket. The TTL for outgoing multicasts should be set to 1.

        The application updates the list in the payload, so that the next node in the tour can easily identify what the next hop from itself will be when it receives the packet. How you do this I leave up to you. You could, for example, include as part of the payload a pointer field into the list of nodes to be visited. This pointer would then be updated to the next entry in the list as the packet progresses hop by hop (see Figure 27.1 and the associated explanation on  pp. 711-712). Other solutions are, of course, possible. The application then fills in a new IP header, designating itself as the IP source, and the next node to be visited as the IP destination. The identification field should be set to the same value as in the received packet. The packet is sent out on the rt socket.

        The node should also initiate pinging to the preceding node in the tour (the IP address of which it should pick up from the header of the received packet). However, unlike the Stevens ping code, it will be using the SOCK_RAW-type PF_PACKET socket of item 1 above to send the ICMP echo request messages.

        Before it can send echo request messages, the application has to call on the ARP module you will implement to get the Ethernet address of this preceding / ‘target’ node; this call is made using the API function areq which you will also implement (see sections ARP module specifications & API specifications below). Note that ARP has to be evoked every time the application wants to send out an echo request message, and not just the first time.

        An echo request message has to be encapsulated in a properly-formulated IP packet, which is in turn encapsulated in a properly-formulated Ethernet frame transmitted out through the PF_PACKET socket ;  otherwise, ICMP at the source node will not receive it. You will have to modify Stevens’ ping code accordingly, specifically, the send_v4 function. In particular, the Ethernet frame must have a value of  ETH_P_IP = 0x0800 (IPv4 – see <linux/if_ether.h>) in the frame type / ‘length’ field ;  and the encapsulated IP packet must have a value of  IPPROTO_ICMP = 0x01 (ICMPv4 – see <netinet_in.h>) in its protocol field.

        You should also simplify the ping code in its entirety by stripping all the ‘indirection’ IPv4 / IPv6 dual-operability paraphernalia and making the code work just for IPv4. Also note that the functions host_serv and freeaddrinfo, together with the associated structure addrinfo (see Sections 11.6, 11.8 & 11.11), in Figures 27.3, 27.6 & 28.5 ( pp. 713, 716 & 744f., respectively) can be replaced by the function gethostbyname and associated structure hostent (see Section 11.3) where needed. Also, there is no ‘-v’ verbose option, so this too should be stripped from Stevens’ code.

        When a node is ready to start pinging, it first prints out a ‘PING’ message similar to lines 32-33 of Figure 28.5,  p. 744. It then builds up ICMP echo request messages and sends them to the source node every 1 second through the PF_PACKET socket. It also reads incoming echo response messages off the pg socket, in response to which it prints out the same kind of output as the code of Figure 28.8,  p. 748.

        If this node and its preceding node have been previously visited in that order during the tour, then pinging would have already been initiated from the one to the other in response to the first visit, and nothing further should nor need be done during second and subsequent visits.

        In light of the above, note that once a node initiates pinging, it needs to read from both its rt and pg sockets, necessitating the use of the select function. As will be clear from what follows below, the application will anyway be needing also to simultaneously monitor its UDP socket for incoming multicast datagrams.

    When the last node on the tour is reached, and if this is the first time it is visited, it joins the multicast group and starts pinging the preceding node (if it is not already doing so). After a few echo replies are received (five, say), it sends out the multicast message below on its UDP socket (i.e., the node should wait about five seconds before sending the multicast message) :

    <<<<< This is node vmi .  Tour has ended .  Group members please identify yourselves. >>>>>

    where vmi is the name (not IP address) of the node. The node should also print this message out on stdout preceded, on the same line, by the phrase:

    Node vmi .  Sending: <then print out the message sent>.

            Each node vmj receiving this message should print out the message received preceded, on the same line, by the phrase:

            Node vmj .  Received <then print out the message received>.

            Each such node in step a above should then immediately stop its pinging activity.

            The node should then send out the following multicast message:

                    <<<<< Node vmj .  I am a member of the group. >>>>>

            and print out this message preceded, on the same line, by the phrase:

            Node vmj .  Sending: <then print out the message sent>.

            Each node receiving these second multicast messages (i.e., the messages that nodes – including itself – sent out in step c above) should print each such message out preceded, on the same line, by the phrase:

            Node vmk .  Received: <then print out the message received>.

            Reading from the socket in step d above should be implemented with a 5-second timeout. When the timeout expires, the node should print out another message to the effect that it is terminating the Tour application, and gracefully exit its Tour process.

            Note that under Multicast specifications, the last node in the tour, which sends out the End of Tour message, should itself receive a copy of that message and, when it does, it should behave exactly as do the other nodes in steps a. – e. above.

ARP module specifications

Your executable is evoked with no command line arguments. Like the Tour module, it will be running on every vm node.

    It uses the get_hw_addrs function of Assignment 3 to explore its node’s interfaces and build a set of  <IP address , HW address>  matching pairs for all eth0 interface IP addresses (including alias IP addresses, if any).

    Write out to stdout in some appropriately clear format the address pairs found.

    The module creates two sockets: a PF_PACKET socket and a Unix domain socket.

        The PF_PACKET should be of type SOCK_RAW (not type SOCK_DGRAM) with a protocol value of your choice (but not one of the standard values defined in <linux/if_ether.h>) which is, hopefully, unique to yourself. This value effectively becomes the protocol value for your implementation of ARP. Because this protocol value will be carried in the frame type / ‘length’ field of the Ethernet frame header (see Figure 4.3 of the ARP & RARP handout), the value chosen should be not less than 1536 (0x600) so that it is not misinterpreted as the length of an Ethernet 802.3 frame.

        The Unix domain socket should be of type SOCK_STREAM (not SOCK_DGRAM). It is a listening socket bound to a ‘well-known’ sun_path file. This socket will be used to communicate with the function areq that is implemented in the Tour module (see the section API specifications below). In this context, areq will act as the client and the ARP module as the server.

    The ARP module then sits in an infinite loop, monitoring these two sockets.

    As ARP request messages arrive on the PF_PACKET socket, the module processes them, and responds with ARP reply messages as appropriate.

    The protocol builds a ‘cache’ of matching  <IP address , HW address>  pairs from the replies (and requests – see below) it receives. For simplicity, and unlike the real ARP, we shall not implement timing out mechanisms for these cache entries.

    A cache entry has five parts: (i) IP address ;  (ii) HW address ;  (iii) sll_ifindex (the interface to be used for reaching the matching pair <(i) , (ii)>) ;  (iv) sll_hatype ;  and (v) a Unix-domain connection-socket descriptor for a connected client (see the section API specifications below for the latter three). When an ARP reply is being entered in the cache, the ARP module uses the socket descriptor in (v) to send a reply to the client, closes the connection socket, and deletes the socket descriptor from the cache entry.

    Note that, like the real ARP, when an ARP request is received by a node, and if the request pertains to that receiving node, the sender’s (see Figure 4.3 of the ARP & RARP handout) <IP address, HW address> matching pair should be entered into the cache if it is not already there (together, of course, with (iii) sll_ifindex &  (iv) sll_hatype), or updated if need be if such an entry already exists in the cache.

    If the ARP request received does not pertain to the node receiving it, but there is already an entry in that receiving node's cache for the sender’s <IP address, HW address> matching pair, that entry should be checked and updated if need be. If there is no such entry, no action is taken (in particular, and unlike the case above, no new entry should be made in the receiving node's cache of the sender’s <IP address, HW address> matching pair if such an entry does not already exist).

    ARP request and reply messages have the same format as Figure 4.3 of the ARP & RARP handout, but with an extra 2-byte identification field added at the beginning which you fill with a value chosen so that it has a high probability of being unique to yourself. This value is to be echoed in the reply message, and helps to act as a further filter in case some other student happens to have fortuitously chosen the same value as yourself for the protocol parameter of the ARP PF_PACKET. Values in the fields of our ARP messages must be in network byte order. You might find the system header file <linux/if_arp.h> useful for manipulating ARP request and reply messages, but remember that our version of these messages have an extra two-byte field as mentioned above.

    Your code should print out on stdout, in some appropriately clear format, the contents of the Ethernet frame header and ARP request message you send. As described in Section 4.4 of the ARP & RARP handout, the node that responds to the request should, in its reply message, swap the two sender addresses with the two target addresses, as well as, of course, echo back the extra identification field sent with the request. The protocol at this responding node should print out, in an appropriately clear format, both the request frame (header and ARP message) it receives and the reply frame it sends. Similarly, the node that sent the request should print out the reply frame it receives. Finally, recall that the node issuing the request sends out a broadcast Ethernet frame, but the responding node replies with a unicast frame.

API specifications

    The API is for communication between the Tour process and the ARP process. It consists of a single function, areq, implemented in the Tour module. areq is called by send_v4 function of the application every time the latter want to send out an ICMP echo request message:

    int areq (struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr);

    IPaddr contains the primary or alias IPaddress of a ‘target’ node on the LAN for which the corresponding hardware address is being requested.

    hwaddr is a new structure (and not a pre-existing type) modeled on the sockaddr_ll of PF_PACKET; you will have to declare it in your code. It is used to return the requested hardware address to the caller of areq :

*/

/*
    areq creates a Unix domain socket of type SOCK_STREAM and connects to the ‘well-known’ sun_path file of the ARP listening socket. It sends the IP address from parameter IPaddr and the information in the three fields of parameter HWaddr to ARP. It then blocks on a read awaiting a reply from ARP. This read should be backed up by a timeout since it is possible that no reply is received for the request. If a timeout occurs, areq should close the socket and return to its caller indicating failure (through its int return value).

    Your application code should print out on stdout, in some appropriately clear format, a notification every time areq is called, giving the IP address for which a HW address is being sought. It should similarly print out the result when the call to areq returns (HW address returned, or failure).

    When the ARP module receives a request for a HW address from areq through its Unix domain listening socket, it first checks if the required HW address is already in the cache. If so, it can respond immediately to the areq and close the Unix domain connection socket.  Else :  it makes an ‘incomplete’ entry in the cache, consisting of parts (i), (iii), (iv) and (v) ;  puts out an ARP request message on the network on its PF_PACKET socket; and starts monitoring the areq connection socket for readability  –  if the areq client closes the connection socket (this would occur in response to a timeout in areq), ARP deletes the corresponding incomplete entry from the cache (and ignores any subsequent ARP reply from the network if such is received). On the other hand, if ARP receives a reply from the network, it updates the incomplete cache entry, responds to areq, and closes the connection socket.

Hand-in

Submit your code on the minix node using the  electronic hand-in  procedure provided. Your submission must absolutely include :

    a Readme file which identifies the members of the group;

    a Makefile which

        compiles your code using, where necessary, the Stevens’ environment in the course account on the minix node,  /home/users/cse533/Stevens/unpv13e ;  and

        gives the standard names <login>_tour  &  <login>_arp for the executables produced (note the underscore in the executable names), where <login> is the login name your group will use to hand in its copy of the assignment.

*/