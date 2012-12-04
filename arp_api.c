
#define UNIXDG_PATH "testpath"

struct hwaddr 
{
    int             sll_ifindex;     /* Interface number */
    unsigned short  sll_hatype;  /* Hardware type */
    unsigned char   sll_halen;       /* Length of address */
    unsigned char   sll_addr[8];     /* Physical layer address */
};
int areq (struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr)
{
    int unix_domain_socket, send_result, replen, n, ihw, khw;
    sockaddr_un unixaddr, repaddr;
    char *ip_address, str_from_sock, output_to_sock;
    if((unix_domain_socket = socket(AF_LOCAL, SOCK_STREAM, 0))==-1)
    {
        printf("Error in creation of Unix Domain socket\n");
        perror("socket");
        return;
        
    }

    unlink(UNIXDG_PATH);
    bzero(&unixaddr, sizeof(unixaddr));
    unixaddr.sun_family = AF_LOCAL;
    strcpy(unixaddr.sun_path, UNIXDG_PATH);
    
    if(connect(unix_domain_socket, (SA *) &unixaddr, SUN_LEN(&unixaddr))<0)
    {       fprintf(stderr,"connect() failed. errorno =  %d\n",errno); 
            exit(1);
    }


      
    
    //Sock_ntop_host(IPaddr, sizeof(*IPaddr))
    inet_ntop( AF_INET, &(IPaddr->sin_addr), ip_address, INET_ADDRSTRLEN );

    printf("areq() called for IP address: %s\n",ip_address );
    sprintf(output_to_sock,"%s|%d|%hu|%c\n", ip_address, 
                                          HWaddr.sll_ifindex,
                                          HWaddr.sll_hatype,
                                          HWaddr.sll_halen);
//    printf("%s\n", output_to_sock);
    printf("\nMessage sent to ARP unix domain socket..%s\n",output_to_sock );
    
   // send_result = sendto(unix_domain_socket,output_to_sock,strlen(output_to_sock),0,&unixaddr,sizeof(unixaddr));
   // if (send_result == -1){ perror("sendto"); exit(0); }

    if (write(unix_domain_socket, output_to_sock, sizeof(output_to_sock)) < 0)
        perror("write");

    
    signal(SIGALRM,arp_receive_timeout);    
    alarm(10);

   // if((n=recvfrom(unix_domain_socket,str_from_sock,MAXLINE,0,&repaddr,&replen))>=0)
    if((n=read(unix_domain_socket,str_from_sock,MAXLINE))>=0)
    {
        alarm(0);



        ihw = IF_HADDR;
        khw=0;
        printf("\nMessage recieved from ARP unix domain socket..%s \n" , str_from_sock);
    
        do 
        {   
            HWaddr.sll_addr[khw] = str_from_sock[khw] & 0xff;
            
            printf("%.2x%s", node_ethernet_address[khw] & 0xff, (ihw == 1) ? " " : ":");
            khw++;
        } while (--ihw > 0);
       
       close(unix_domain_socket);
       return 1; 

   }

   close(unix_domain_socket);

   return -1;



}
static void arp_receive_timeout(int signo)
{
    printf("ARP Request timeout\n");

    return;
}