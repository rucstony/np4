
#include <sys/socket.h>
//#include <netpacket/packet.h>
//#include <net/ethernet.h> /* the L2 protocols */
#include "hw_addrs.h"
#include "unp.h"
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#define USID_PROTO 0x4481
#define UNIXDG_PATH "testpath"
#define ETH_FRAME_LEN 1514

struct arp_frame
{
	uint16_t id;	
	uint16_t hard_type;
	uint16_t proto_type;
	uint8_t hard_size;
	uint8_t proto_size;
	uint16_t op;
	char sender_ethernet_address[6];
	char sender_ip_address[4];
	char target_ethernet_address[6];
	char target_ip_address[4];
};

struct IP_hw_address_mpg
{
	char ip_address[100];
	char hw_address[6];
	int sll_ifindex;
	unsigned short sll_hatype;
	int unix_domain_confd;
}*rt_head, *rt_tmp;


void sendARPframe( int s , struct arp_frame * populated_arp_frame , char * source_hw_mac_address, char * destination_hw_mac_address , int if_index )
{
	
	int j,i;
	/*target address*/
	struct sockaddr_ll socket_address;

	/*buffer for ethernet frame*/
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	 
	/*pointer to ethenet header*/
	unsigned char* etherhead = buffer;
		
	/*pointer to userdata in ethernet frame*/
	unsigned char* data = buffer + 14;
		
	/*another pointer to ethernet header*/
	struct ethhdr *eh = (struct ethhdr *)etherhead;
	 
	int send_result = 0,k=0;

	/*our MAC address*/
	unsigned char src_mac[6], dest_mac[6]; 

	char * src_mac1=source_hw_mac_address; 
	char * dest_mac1=destination_hw_mac_address; 


//	unsigned char src_mac[6] = {0x00, 0x0c, 0x29, 0x11, 0x58, 0xa2};
	
	/*Broadcast MAC address*/
	//unsigned char dest_mac[6] = {0x00, 0x0c, 0x29, 0x24, 0x8f, 0x70};
	//unsigned char dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	
	i = IF_HADDR;
	printf("\n\nSending ARP Frame \n Destination H/W Address :\n");
	do 
	{	
		dest_mac[k] = *destination_hw_mac_address++ & 0xff;
		k++;
		printf("%.2x%s", *dest_mac1++ & 0xff, (i == 1) ? " " : ":");
	} while (--i > 0);
	printf("\n");
	

	//printf("\tsending frame on socket: %d\n",s );
	//printf("\tpopulated_odr_frame: %d bytes.\n",sizeof(*populated_odr_frame));
	/*prepare sockaddr_ll*/
	
	printf(" Source H/W Address :\n");
	i = IF_HADDR;
	k=0;
	do 
	{	
		src_mac[k] = *source_hw_mac_address++ & 0xff;
		k++;
		printf("%.2x%s", *src_mac1++ & 0xff, (i == 1) ? " " : ":");
	} while (--i > 0);

	printf("\n");
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

	//printf("Before socket_address..\n");	
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
	/*fill the frame with some data*/
	memcpy((void*)data,(void*)populated_arp_frame, sizeof( struct arp_frame ));
/*
	for (j = 0; j < 1500; j++) {
		data[j] = (unsigned char)((int) (255.0*rand()/(RAND_MAX+1.0)));
	}
*/
	//printf("Just before send.. \n");
	/*send the packet*/
	send_result = sendto(s, buffer, ETH_FRAME_LEN, 0, 
		      (struct sockaddr*)&socket_address, sizeof(socket_address));
	if (send_result == -1){ perror("sendto"); }
	//printf("Done sending..WOO\n");
}

struct arp_frame * processRecievedPacket(char * str_from_sock)
{

	struct arp_frame * recieved_arp_frame;
	int j;
	struct sockaddr_ll socket_address; 	/*target address*/
	void* buffer = (void*)malloc(ETH_FRAME_LEN); 	/*buffer for ethernet frame*/
	unsigned char* etherhead = buffer; 	/*pointer to ethenet header*/
	void * data = buffer + 14;
	
	printf("\nBeginning processing of recieved packet..\n");
		
	/*pointer to userdata in ethernet frame*/
	
	memcpy((void*)buffer, (void*)str_from_sock, ETH_FRAME_LEN ); 
		
	recieved_arp_frame = (struct arp_frame *)data;
	
	printf("Converting to Host Byte Order..\n");
	recieved_arp_frame = convertToHostByteOrder( recieved_arp_frame );

	printf("Done processing of recieved packet..\n");
	return recieved_arp_frame;

}

struct arp_frame * convertToHostByteOrder(struct arp_frame * recieved_arp_frame)
{

	recieved_arp_frame->id=htons(recieved_arp_frame->id);	
	recieved_arp_frame->hard_type=htons(recieved_arp_frame->hard_type);
	recieved_arp_frame->proto_type=htons(recieved_arp_frame->proto_type);
	recieved_arp_frame->hard_size=htons(recieved_arp_frame->hard_size);
	recieved_arp_frame->proto_size=htons(recieved_arp_frame->proto_size);
	recieved_arp_frame->op=htons(recieved_arp_frame->op);
	return recieved_arp_frame;
}

void insert_to_cache( char * ip_address, int if_index, char * hatype, int connfd )
{

    struct IP_hw_address_mpg *node = (struct IP_hw_address_mpg *)malloc( sizeof(struct IP_hw_address_mpg) );
	
    strcpy( node->ip_address, ip_address );
    memcpy( node->next_hop_node_ethernet_address, next_hop_node_ethernet_address, 6 );
    node->if_index =  outgoing_interface_index ;
    
    node->number_of_hops_to_destination = number_of_hops_to_destination;
	node->made_or_last_reconfirmed_or_updated_timestamp = curr_time_ms;
   
    if( rt_head == NULL )
    {
      rt_head = node;
      rt_head->next = NULL;			
    } 
    else if( rt_head->next == NULL )
    {
      rt_head->next = node;
      node->next = NULL;			
    } 
    else
    {
      rt_tmp = rt_head->next;       
      rt_head->next = node;
      node->next = rt_tmp;            
    } 
 	return;
 }

/*
	Routing table lookup.
*/
struct IP_hw_address_mpg * get_ethernet_from_ip( char * ip_address, char * if_index, char * hatype, int connfd )
{
	struct IP_hw_address_mpg *node; 
	char * h_name;	

	node = rt_head;
	while( node != NULL )
	{
		if( strcmp( node->ip_address, ip_address ) == 0 && (node->sll_ifindex== if_index ))
		{
			//retrieveHostName( node->destination_canonical_ip_address , h_name);

			return node;
		}	
		
		node = node->next;
	}
	return "-1";	
}

/*
	Deletes an entry from the routing table entry. 
*/
int cache_delete_entry( char * destination_canonical_ip_address )
{
	struct routing_entry *node; 	
	struct routing_entry *prev; 	

	printf("Deleting routing table entry for : %s\n", destination_canonical_ip_address );

	node = rt_head; 
	while( node != NULL )	
	{
		if( strcmp( node->destination_canonical_ip_address, destination_canonical_ip_address ) == 0 )
		{
			//delete logic goes here.
			prev->next = node->next;
			node->next = NULL;
			free(node);	
		}	
		prev = node;
		node = node->next;
	}	
	return -1;
}




int main(int argc, char const *argv[])
{

		struct hwa_info	*hwa, *hwahead;
		char * ifname_split;
		int i, prflag, k, pf_socket, unix_domain_socket, arplen,unixarplen, ihw, khw, maxfdp;
		char   *ptr,*ptr1, *hw_address1, sender_ethernet_address[6], buffer[ETH_FRAME_LEN+1], unix_buffer[ETH_FRAME_LEN+1];
		struct sockaddr	*sa;
		struct sockaddr_un unixaddr, unixarpaddr;
		struct sockaddr_ll arpaddr;
		char * dest_mac1; 
		struct IP_hw_address_mpg IP_hw_address_mpg_collection, cache;
		struct arp_frame *recvd_packet;
		int nready, client[FD_SETSIZE];
		ssize_t	n;
		fd_set	rset, allset;

		for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) 
		{
			ifname_split = strtok(hwa->if_name, ":"); //get pointer to first token found and store in 0
		
			if( strcmp(ifname_split, "eth0")==0 )
			{	
				
				if ( (sa = hwa->ip_addr) != NULL)
				{
					strcpy(IP_hw_address_mpg_collection.ip_address, Sock_ntop_host(sa, sizeof(*sa)));
					printf("IP: %s\n", IP_hw_address_mpg_collection.ip_address);
				}	
				prflag = 0;
				i = 0;
				do 
				{

					if (hwa->if_haddr[i] != '\0') 
					{
						prflag = 1;
						break;
					}
				} while (++i < IF_HADDR);
			}
			k=0;
			if (prflag) 
			{
				printf("HW addr = ");
				ptr = hwa->if_haddr;
				hw_address1=ptr;
				i = IF_HADDR;
				do {
					IP_hw_address_mpg_collection.hw_address[k] = *ptr++ & 0xff;
					k++;
					printf("%.2x%s", *hw_address1++ & 0xff, (i == 1) ? " " : ":");
				} while (--i > 0);
				printf("\n");
			}
		}

	if((pf_socket = socket(PF_PACKET, SOCK_RAW, htons(USID_PROTO)))==-1)
 	{
 		printf("Error in creation of socket for PF_PACKET\n");
 		perror("socket");
 		return 0;
 	}
 
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
	
    if(bind(unix_domain_socket, (SA *) &unixaddr, SUN_LEN(&unixaddr))<0)
    {       fprintf(stderr,"bind() failed. errorno =  %d\n",errno); 
            exit(1);
    }
	
    if(listen(unix_domain_socket, LISTENQ)<0)
    {       fprintf(stderr,"listen() failed. errorno = %d\n",errno);       
            exit(1);
    }

    for (i = 0; i < FD_SETSIZE; i++)
		client[i] = -1;			/* -1 indicates available entry */
	
	FD_ZERO(&allset);
	FD_SET(unix_domain_socket, &allset);
	FD_SET(pf_socket, &allset);
	maxfdp=max(unix_domain_socket,pf_socket)+1;
	/* end fig01 */

	/* include fig02 */
	for ( ; ; ) 
	{
		
		rset = allset;		/* structure assignment */
		if((nready = select(maxfdp, &rset, NULL, NULL, NULL))<0)
		{	
			if(errno==EINTR)	
				continue;
			else
				err_sys("select error");	
		}		
		if (FD_ISSET(unix_domain_socket, &rset)) 
		{	
			
        	unixarplen=sizeof(unixarpaddr);
	        if((connfd = accept(unix_domain_socket, (SA *) unixarpaddr, &unixarplen))<0)
	        {
	        	 if ( (n = readline(connfd, unix_buffer, MAXLINE)) == 0)
				{          
	        	//(n=recvfrom(unix_domain_socket,unix_buffer, ETH_FRAME_LEN+1, 0, &unixarpaddr, &unixarplen)>0)
	        		printf("Received  packet from unix_domain_socket..s.%\n",unix_buffer);
	        		unix_buffer

	        		msg_fields[0] = strtok(unix_buffer, "|"); //get pointer to first token found and store in 0
	                while(msg_fields[i]!= NULL) 
	                {   /* ensure a pointer was found */
	                    i++;
	                    msg_fields[i] = strtok(NULL, "|"); /* continue to tokenize the string */
	                }
                
                	for(j = 0; j <= i-1; j++) {
          
                   		 printf("%s\n", msg_fields[j]); /* print out all of the tokens */
                	}
 
                	hw_address_from_cache=get_ethernet_from_ip(msg_fields[0],msg_fields[2],msg_fields[4],connfd);
               		
			        if(hw_address_from_cache!=NULL)
			        {
			        	    writen(connfd,hw_address_from_cache, strlen(hw_address_from_cache));
			        	/*
						A cache entry has five parts:
						 (i) IP address ;  
						(ii) HW address ;  
						(iii) sll_ifindex (the interface to be used for reaching the matching pair <(i) , (ii)>) ;  
						(iv) sll_hatype ;  and
						 (v) a Unix-domain connection-socket descriptor
			        	*/

			        }else
			        {

			        }
		        }else
		        {
		        	perror("readline");
		        }


	      
		}
//---------------------------------------------------------------------------------------------------------

        if (FD_ISSET(pf_socket, &rset)) 
        {        /* new client connection */
 
 			printf("Receiving packet ...\n");
        	arplen=sizeof(arpaddr);
	        if((n=recvfrom(pf_socket,buffer, ETH_FRAME_LEN+1, 0, &arpaddr, &arplen)>0))
	        {

				ihw = IF_HADDR;
	        	khw=0;

	        		printf("Received packet from hw address:\n");
				do 
				{	
					sender_ethernet_address[khw] = arpaddr.sll_addr[khw] & 0xff;
					
					printf("%.2x%s", sender_ethernet_address[khw] & 0xff, (ihw == 1) ? " " : ":");
					khw++;
				} while (--ihw > 0);
				printf("\n at interface %d...\n",arpaddr.sll_ifindex);

	        	

	        	if (n == -1)
	        	{ 
	        		printf("Error in recieving data from ODR..\n"); 
	        		exit(0);
	        	}
	        	else
	        	{ 
	        		printf("Recieved Packet successfully\n" ); 
	        	}

	            recvd_packet = (struct arp_frame *)processRecievedPacket(buffer);
	        }

        }

    }
	return 0;
}