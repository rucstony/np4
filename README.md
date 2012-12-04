np4
===

Ping routine : 

- Create an ICMP ping request : 
	refer send_v4.c - this basically sends a packet on socket with ICMP header. 
					WE NEED TO ADD THE IP HEADER AS WELL. 
					and send the packet to sendODRframe variant. 

					Send has to be made on the PF_PACKET raw socket. 

For sending outline - main.c 
For recieving outline - proc_v4.c , readloop.c


/*
	Principal frame-sending function. Packs the data and sends it on PF-PACKET socket.
*/
void sendTourPacket( int s , struct odr_frame * populated_odr_frame , char * source_hw_mac_address, char * destination_hw_mac_address , int if_index )
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


//	unsigned char src_mac[6] = {0x00, 0x0c, 0x29, 0x11, 0x58, 0xa2};
	
	/*Broadcast MAC address*/
	//unsigned char dest_mac[6] = {0x00, 0x0c, 0x29, 0x24, 0x8f, 0x70};
	//unsigned char dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	
	i = IF_HADDR;
	printf("\n\nSending Tour Packet to  \n\t Destination H/W Address :\n");
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



	/*fill the frame with some data*/
	memcpy((void*)data,(void*)populated_odr_frame, sizeof( struct odr_frame ));

	printf("Just before send.. \n");
	/*send the packet*/
	send_result = sendto(s, buffer, ETH_FRAME_LEN, 0, 
		      (struct sockaddr*)&socket_address, sizeof(socket_address));
	if (send_result == -1){ perror("sendto"); }
	printf("Done sending..WOO\n");
}
