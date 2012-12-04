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