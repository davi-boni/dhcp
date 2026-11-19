#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <ioth.h>
#include <iothconf.h>
#include "iothconf_dhcp.c"


#define DHCP_R_REQUEST 9 
#define BROADCASTADDR 0xffffffff

uint8_t serveraddr[4] = {0xb,0x0, 0x0,0xa};		//11.0.0.10; indirizzo server statico 
const char *fqdn = "host.v2.cs.unibo.it";	
unsigned int ifindex = 2;
struct ioth *serverstack = NULL;	
uint8_t chaddr[16] = {0x00}; 		

static int check_pkt(struct dhcp_pkt inbuf, size_t inbuflen, struct dhcpdata *data) {
	unsigned int sum=0;
	static uint8_t dhcp_cookie[] = DHCP_COOKIE;
	if( inbuflen < DHCPPKT){
		printf("pacchetto troppo piccolo: %lu \n", inbuflen); 
		return 0; 
	}
	sum = chksum(sum, &inbuf.ip_h, sizeof(inbuf.ip_h));
	if (sum != 0xffff){
		printf("Chesksum sbagliato %x\n",sum);
		return 0;
	}
	if (inbuf.ip_h.protocol != SOL_UDP){
		printf("protocollo sbagliato %d\n",inbuf.ip_h.protocol);
		return 0;
	}
	if (inbuf.udp_h.uh_sport != htons(DHCP_CLIENTPORT)){
		printf("porta server sbagliata %d\n",inbuf.udp_h.uh_sport);
		return 0;
	}
	if (inbuf.udp_h.uh_dport != htons(DHCP_SERVERPORT)){
		printf("porta client sbagliata %d\n",inbuf.udp_h.uh_dport);
		return 0;
	}
	if (memcmp(inbuf.dhcp_h.dhcp_cookie, dhcp_cookie, sizeof(dhcp_cookie))){
		printf("cookie sbagliati in %d e expected %d \n",inbuf.dhcp_h.dhcp_cookie,dhcp_cookie);
		return 0;
	}
	if (inbuf.bootp_h.op != 1){ 
		printf("op sbagliato %d diverso da 1\n",inbuf.bootp_h.op);
		return 0;
	}
	return 1;
}


static int dhcp_get_srv(int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data);
static int dhcp_server_send(int type, int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data){  
	

	struct dhcp_pkt outbuf = {
		.ip_h.version = 4,
		.ip_h.ihl = 5,
		.ip_h.ttl = 64,
		.ip_h.protocol = SOL_UDP, 
		.ip_h.daddr = BROADCASTADDR,
		.udp_h.uh_sport = htons(DHCP_SERVERPORT),	
		.udp_h.uh_dport = htons(DHCP_CLIENTPORT),		 
		.bootp_h.op = 2, 
		.bootp_h.htype = 1, 
		.bootp_h.hlen = ETH_ALEN,
		.dhcp_h.dhcp_cookie = DHCP_COOKIE};	
	memcpy(outbuf.bootp_h.xid, data->xid, sizeof(data->xid));
	 	
	uint8_t clientaddr[4] = {0xb,0x0, 0x0,0xe};	 					//indirizzo 11.0.0.14
	memcpy(outbuf.bootp_h.yiaddr, clientaddr, sizeof(clientaddr)); 
	memcpy(&data->clientaddr, clientaddr, sizeof(clientaddr)); 
	memcpy(outbuf.bootp_h.siaddr, serveraddr, sizeof(serveraddr)); 	 
	memcpy(&data->serveraddr, serveraddr, sizeof(serveraddr));		  
	 
	FILE *optf = fmemopen(&outbuf.options, MAXOPT, "w");
	add_dhcp_opt_type(optf, type);			 
	add_dhcp_opt_maxsize(optf);
	add_dhcp_opt_clientid(optf, chaddr);		 
	if (type != DHCPDISCOVER){	
		add_dhcp_opt(optf, OPTION_SERVID, sizeof(data->serveraddr), &data->serveraddr);
		 
		uint32_t lease_seconds = 120; 	
		uint32_t netmask = htonl((255 << 24) | (255 << 16) | (255 << 8) | 0);  
		uint32_t leasetime = htonl(lease_seconds);		 
		add_dhcp_opt(optf, OPTION_LEASETIME, sizeof(leasetime), &leasetime); 
		add_dhcp_opt(optf, OPTION_MASK, sizeof(netmask), &netmask); 
	}
	add_dhcp_opt_parlist(optf,
			OPTION_MASK,
			OPTION_ROUTER,
			OPTION_DNS,
			OPTION_DOMNAME,
			0);
	if (data->fqdn)
		add_dhcp_opt_fqdn(optf, data->fqdn);
	add_dhcp_opt_end(optf);
	long optlen = ftell(optf);
	fclose(optf);
	unsigned int sum = 0;
	outbuf.udp_h.uh_ulen = htons(DHCPPKT - sizeof(struct iphdr) + optlen);
	outbuf.ip_h.tot_len = htons(DHCPPKT + optlen);
	memcpy(&outbuf.ip_h.saddr, serveraddr, sizeof(serveraddr));
	outbuf.ip_h.check = 0;
	sum = chksum(sum, &outbuf.ip_h, sizeof(outbuf.ip_h));
	outbuf.ip_h.check = htons(~sum);
	if (ioth_sendto(fd, &outbuf, DHCPPKT + optlen, 0, (struct sockaddr *) dest_addr, sizeof(*dest_addr)) < 0)
		return -1;

	//if( dhcp_get_srv(fd, dest_addr, data) == 0)
	//	return 0; 
}



static int dhcp_get_srv(int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data){
	int type; 		
	struct dhcp_pkt inbuf;
	struct pollfd pfd[] = {{fd, POLLIN, 0}};
	int timeout = DHCP_TIMEOUT;
	struct timeval start;
	struct timeval end;
	struct timeval timediff;
	/* this loop terminates:
		 when the expected reply msg has been received and processed OR
		 when the timeout expires */
   	for (;;) {
		int event = poll(pfd, 1, timeout);
		if (event == 0) {
			printf("Timeout scaduto: nessun pacchetto sul socket.\n");
			return -1;
		}
		
    	ssize_t inbuflen = ioth_recvfrom(fd, &inbuf, sizeof(inbuf), 0, NULL, NULL);

		if(!check_pkt(inbuf, inbuflen, data)){
			printf("pacchetto scartato \n"); 
			return -1; 
		}

		FILE *optf = fmemopen(&inbuf.options, MAXOPT, "r");
		uint8_t answ_type = 0;
		uint8_t *answ_server = NULL;
		uint8_t answ_prefix = 0;
		uint32_t answ_leasetime = 0;
 
		/* first scan */
		for(;;) {
			int opt_type = getc(optf);
			printf("first scan -> opt_type: %d\n",opt_type);
			if (opt_type == OPTION_PAD)
				continue;
			if (opt_type == EOF || opt_type == OPTION_END)
				break;
			unsigned int opt_len = getc(optf);
			long next_opt = ftell(optf) + opt_len;
			switch(opt_type) {
				case OPTION_TYPE: answ_type = getc(optf); 
								printf("answ_type dal client: %u \n", answ_type); 	
								 break;
				case OPTION_SERVID: answ_server = inbuf.options + ftell(optf); break;
				case OPTION_MASK:
														answ_prefix = mask2prefix(
																(getc(optf) << 24) |
																(getc(optf) << 16) |
																(getc(optf) << 8) |
																getc(optf));
														printf("answ_prefix (mask): %u \n", answ_prefix); 
														break;
				case OPTION_LEASETIME:
														answ_leasetime = (getc(optf) << 24) | (getc(optf) << 16) |
															(getc(optf) << 8) | getc(optf);
														printf("answ_leasetime: %u \n", answ_leasetime); 
														break;


			}
			fseek(optf, next_opt, SEEK_SET);
		}
		fclose(optf);

 
		switch(answ_type){
			case DHCPDISCOVER: type = DHCPOFFER; break;			 
			case DHCPREQUEST: type = DHCPACK; break;
			case DHCP_R_REQUEST: type = DHCPACK; break;
			default: return errno = EINVAL, -1; 
		}  
		
			
		struct dhcpdata dhcpdatasrv = { 
			.stack = serverstack,
			.ifindex = ifindex,			
			.xid = {0,0,0,0},		
			.fqdn = fqdn,
			.timestamp = ioth_confdata_new_timestamp(serverstack,ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP)
		};
	
		memcpy(chaddr, inbuf.bootp_h.chaddr, sizeof(chaddr)); 
		memcpy(dhcpdatasrv.xid, inbuf.bootp_h.xid, sizeof(inbuf.bootp_h.xid));	


		printf("Invio server con type: %u \n", type); 
		if(dhcp_server_send(type, fd, dest_addr, &dhcpdatasrv) < 0){
			printf("Errore send server\n"); 
			perror(NULL); 
			return -1;
		}
	return 0; 
		
	}	 

	
	/* the code reaches this poinnt only if a spurious pakcet has beeen received.
	it loops waiting for more packets using the remaining time to the timeout */
	gettimeofday(&end, NULL);
	timersub(&end, &start, &timediff);
	timeout -= timediff.tv_sec * 1000 + timediff.tv_usec / 1000;
		if (timeout < 0) timeout = 0; 

}

			


static int iothconf_dhcp_proto_srv(struct ioth *stack, unsigned int ifindex, const char *fqdn, uint32_t config_flags) {
	(void) config_flags;
	int packet_socket = ioth_msocket(stack, AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));		
	struct sockaddr_ll sll = {			
		.sll_family = AF_PACKET,   
		.sll_protocol = htons(ETH_P_IP),
		.sll_ifindex = ifindex,	  
		.sll_halen = ETH_ALEN,
		.sll_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	};
	ioth_bind(packet_socket, (struct sockaddr *) &sll, sizeof(sll));
	struct dhcpdata dhcpdata = {
		.stack = stack,
		.ifindex = ifindex,
		.xid = {0, 0, 0, 0},
		.fqdn = fqdn,
		.timestamp = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP)
	}; 
	ioth_linkgetaddr(stack, ifindex, dhcpdata.macaddr);
	//loop
	int rv;
	int i = 0; 
	while(i < 10000000){
		rv = dhcp_get_srv(packet_socket, &sll, &dhcpdata);
		printf("\n ----------------------------- \n "); 
		i++; 
	}
	ioth_close(packet_socket);
	return rv;
} 







int main(){

    const char *stack = "vdestack";         
    const char *vnl = "vde:///tmp/mysw";                                                    
    uint32_t config_flags = 0; 

    serverstack = ioth_newstack(stack,vnl); 						
     
    if(stack == NULL) {
		perror("stack");
		return 1;
    } 

    int rv = ioth_config(serverstack, "ifindex=2,ip=11.0.0.10/24"); 	 
    if (rv < 0)
	perror("ioth_config");
    else {
	printf("ioth_config confirmed:");
	if (rv & IOTHCONF_STATIC) printf("static");
	if (rv & IOTHCONF_ETH) printf(" eth");
	if (rv & IOTHCONF_DHCP) printf(" dhcp");
	if (rv & IOTHCONF_DHCPV6) printf(" dhcpv6");
	if (rv & IOTHCONF_RD) printf("rd");
	printf("\n");
    } 
    
    
    int rvproto; 
    if( (rvproto = iothconf_dhcp_proto_srv(serverstack, ifindex, fqdn, config_flags)) == -1 ){
 	 	printf("Errore server: ");
		perror(NULL); 	
		return 1; 
    } 

    return 0; 
}	

