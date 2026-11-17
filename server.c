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
#include "iothconf_thread_dhcp.c"

uint8_t serveraddr[4] = {0xb,0x0, 0x0,0xa};		//11.0.0.10;				//indirizzo server statico 
const char *fqdn = "host.v2.cs.unibo.it";	
unsigned int ifindex = 2;
struct ioth *serverstack = NULL;	//inizializzato dopo 
uint8_t chaddr[16] = {0x00}; 		//indirizzo client (per ora uno)


static int dhcp_get_prova(int sendtype, int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data);
static int dhcp_server_send(int type, int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data){  
	//Controlla che il type sia valido 
	int get_type;  
	switch(type){
		case DHCPOFFER: 	//risponde al DHCPDISCOVER inviato da un client 
			get_type = DHCPREQUEST;
		break; 
		case DHCPACK:		//risponde al DHCPREQUEST inviato da client 
		break; 
		default: 
			return errno = EINVAL, -1;    
	}

	//Server costruisce il pacchetto di risposta da inviare 
	struct dhcp_pkt outbuf = {
		.ip_h.version = 4,
		.ip_h.ihl = 5,
		.ip_h.ttl = 64,
		.ip_h.protocol = SOL_UDP, //UDP
		.ip_h.daddr = BROADCASTADDR,
		.udp_h.uh_sport = htons(DHCP_SERVERPORT),	
		.udp_h.uh_dport = htons(DHCP_CLIENTPORT),		//perchè vede i messaggi del client, hanno la porta di destinazione del server 
		.bootp_h.op = 2, // boot reply
		.bootp_h.htype = 1, // ethernet
		.bootp_h.hlen = ETH_ALEN,
		.dhcp_h.dhcp_cookie = DHCP_COOKIE};	
	memcpy(outbuf.bootp_h.xid, data->xid, sizeof(data->xid));
	// in data->macaddr c'è indirizzo mac server
	//Indirizzo IP del client che sceglie il server nella offer potrebbe essere randomico, qui lo mettiamo a mano 
	//in_addr_t clientaddr = htonl((11u << 24) | (0u << 16) | (0u << 8) | 14u); 	
	uint8_t clientaddr[4] = {0xb,0x0, 0x0,0xe};	 	//indirizzo 11.0.0.14
	memcpy(outbuf.bootp_h.yiaddr, clientaddr, sizeof(clientaddr)); 
	memcpy(&data->clientaddr, clientaddr, sizeof(clientaddr)); 
	memcpy(outbuf.bootp_h.siaddr, serveraddr, sizeof(serveraddr)); 	//Il client non lo legge, ma standard lo richiede 
	memcpy(&data->serveraddr, serveraddr, sizeof(serveraddr));		//aggiunta io visto che la riga precedente il client non la usa   
	//Per DHCPOFFER, oltre all'indirizzo disponibile nel campo yiaddr, vanno inseriti nelle option gli altri parametri di configurazione 
	FILE *optf = fmemopen(&outbuf.options, MAXOPT, "w");
	add_dhcp_opt_type(optf, type);			//viene scritta nell'option 53 il tipo di pacchetto dhcp che viene inviato 
	add_dhcp_opt_maxsize(optf);
	//controllo se chaddr non è nullo
	add_dhcp_opt_clientid(optf, chaddr);		//questo è il macaddr del client 
	if (type != DHCPDISCOVER) {					//cattura DHCPOFFER e DHCPACK 
		//Qui bisogna capire come si inserisce, data qua fa riferimento al server 
		//add_dhcp_opt(optf, OPTION_REQIP, sizeof(data->clientaddr), &data->clientaddr);	questa il server non deve farla
		add_dhcp_opt(optf, OPTION_SERVID, sizeof(data->serveraddr), &data->serveraddr);
		//Aggiungo il leasetime e la maschera di rete 
		uint32_t lease_seconds = 120; 	
		uint32_t netmask = htonl((255 << 24) | (255 << 16) | (255 << 8) | 0);  
		uint32_t leasetime = htonl(lease_seconds);		//host to network long 
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

	if( dhcp_get_prova(get_type, fd, dest_addr, data) == 0)
		return 0; 
}



static int dhcp_get_print(int sendtype, int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data){
	int type; 		//Per le risposte del server 
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
		if (inbuflen > 0) {
        		printf("PACCHETTO RICEVUTO! Dimensione: %zd byte\n", inbuflen);
    			//break;
    	}
		
		//Invio pacchetto successivo 
		switch(sendtype){
			case DHCPDISCOVER: type = DHCPOFFER; break;			 
			case DHCPREQUEST: type = DHCPACK; break;
			case DHCP_R_REQUEST: type = DHCPACK; break;
			default: return errno = EINVAL, -1; 
		} 
		//memorizzo l'indirizzo mac identificativo del client di cui ho ricevuto la discover 
		//dhcp data struct 	
		struct dhcpdata dhcpdatasrv = {				//serverstack, ifinde,fqdn globali 
			.stack = serverstack,
			.ifindex = ifindex,			
			.xid = {0,0,0,0},		//default, cambiato sotto 
			.fqdn = fqdn,
			.timestamp = ioth_confdata_new_timestamp(serverstack,ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP)
		};
		//Salvo il macaddr del client proveniente dal pacchetto DHCPDISCOVER
		if(sendtype == DHCPDISCOVER){
			memcpy(chaddr, inbuf.bootp_h.chaddr, sizeof(chaddr)); 
			//Cambiare xid prendendo quello del client 
			memcpy(dhcpdatasrv.xid, inbuf.bootp_h.xid, sizeof(inbuf.bootp_h.xid));	
			printf("inbuf: %hhu e data->xid %hhu", inbuf.bootp_h.xid, dhcpdatasrv.xid);  	//DEBUG
		}
		

		//Lettura options pacchetto ricevuto 
		FILE *optf = fmemopen(&inbuf.options, MAXOPT, "r");
		uint8_t answ_type = 0;
		uint8_t *answ_server = NULL;
		uint8_t answ_prefix = 0;
		uint32_t answ_leasetime = 0;
		/* first scan */
		for(;;) {
			/*	int event;
				gettimeofday(&start, NULL);
				event = poll(pfd, 1, timeout);
				//printf("event %d\n", event);
				if (event == 0)
					return errno = ETIME, -1;
			*/ 
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
		printf("Invio server con type: %u \n", type); 
	/*	if(dhcp_server_send(type, fd, dest_addr, &dhcpdatasrv) < 0){
			printf("Errore send server\n"); 
			perror(NULL); 
			return -1;
		}
	*/
	return 0; 
		
	}	 

	
	/* the code reaches this poinnt only if a spurious pakcet has beeen received.
	it loops waiting for more packets using the remaining time to the timeout */
	gettimeofday(&end, NULL);
	timersub(&end, &start, &timediff);
	timeout -= timediff.tv_sec * 1000 + timediff.tv_usec / 1000;
		if (timeout < 0) timeout = 0; 

}


//funzione originale 

static int dhcp_get_prova(int sendtype, int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data){
	int type; 		//Per le risposte del server 
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
		if (inbuflen > 0) {
        		printf("PACCHETTO RICEVUTO! Dimensione: %zd byte\n", inbuflen);
    			//break;
    	}
		
		//Se il pacchetto ricevuto è corretto, il server invia il successivo 
		switch(sendtype){
			case DHCPDISCOVER: type = DHCPOFFER; break;			 
			case DHCPREQUEST: type = DHCPACK; break;
			case DHCP_R_REQUEST: type = DHCPACK; break;
			default: return errno = EINVAL, -1; 
		} 
		//memorizzo l'indirizzo mac identificativo del client di cui ho ricevuto la discover 
		//dhcp data struct 	
		struct dhcpdata dhcpdatasrv = {				//serverstack, ifinde,fqdn globali 
			.stack = serverstack,
			.ifindex = ifindex,			
			.xid = {0,0,0,0},		//default, cambiato sotto 
			.fqdn = fqdn,
			.timestamp = ioth_confdata_new_timestamp(serverstack,ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP)
		};
		//Salvo il macaddr del client proveniente dal pacchetto DHCPDISCOVER
		if(sendtype == DHCPDISCOVER){
			memcpy(chaddr, inbuf.bootp_h.chaddr, sizeof(chaddr)); 
			//Cambiare xid prendendo quello del client 
			memcpy(dhcpdatasrv.xid, inbuf.bootp_h.xid, sizeof(inbuf.bootp_h.xid));	
			printf("inbuf: %hhu e data->xid %hhu", inbuf.bootp_h.xid, dhcpdatasrv.xid);  	//DEBUG
		}
		

		//Lettura options pacchetto ricevuto 
		FILE *optf = fmemopen(&inbuf.options, MAXOPT, "r");
		uint8_t answ_type = 0;
		uint8_t *answ_server = NULL;
		uint8_t answ_prefix = 0;
		uint32_t answ_leasetime = 0;
		/* first scan */
		for(;;) {
			/*	int event;
				gettimeofday(&start, NULL);
				event = poll(pfd, 1, timeout);
				//printf("event %d\n", event);
				if (event == 0)
					return errno = ETIME, -1;
			*/ 
			int opt_type = getc(optf);
			printf("first scan -> opt_type: %d\n",opt_type);
			if (opt_type == OPTION_PAD)
				continue;
			if (opt_type == EOF || opt_type == OPTION_END)
				break;
			unsigned int opt_len = getc(optf);
			long next_opt = ftell(optf) + opt_len;
			switch(opt_type) {
				case OPTION_TYPE: answ_type = getc(optf); break;
				case OPTION_SERVID: answ_server = inbuf.options + ftell(optf); break;
				case OPTION_MASK:
														answ_prefix = mask2prefix(
																(getc(optf) << 24) |
																(getc(optf) << 16) |
																(getc(optf) << 8) |
																getc(optf));
														break;
				case OPTION_LEASETIME:
														answ_leasetime = (getc(optf) << 24) | (getc(optf) << 16) |
															(getc(optf) << 8) | getc(optf);
														break;


			}
			fseek(optf, next_opt, SEEK_SET);
		}
		fclose(optf);
		printf("answ_type client: %u e type: %u \n", answ_type, type);
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

	


static int iothconf_dhcp_proto2(struct ioth *stack, unsigned int ifindex, const char *fqdn, uint32_t config_flags) {
	(void) config_flags;
	int packet_socket = ioth_msocket(stack, AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));		
	struct sockaddr_ll sll = {			//Descrittore di indirizzo a livello 2, si usa con AF_PACKET
		.sll_family = AF_PACKET,  //Indica pacchetti a livello 2 fisico 
		.sll_protocol = htons(ETH_P_IP),
		.sll_ifindex = ifindex,	  //Indice dell'interfaccia che manda pacchetto 
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
	rv = dhcp_get_prova(DHCPDISCOVER, packet_socket, &sll, &dhcpdata);
	while(1){
		rv = dhcp_get_prova(DHCP_R_REQUEST, packet_socket, &sll, &dhcpdata);
	}
	ioth_close(packet_socket);
	return rv;
} 







int main(){

    const char *stack = "vdestack";         
    const char *vnl = "vde:///tmp/mysw";                             //tutorial                        
    uint32_t config_flags = 0; 

    serverstack = ioth_newstack(stack,vnl); 						//nuova var. globale
     
    if(stack == NULL) {
		perror("stack");
		return 1;
    } 

    int rv = ioth_config(serverstack, "ifindex=2,ip=11.0.0.10/24"); 	//CANCELLA a mano SE ESISTE GIA' 
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
    
    //Server configurato a questo punto
    int rvproto; 
    if( (rvproto = iothconf_dhcp_proto2(serverstack, ifindex, fqdn, config_flags)) == -1 ){
 	 	printf("Errore server: ");
		perror(NULL); 	
		return 1; 
    } 

    return 0; 
}		


