/*
 *   iothconf_dhcp.c: auto configuration for ioth.
 *       dhcp (v4) partial implementation do DHCP 2131 and 6843 (fqdn)
 *
 *   Copyright 2021 Renzo Davoli - Virtual Square Team
 *   University of Bologna - Italy
 *
 *   This library is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU Lesser General Public License as published by
 *   the Free Software Foundation; either version 2.1 of the License, or (at
 *   your option) any later version.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

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
#include <iothconf_mod.h>
#include <iothconf_hash.h>
#include "iothconf_data.h"
#include <pthread.h>
#include <sys/timerfd.h>
#include <unistd.h>

struct dhcpdata {
	struct ioth *stack;
	unsigned int ifindex;
	uint8_t xid[4];
	uint8_t macaddr[ETH_ALEN];
	const char *fqdn;
	time_t timestamp;
	struct in_addr serveraddr;
	struct in_addr clientaddr;
};

#define   DHCP_CLIENTPORT   68
#define   DHCP_SERVERPORT   67

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define OPTION_PAD        0
#define OPTION_MASK       1
#define OPTION_ROUTER     3
#define OPTION_DNS        6
#define OPTION_HOSTNAME  12
#define OPTION_DOMNAME   15
#define OPTION_BROADCAST 28
#define OPTION_NTP       42
#define OPTION_REQIP     50
#define OPTION_LEASETIME 51
#define OPTION_TYPE      53
#define OPTION_SERVID    54
#define OPTION_PARLIST   55
#define OPTION_MAXSIZE   57
#define OPTION_CLIENTID  61
#define OPTION_FQDN      81
#define OPTION_DOMAIN_LIST      119
#define OPTION_END      255

#define DHCP_COOKIE {0x63,0x82,0x53,0x63}
#define BOOTP_VEND_LEN 64

// Thread util const
#define UNBOUND -1
#define INIT 0
#define BOUND 1
#define RENEW 2
#define REBIND 3
#define BROADCASTADDR 0xffffffff
#define DHCP_R_REQUEST 9

__attribute__((__packed__)) struct bootp_head {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint8_t xid[4];
	uint8_t secs[2];
	uint8_t flags[2];
	uint8_t ciaddr[4];
	uint8_t yiaddr[4];
	uint8_t siaddr[4];
	uint8_t giaddr[4];
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
};

__attribute__((__packed__)) struct dhcp_head {
	uint8_t dhcp_cookie[4];
};

__attribute__((__packed__)) struct dhcp_option {
	uint8_t opt_type;
	uint8_t opt_len;
	uint8_t opt_value[];
};

#define MAXDHCP 576
#define DHCPPKT \
	(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct bootp_head) + sizeof(struct dhcp_head))
#define MAXOPT MAXDHCP - DHCPPKT

struct dhcp_pkt {
	struct iphdr ip_h;
	struct udphdr udp_h;
	struct bootp_head bootp_h;
	struct dhcp_head dhcp_h;
	uint8_t options[MAXOPT];
};

/* IP checksum */
unsigned int chksum(unsigned int sum, void *vbuf, size_t len) {
	uint8_t *buf=vbuf;
	unsigned int i;
	for (i = 0; i < len; i++)
		sum += (i & 1)? buf[i]: buf[i]<<8;
	sum = (sum>>16) + (sum & 0xffff);
	sum = (sum>>16) + (sum & 0xffff);
	return sum;
}

/* packet composing helper functions */
static void add_dhcp_opt_type(FILE *f, int type) {
	fputc(OPTION_TYPE, f);
	fputc(1, f);
	fputc(type, f);
}

static void add_dhcp_opt_clientid(FILE *f, uint8_t *macaddr) {
	fputc(OPTION_CLIENTID, f);
	fputc(7, f);
	fputc(1, f); // ethernet
	fwrite(macaddr, ETH_ALEN, 1, f);
}

static void add_dhcp_opt_fqdn(FILE *f, const char *fqdn) {
	size_t len = strlen(fqdn);
	if (len > 251) return;
	fputc(OPTION_FQDN, f);
	fputc(4 + len, f);
	fputc(0x01, f); //flags
	fputc(0x00, f); //A-res
	fputc(0x00, f); //PTR-res
	fwrite(fqdn, len + 1, 1, f);
}

static void add_dhcp_opt_maxsize(FILE *f) {
	fputc(OPTION_MAXSIZE, f);
	fputc(2, f);
	fputc(MAXDHCP >> 8, f);
	fputc(MAXDHCP & 255, f);
}

static void add_dhcp_opt_end(FILE *f) {
	fputc(OPTION_END, f);
}

static void add_dhcp_opt(FILE *f, int opttype, uint8_t len,  const void *opt) {
	fputc(opttype, f);
	fputc(len, f);
	fwrite(opt, len, 1, f);
}

static void add_dhcp_opt_parlist(FILE *f, ...) {
	int len;
	va_list ap;
	va_start(ap, f);
	for (len = 0; va_arg(ap, unsigned int) != 0; len++)
		;
	va_end(ap);
	fputc(OPTION_PARLIST, f);
	fputc(len, f);
	va_start(ap, f);
	for (;;) {
		uint8_t opt = va_arg(ap, unsigned int);
		if (opt == 0) break;
		fputc(opt, f);
	}
	va_end(ap);
}

/* dialog functions. dhcp_send and dhcp_get use indirect recursion.
	 In this way temporary data can be stored on the stack */
static int dhcp_get(int sendtype, int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data);
static int dhcp_send(int type, int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data, uint32_t daddr) {
	switch (type) {
		case DHCPDISCOVER:
		case DHCPREQUEST:
		case DHCP_R_REQUEST:
			break;
		default:
			return errno = EINVAL, -1;
	}
		if (getrandom(data->xid, sizeof(data->xid), 0) < 0 )
			return -1;
	struct dhcp_pkt outbuf = {
		.ip_h.version = 4,
		.ip_h.ihl = 5,
		.ip_h.ttl = 64,
		.ip_h.protocol = SOL_UDP, //UDP
		.ip_h.daddr = daddr, //0xffffffff,
		.udp_h.uh_sport = htons(DHCP_CLIENTPORT),
		.udp_h.uh_dport = htons(DHCP_SERVERPORT),
		.bootp_h.op = 1, // boot req
		.bootp_h.htype = 1, // ethernet
		.bootp_h.hlen = ETH_ALEN,
		.dhcp_h.dhcp_cookie = DHCP_COOKIE};
	memcpy(outbuf.bootp_h.xid, data->xid, sizeof(data->xid));
	memcpy(outbuf.bootp_h.chaddr, data->macaddr, sizeof(data->macaddr));
	if (type != DHCPDISCOVER) {
		memcpy(outbuf.bootp_h.ciaddr, &data->clientaddr, sizeof(data->clientaddr));
		memcpy(outbuf.bootp_h.siaddr, &data->serveraddr, sizeof(data->serveraddr));
	}
	unsigned int sum=0;
	FILE *optf = fmemopen(&outbuf.options, MAXOPT, "w");
	add_dhcp_opt_type(optf, (type == DHCP_R_REQUEST)? DHCPREQUEST : type);
	add_dhcp_opt_maxsize(optf);
	add_dhcp_opt_clientid(optf, data->macaddr);
	if (type == DHCPREQUEST) {
		add_dhcp_opt(optf, OPTION_REQIP, sizeof(data->clientaddr), &data->clientaddr);
		add_dhcp_opt(optf, OPTION_SERVID, sizeof(data->serveraddr), &data->serveraddr);
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
	outbuf.udp_h.uh_ulen = htons(DHCPPKT - sizeof(struct iphdr) + optlen);
	outbuf.ip_h.tot_len = htons(DHCPPKT + optlen);
	outbuf.ip_h.check = 0;
	sum = chksum(sum, &outbuf.ip_h, sizeof(outbuf.ip_h));
	outbuf.ip_h.check = htons(~sum);
	/* try 3 times */
	printf("Send with type: %u \n", type); 
	uint32_t xid_val;
	memcpy(&xid_val, data->xid, sizeof(xid_val));
	printf("xid in data: 0x%08x\n", ntohl(xid_val));
	uint32_t xid_val2;
	memcpy(&xid_val2, outbuf.bootp_h.xid, sizeof(xid_val2));
	printf("xid in outbuf: 0x%08x\n", ntohl(xid_val2));

	
	int times = 0;
	for (;;) {
		if (ioth_sendto(fd, &outbuf, DHCPPKT + optlen, 0, (struct sockaddr *) dest_addr, sizeof(*dest_addr)) < 0)
			return -1;
		if (dhcp_get(type, fd, dest_addr, data) == 0)
			return 0;
		if (times >= 2 || errno != ETIME)
			return -1;
		times++;
	}
}

/* check if the current packet is the expected one */
static int check_consistency(struct dhcp_pkt inbuf, size_t inbuflen, struct dhcpdata *data) {
	unsigned int sum=0;
	static uint8_t dhcp_cookie[] = DHCP_COOKIE;
	if (inbuflen < DHCPPKT){
		printf("Pacchetto troppo corto %d rispetto %d",inbuflen,DHCPPKT);
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
	if (inbuf.udp_h.uh_sport != htons(DHCP_SERVERPORT)){
		printf("porta server sbagliata %d\n",inbuf.udp_h.uh_sport);
		return 0;
	}
	if (inbuf.udp_h.uh_dport != htons(DHCP_CLIENTPORT)){
		printf("porta client sbagliata %d\n",inbuf.udp_h.uh_dport);
		return 0;
	}
	uint32_t xid_val;
	memcpy(&xid_val, inbuf.bootp_h.xid, sizeof(xid_val));
	printf("Ricevuto xid: 0x%08x\n", ntohl(xid_val));


	if (memcmp(inbuf.bootp_h.xid, data->xid, sizeof(data->xid))){
		uint32_t xid_val;
		memcpy(&xid_val, inbuf.bootp_h.xid, sizeof(xid_val));
		printf("Ricevuto xid: 0x%08x\n", ntohl(xid_val));
		return 0;
	}
	if (memcmp(inbuf.dhcp_h.dhcp_cookie, dhcp_cookie, sizeof(dhcp_cookie))){
		printf("cookie sbagliati in %d e expected %d \n",inbuf.dhcp_h.dhcp_cookie,dhcp_cookie);
		return 0;
	}
	if (inbuf.bootp_h.op != 2){ //boot reply
		printf("op sbagliato %d diverso da 2\n",inbuf.bootp_h.op);
		return 0;
	}
	return 1;
}

/* mask to prefix conversion. e.g.: 255.255.255.0 -> 24 */
static uint8_t mask2prefix(uint32_t mask) {
	int i;
	for (i = 0;i < 32; i++, mask >>= 1)
		if (mask & 1)
			break;
	return 32 - i;
}

#define DHCP_TIMEOUT 10000 	//2000
static int dhcp_get(int sendtype, int fd, const struct sockaddr_ll *dest_addr, struct dhcpdata *data) {
	int type;
	switch (sendtype) {
		case DHCPDISCOVER: type = DHCPOFFER; break;
		case DHCPREQUEST: type = DHCPACK; break;
		case DHCP_R_REQUEST: type = DHCPACK; break;
		default:
											return errno = EINVAL, -1;
	}
	struct dhcp_pkt inbuf;
	struct pollfd pfd[] = {{fd, POLLIN, 0}};
	int timeout = DHCP_TIMEOUT;
	struct timeval start;
	struct timeval end;
	struct timeval timediff;
	/* this loop terminates:
		 when the expected reply msg has been received and processed OR
		 when the timeout expires */
	for(;;) {
		uint32_t xid_val;
		memcpy(&xid_val, data->xid, sizeof(xid_val));
		printf("Ascolto con xid: 0x%08x\n", ntohl(xid_val));
		int event;
		gettimeofday(&start, NULL);
		event = poll(pfd, 1, timeout);
		//printf("event %d\n", event);
		if (event == 0)
			return errno = ETIME, -1;
		size_t inbuflen = ioth_recvfrom(fd, &inbuf, sizeof(inbuf), 0, NULL, NULL);
		//printf("%zd \n", inbuflen);
		if(check_consistency(inbuf, inbuflen, data)) {
			FILE *optf = fmemopen(&inbuf.options, MAXOPT, "r");
			uint8_t answ_type = 0;
			uint8_t *answ_server = NULL;
			uint8_t answ_prefix = 0;
			uint32_t answ_leasetime = 0;
			/* first scan */
			for(;;) {
				int opt_type = getc(optf);
				//printf("1 %d\n",opt_type);
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
			if (answ_type == DHCPNAK)
				return errno = ECANCELED, -1;
			if (answ_type == type && answ_server) {
				if (answ_server)
					memcpy(&data->serveraddr, answ_server, sizeof(data->serveraddr));
				memcpy(&data->clientaddr, inbuf.bootp_h.yiaddr, sizeof(data->clientaddr));
				if (answ_type == DHCPOFFER)
					return dhcp_send(DHCPREQUEST, fd, dest_addr, data, BROADCASTADDR);
				else if (answ_type == DHCPACK) {
					ioth_confdata_add_data(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_SERVER, data->timestamp, 0,
							struct in_addr, data->serveraddr.s_addr);
					ioth_confdata_add_data(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_ADDR, data->timestamp, 0,
							struct ioth_confdata_ipaddr,
							.addr = data->clientaddr,
							.prefixlen = answ_prefix,
							.leasetime = answ_leasetime);
					optf = fmemopen(&inbuf.options, MAXOPT, "r");
					/* second scan */
					for(;;) {
						int opt_type = getc(optf);
						if (opt_type == OPTION_PAD)
							continue;
						if (opt_type == EOF || opt_type == OPTION_END)
							break;
						unsigned int opt_len = getc(optf);
						long next_opt = ftell(optf) + opt_len;
						switch(opt_type) {
							case OPTION_ROUTER:
								ioth_confdata_add(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_ROUTER, data->timestamp, 0,
										inbuf.options + ftell(optf), opt_len);
								break;
							case OPTION_DNS:
								ioth_confdata_add(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_DNS, data->timestamp, 0,
										inbuf.options + ftell(optf), opt_len);
								break;
							case OPTION_DOMNAME:
								{
									/* add string termination */
									char domname[opt_len + 1];
									snprintf(domname, opt_len + 1,  "%.*s", opt_len, inbuf.options + ftell(optf));
									ioth_confdata_add(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_DOMAIN, data->timestamp, 0,
											domname, opt_len + 1);
								}
								break;
						}
						fseek(optf, next_opt, SEEK_SET);
					}
					fclose(optf);
					ioth_confdata_write_timestamp(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP, data->timestamp);
					return 0;
				} else
					return errno = EFAULT, -1;
			}
		}else{ //debug
			printf("CHECK FALLITO SUL PACCHETTO\n");
		}
		/* the code reaches this poinnt only if a spurious pakcet has beeen received.
			 it loops waiting for more packets using the remaining time to the timeout */
		gettimeofday(&end, NULL);
		timersub(&end, &start, &timediff);
		timeout -= timediff.tv_sec * 1000 + timediff.tv_usec / 1000;
		if (timeout < 0) timeout = 0;
	}
}

static int iothconf_dhcp_proto(struct ioth *stack, unsigned int ifindex, const char *fqdn, uint32_t config_flags, time_t timestamp) {
	(void) config_flags;
	int packet_socket = ioth_msocket(stack, AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_ifindex = ifindex,
		.sll_halen = ETH_ALEN,
		.sll_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	};
	//ioth_bind(packet_socket, (struct sockaddr *) &sll, sizeof(sll));
	struct dhcpdata dhcpdata = {
		.stack = stack,
		.ifindex = ifindex,
		.xid = {0, 0, 0, 0},
		.fqdn = fqdn,
		.timestamp = timestamp
	};
	ioth_linkgetaddr(stack, ifindex, dhcpdata.macaddr);
	//loop
	int rv = dhcp_send(DHCPDISCOVER, packet_socket, &sll, &dhcpdata, BROADCASTADDR);
	ioth_close(packet_socket);
	return rv;
}
// da modificare per creare e gestire il thread
#define IOTH_CONFDATA_THREAD_TIMESTAMP 0x30 // struct dhcp_thread
#define IOTH_CONFDATA_THREAD_DHCP4     0x31 // struct dhcp_thread

struct dhcp_thread_info{
	pthread_t thread_id;
	time_t timestamp;
	int status;
	int active;
};

struct dhcp_timed_status{
	time_t timestamp;
	int status;
};


struct dhcp_thread_args {
    struct ioth *stack;
    unsigned int ifindex;
    const char *fqdn;
    uint32_t config_flags;
    time_t timestamp;
    int state;
};


int ioth_dhcp_thread(struct ioth *stack, unsigned int ifindex, const char *fqdn, uint32_t config_flags, time_t timestamp, int state);
void *dhcp_pthread_runner(void *arg) {
    struct dhcp_thread_args *args = (struct dhcp_thread_args *)arg;

    /* Execute the task */
    int result = ioth_dhcp_thread(args->stack, 
                                  args->ifindex, 
                                  args->fqdn, 
                                  args->config_flags, 
                                  args->timestamp, 
                                  args->state);

    /* Free heap-allocated argument wrapper */
	ioth_confdata_free(args->stack, args->ifindex, IOTH_CONFDATA_THREAD_DHCP4, args->timestamp); 
    free(args);

    /* Cast int return code to void* or return NULL */
    return (void *)(intptr_t)result;
}

int iothconf_dhcp(struct ioth *stack, unsigned int ifindex, const char *fqdn, uint32_t config_flags) {
	pthread_t dhcp_thread_id = 0;
	time_t timestamp = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_THREAD_TIMESTAMP);

	
	
	struct dhcp_thread_args *args = malloc(sizeof(*args));
    if (!args) {
        return -1;
    }

    args->stack = stack;
    args->ifindex = ifindex;
    args->fqdn = fqdn;
    args->config_flags = config_flags;
    args->timestamp = timestamp;
    args->state = INIT; /* Explicit default (e.g., INIT) can be passed by caller */

    int ret = pthread_create(&dhcp_thread_id, NULL, dhcp_pthread_runner, args);
    if (ret != 0) {
        free(args);
        return ret;
    }
	printf("D_INFO creato id in dhcp %ld\n",dhcp_thread_id);
	ioth_confdata_add_data(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, timestamp, 0,
							struct dhcp_thread_info,
							.thread_id = dhcp_thread_id,
							.timestamp = timestamp,
							.status = UNBOUND,
							.active = 1);

    return 0;
}

static int _set_thread_status(void *data, void *arg) {
	struct dhcp_thread_info *thread_info = data;
	struct dhcp_timed_status *dhcp_status = arg;
	time_t timestamp = ioth_confdata_gettimestamp(data);
	printf("CHECKING SET TIMESTAMPS\n");
	if (timestamp >= dhcp_status->timestamp) {
		thread_info->status = dhcp_status->status;
		printf("Setting status to %d with actual value set %d\n", dhcp_status->status ,thread_info->status);
	}
	return 0;
}

static int _get_thread_info(void *data, void *arg) {
	struct dhcp_thread_info *out_info = arg;
	struct dhcp_thread_info *saved_info = data;
	time_t timestamp = ioth_confdata_gettimestamp(data);
	printf("CHECKING GET TIMESTAMPS\n");
	if (timestamp >= out_info->timestamp) {
		memcpy(out_info,saved_info, sizeof(struct dhcp_thread_info));
		printf("Setting Info\n");
	}
	return 0;
}

int iothconf_dhcp_kill(struct ioth *stack, unsigned int ifindex){
	time_t timestamp = 0;
	timestamp = ioth_confdata_read_timestamp(stack,ifindex,IOTH_CONFDATA_THREAD_DHCP4);
	struct dhcp_thread_info  d_i= {0,0,0,0};
	d_i.timestamp = timestamp;
	
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, _get_thread_info, &d_i);
	printf("D_INFO  active in kill %d\n",d_i.active);
	printf("D_INFO  status in kill %d\n",d_i.status);
	if(!d_i.active) return 1;
	
	printf("D_INFO  id in kill %ld\n",d_i.thread_id);
	pthread_cancel(d_i.thread_id);
	printf("Segnale di Kill lanciato\n"); 
	pthread_join(d_i.thread_id, NULL);
	ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, timestamp); 
	return 0;

}

int iothconf_dhcp_info(struct ioth *stack, unsigned int ifindex, int *status){
	time_t timestamp = 0;
	timestamp = ioth_confdata_read_timestamp(stack,ifindex,IOTH_CONFDATA_THREAD_DHCP4);
	struct dhcp_thread_info  d_i= {0,0,0,0};
	d_i.timestamp = timestamp;
	
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, _get_thread_info, &d_i);
	printf("D_INFO active in info %d\n",d_i.active);
	printf("D_INFO status in info %d\n",d_i.status);
	
	if(!d_i.active) return -1;
	
	printf("Stato del Thread %d\n", d_i.status); 
	*status = d_i.status;
	return 0;

}




//Cleanup for ioth packet sockets 
void ioth_close_clean(void* arg){
	printf("MI SONO FERMATO E SONO NEL CLEANUP ioth\n");
	int fd = *(int *)arg;
    if (fd >= 0)
    ioth_close(fd);
}

//Cleanup for generic file descriptors 
void fd_close_clean(void * arg){
	printf("MI SONO FERMATO E SONO NEL CLEANUP fd\n");
	int fd = *(int *)arg;
    if (fd >= 0)
	close(fd); 
} 

void test_clean(void * arg){
	printf("MI SONO FERMATO E SONO NEL CLEANUP\n");
}


static pthread_mutex_t addr_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t leasetime_mutex = PTHREAD_MUTEX_INITIALIZER;

struct in_addr tmp_dhcp_server_add, tmp_client_addr;   
uint32_t tmp_leasetime;    



// Thread func
static int _read_dhcp_serverip(void *data, void *arg) {
	time_t *latest_timestamp = arg;
	struct in_addr *s_addr =  data;
	time_t timestamp = ioth_confdata_gettimestamp(data);
	if (timestamp >= *latest_timestamp) {
		tmp_dhcp_server_add = *s_addr;
	}
	return 0;
}

static int _read_ip_leasetime(void *data, void *arg) {
	time_t *latest_timestamp = arg;
	struct ioth_confdata_ipaddr *ip_addr =  data;
	time_t timestamp = ioth_confdata_gettimestamp(data);
	if (timestamp >= *latest_timestamp) {
		tmp_leasetime = ip_addr->leasetime;
	}
	return 0;
}

static int _read_clientip(void *data, void *arg){
	time_t *latest_timestamp = arg;
	struct ioth_confdata_ipaddr *addr = data; 
	time_t timestamp = ioth_confdata_gettimestamp(data);
	if(timestamp >= *latest_timestamp) {
		tmp_client_addr = addr->addr;
	}
	return 0;
}

int set_timer_poll(int timerfd, struct itimerspec *tspec, uint32_t sec, struct pollfd *plfd) {
	// Se sec == 0, timerfd_settime disarmerebbe il timer anziché farlo scadere subito;
	// impostiamo almeno 1 nanosecondo se sec == 0, oppure assicuriamoci che sec > 0.
	tspec->it_value.tv_sec = sec;
	tspec->it_value.tv_nsec = (sec == 0) ? 1 : 0;
	tspec->it_interval.tv_sec = 0;
	tspec->it_interval.tv_nsec = 0;

	if (timerfd_settime(timerfd, 0, tspec, NULL) == -1) {
		perror("Errore nell'attivazione del timer (timerfd_settime)");
		return 1;
	}

	plfd->fd = timerfd;
	plfd->events = POLLIN;
	plfd->revents = 0;

	return 0;
}

void set_dhcp_thread_status(struct ioth *stack, unsigned int ifindex, int status){

	time_t timestamp = 0;
	timestamp = ioth_confdata_read_timestamp(stack,ifindex,IOTH_CONFDATA_THREAD_DHCP4);
	struct dhcp_timed_status  t_status= {timestamp,status};
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, _set_thread_status, &t_status);

}




static void consume_timer(int timerfd) {
	uint64_t exp;
	ssize_t s = read(timerfd, &exp, sizeof(uint64_t));
	(void)s;
}


/*
#define read_addr(server_addr, client_addr)	\
{											\
	pthread_mutex_lock(&addr_mutex);		\
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_DHCP4_SERVER, _read_dhcp_serverip, &timestamp);\
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_DHCP4_ADDR, _read_clientip, &timestamp);\
	server_addr = tmp_dhcp_server_add;\
	client_addr = tmp_client_addr;\
	pthread_mutex_unlock(&addr_mutex);\
}											\


#define read_leasetime(leasetime)	\
{											\
	pthread_mutex_lock(&leasetime_mutex);		\
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_DHCP4_ADDR, _read_ip_leasetime, &timestamp);\
	leasetime = tmp_leasetime;\
	pthread_mutex_unlock(&leasetime_mutex);\
}											\

*/

void read_addr(struct ioth *stack, unsigned int ifindex, time_t timestamp, struct in_addr *dhcp_server_add, struct in_addr *client_addr) {
	pthread_mutex_lock(&addr_mutex);
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_DHCP4_SERVER, _read_dhcp_serverip, &timestamp);
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_DHCP4_ADDR, _read_clientip, &timestamp);
	*dhcp_server_add = tmp_dhcp_server_add;
	*client_addr = tmp_client_addr;
	pthread_mutex_unlock(&addr_mutex);
}

void read_leasetime(struct ioth *stack, unsigned int ifindex, time_t timestamp, uint32_t *leasetime) {
	pthread_mutex_lock(&leasetime_mutex);
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_DHCP4_ADDR, _read_ip_leasetime, &timestamp);
	*leasetime = tmp_leasetime;
	pthread_mutex_unlock(&leasetime_mutex);
}



int ioth_dhcp_thread(struct ioth *stack, unsigned int ifindex, const char *fqdn, uint32_t config_flags, time_t timestamp, int state) {
	printf("ioth_dhcp_thread dentro \n"); // DEBUG
	int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timerfd == -1) {
		perror("timerfd_create");
		return 1;
	}
	struct itimerspec timerspec1, timerspec2;
	struct pollfd plfd;

	struct in_addr dhcp_server_add, client_addr;
	uint32_t leasetime = 0;

	int packet_socket = -1;

	pthread_cleanup_push(test_clean, NULL);
	pthread_cleanup_push(fd_close_clean, &timerfd);
	pthread_cleanup_push(ioth_close_clean,&packet_socket);

	while (state != UNBOUND) {
		switch (state) {
			case INIT: {
				set_dhcp_thread_status(stack,ifindex,INIT);
				printf("Enter INIT \n"); 
				int rv = iothconf_dhcp_proto(stack, ifindex, fqdn, config_flags, timestamp);
				if (rv == 0) {
					state = BOUND;
					printf("BOUND raggiunto \n"); // DEBUG
				} else {
					state = UNBOUND;
					printf("UNBOUND raggiunto \n"); // DEBUG
				}
				break;
			}

			case BOUND: {
				set_dhcp_thread_status(stack,ifindex,BOUND);
				printf("Enter BOUND\n"); 
				iothconf_ip_update(stack, ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP, config_flags);
				pthread_testcancel();
				read_leasetime(stack, ifindex, timestamp, &leasetime);
				printf("ottenuto leastime %d\n", leasetime);
				
				// Imposta T1 = 50% del leasetime (leasetime / 2)
				if (set_timer_poll(timerfd, &timerspec1, leasetime >> 1, &plfd) == 1) {
					close(timerfd);
					timerfd = -1;
					return 1;
				}
				pthread_testcancel();
				// Aspetta il timer T1 in modo bloccante
				int ret1 = poll(&plfd, 1, -1);
				if (ret1 == -1) {
					perror("Errore nella poll");
					close(timerfd);
					timerfd = -1;
					return 1;
				}

				if (plfd.revents & POLLIN) {
					consume_timer(timerfd); // Consuma la scadenza di T1
					printf("concluso T1\n");
					// Scade T1, si avvia T2 per il tempo rimanente fino a 7/8 del lease:
					// (7/8 leasetime) - (1/2 leasetime) = 3/8 leasetime
					uint32_t t2_delta = ((leasetime * 7) >> 3) - (leasetime >> 1);
					printf("t2_delta %d\n", t2_delta);
					if (set_timer_poll(timerfd, &timerspec2, t2_delta, &plfd) == 1) {
						close(timerfd);
						timerfd = -1;
						return 1;
					}
					state = RENEW;
				}
				break;
			}

			case RENEW: {
				pthread_testcancel();
				set_dhcp_thread_status(stack,ifindex,RENEW);
				printf("Enter RENEW \n"); 
				read_addr(stack, ifindex, timestamp, &dhcp_server_add, &client_addr);
				(void)config_flags;
				packet_socket = ioth_msocket(stack, AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
				struct sockaddr_ll sll = {
					.sll_family = AF_PACKET,
					.sll_protocol = htons(ETH_P_IP),
					.sll_ifindex = ifindex,
					.sll_halen = ETH_ALEN,
					.sll_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				};
				struct dhcpdata dhcpdata = {
					.stack = stack,
					.ifindex = ifindex,
					.xid = {0, 0, 0, 0},
					.fqdn = fqdn,
					.timestamp = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP),
					.serveraddr = dhcp_server_add,
					.clientaddr = client_addr,
				};
				ioth_linkgetaddr(stack, ifindex, dhcpdata.macaddr);

				int ret2;
				// Ripeti finché T2 non scade (poll con timeout 0 restituisce 0 se il timer non è scaduto)
				printf("Inizio Renew\n");
				while ((ret2 = poll(&plfd, 1, 0)) == 0) {
					pthread_testcancel();
					if (dhcp_send(DHCP_R_REQUEST, packet_socket, &sll, &dhcpdata, dhcp_server_add.s_addr) == 0) {
						timestamp = dhcpdata.timestamp; // Aggiorna il timestamp di riferimento al nuovo lease
						state = BOUND;
						break;
					} else if (errno == ECANCELED) { // Ricevuto NACK dal server
						state = INIT;
						break;
					}
				}
				ioth_close(packet_socket);
				packet_socket =-1;

				// Se T2 è scaduto
				if (plfd.revents & POLLIN) {
					printf("Scaduto T2\n");
					consume_timer(timerfd); // Consuma la scadenza di T2
					if (state == RENEW) {
						// Carica il timer con il rimanente 1/8 del lease time
						if (set_timer_poll(timerfd, &timerspec2, leasetime >> 3, &plfd) == 1) {
							close(timerfd);
							timerfd = -1;
							return 1;
						}
						state = REBIND;
					}
				}
				break;
			}

			case REBIND: {
				pthread_testcancel();
				set_dhcp_thread_status(stack,ifindex,REBIND);
				printf("Enter REBIND \n");
				read_addr(stack, ifindex, timestamp, &dhcp_server_add, &client_addr);
				(void)config_flags;
				packet_socket = ioth_msocket(stack, AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
				struct sockaddr_ll sll = {
					.sll_family = AF_PACKET,
					.sll_protocol = htons(ETH_P_IP),
					.sll_ifindex = ifindex,
					.sll_halen = ETH_ALEN,
					.sll_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
				};
				struct dhcpdata dhcpdata = {
					.stack = stack,
					.ifindex = ifindex,
					.xid = {0, 0, 0, 0},
					.fqdn = fqdn,
					.timestamp = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP),
					.clientaddr = client_addr
				};
				ioth_linkgetaddr(stack, ifindex, dhcpdata.macaddr);

				int ret2;
				// Ripeti fino alla scadenza del lease time
				printf("Inizio REBIND\n");
				while ((ret2 = poll(&plfd, 1, 0)) == 0) {
					pthread_testcancel();
					if (dhcp_send(DHCP_R_REQUEST, packet_socket, &sll, &dhcpdata, BROADCASTADDR) == 0) {
						timestamp = dhcpdata.timestamp; // Aggiorna il timestamp di riferimento al nuovo lease
						state = BOUND;
						break;
					} else if (errno == ECANCELED) { // Ricevuto NACK dal server
						state = INIT;
						break;
					}
				}
				ioth_close(packet_socket);
				packet_socket =-1;

				// Scade il lease time finale
				if (plfd.revents & POLLIN) {
					consume_timer(timerfd); // Consuma la scadenza finale
					if (state != BOUND) {
						state = INIT;
					}
				}
				break;
			}

			default:
				break;
		}
	}
	set_dhcp_thread_status(stack,ifindex,UNBOUND);
	pthread_cleanup_pop(0);
	pthread_cleanup_pop(0);
	pthread_cleanup_pop(0);


	close(timerfd);
	timerfd = -1;
	return UNBOUND;
}
