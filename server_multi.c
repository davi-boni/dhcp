#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
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

#define BROADCASTADDR  0xffffffff

/* Configurazione rete e pool IP: 11.0.0.14 - 11.0.0.250 (/24) */
#define SUBNET_NET     ((11u << 24) | (0u << 16) | (0u << 8))
#define SUBNET_MASK    ((255u << 24) | (255u << 16) | (255u << 8) | 0u)
#define POOL_START     14
#define POOL_END       250
#define POOL_SIZE      (POOL_END - POOL_START + 1)

#define DEFAULT_LEASE_TIME 60
#define OFFER_TIMEOUT      15

/* Modalita' di testing per i rinnovi */
enum test_mode {
	MODE_NORMAL = 0,       /* Rinnova normalmente */
	MODE_IGNORE_RENEW = 1, /* Ignora silenziosamente RENEW/REBIND (fa scadere il lease) */
	MODE_NAK_RENEW = 2     /* Risponde con DHCPNAK a RENEW/REBIND */
};

enum lease_state {
	LEASE_FREE = 0,
	LEASE_OFFERED,
	LEASE_BOUND
};

struct lease_entry {
	struct in_addr ip;
	uint8_t mac[ETH_ALEN];
	enum lease_state state;
	time_t expires_at;
};

static uint8_t serveraddr_bytes[4] = {11, 0, 0, 10}; /* 11.0.0.10 */
static struct in_addr serveraddr;
static const char *fqdn = "host.v2.cs.unibo.it";
static unsigned int ifindex = 2;
static struct ioth *serverstack = NULL;

static struct lease_entry pool[POOL_SIZE];
static uint32_t g_lease_seconds = DEFAULT_LEASE_TIME;
static enum test_mode g_test_mode = MODE_NORMAL;

/* Helper per formattare un MAC address */
static void format_mac(const uint8_t *mac, char *buf, size_t len) {
	snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Inizializza il pool IP 11.0.0.14 .. 11.0.0.250 */
static void init_pool(void) {
	memcpy(&serveraddr, serveraddr_bytes, sizeof(serveraddr));
	for (int i = 0; i < POOL_SIZE; i++) {
		pool[i].ip.s_addr = htonl(SUBNET_NET | (uint32_t)(POOL_START + i));
		memset(pool[i].mac, 0, ETH_ALEN);
		pool[i].state = LEASE_FREE;
		pool[i].expires_at = 0;
	}
}

/* Libera tutti i lease scaduti */
static void purge_expired_leases(time_t now) {
	for (int i = 0; i < POOL_SIZE; i++) {
		if (pool[i].state != LEASE_FREE && now >= pool[i].expires_at) {
			char ipstr[INET_ADDRSTRLEN];
			char macstr[18];
			inet_ntop(AF_INET, &pool[i].ip, ipstr, sizeof(ipstr));
			format_mac(pool[i].mac, macstr, sizeof(macstr));
			printf("[LEASE SCADUTO] IP %s (MAC %s, stato precedente: %s) rimesso nel pool\n",
					ipstr, macstr,
					pool[i].state == LEASE_BOUND ? "BOUND" : "OFFERED");
			pool[i].state = LEASE_FREE;
			memset(pool[i].mac, 0, ETH_ALEN);
			pool[i].expires_at = 0;
		}
	}
}

static struct lease_entry *find_lease_by_mac(const uint8_t *mac) {
	for (int i = 0; i < POOL_SIZE; i++) {
		if (pool[i].state != LEASE_FREE && memcmp(pool[i].mac, mac, ETH_ALEN) == 0)
			return &pool[i];
	}
	return NULL;
}

static struct lease_entry *find_lease_by_ip(struct in_addr ip) {
	for (int i = 0; i < POOL_SIZE; i++) {
		if (pool[i].ip.s_addr == ip.s_addr)
			return &pool[i];
	}
	return NULL;
}

/* Cerca un lease esistente per il MAC oppure ne assegna uno libero dal pool */
static struct lease_entry *alloc_lease_for_mac(const uint8_t *mac, struct in_addr req_ip) {
	struct lease_entry *existing = find_lease_by_mac(mac);
	if (existing != NULL)
		return existing;

	/* Se il client ha richiesto un IP specifico ed e' libero nel pool, glielo assegnamo */
	if (req_ip.s_addr != 0) {
		struct lease_entry *preferred = find_lease_by_ip(req_ip);
		if (preferred != NULL && preferred->state == LEASE_FREE) {
			memcpy(preferred->mac, mac, ETH_ALEN);
			return preferred;
		}
	}

	/* Altrimenti assegna il primo IP libero della famiglia */
	for (int i = 0; i < POOL_SIZE; i++) {
		if (pool[i].state == LEASE_FREE) {
			memcpy(pool[i].mac, mac, ETH_ALEN);
			return &pool[i];
		}
	}
	return NULL;
}

static int check_pkt(struct dhcp_pkt *inbuf, ssize_t inbuflen) {
	unsigned int sum = 0;
	static uint8_t dhcp_cookie[] = DHCP_COOKIE;
	if (inbuflen < (ssize_t)DHCPPKT)
		return 0;
	sum = chksum(sum, &inbuf->ip_h, sizeof(inbuf->ip_h));
	if (sum != 0xffff)
		return 0;
	if (inbuf->ip_h.protocol != SOL_UDP)
		return 0;
	if (inbuf->udp_h.uh_sport != htons(DHCP_CLIENTPORT))
		return 0;
	if (inbuf->udp_h.uh_dport != htons(DHCP_SERVERPORT))
		return 0;
	if (memcmp(inbuf->dhcp_h.dhcp_cookie, dhcp_cookie, sizeof(dhcp_cookie)) != 0)
		return 0;
	if (inbuf->bootp_h.op != 1) /* boot request */
		return 0;
	return 1;
}

static int dhcp_server_send(int type, int fd, const struct sockaddr_ll *dest_addr,
		const uint8_t *xid, const uint8_t *client_mac, struct in_addr assigned_ip) {
	struct dhcp_pkt outbuf = {
		.ip_h.version = 4,
		.ip_h.ihl = 5,
		.ip_h.ttl = 64,
		.ip_h.protocol = SOL_UDP,
		.ip_h.daddr = BROADCASTADDR,
		.udp_h.uh_sport = htons(DHCP_SERVERPORT),
		.udp_h.uh_dport = htons(DHCP_CLIENTPORT),
		.bootp_h.op = 2, /* boot reply */
		.bootp_h.htype = 1,
		.bootp_h.hlen = ETH_ALEN,
		.dhcp_h.dhcp_cookie = DHCP_COOKIE
	};

	memcpy(outbuf.bootp_h.xid, xid, 4);
	memcpy(outbuf.bootp_h.chaddr, client_mac, ETH_ALEN);
	memcpy(outbuf.bootp_h.siaddr, &serveraddr, sizeof(serveraddr));

	if (type == DHCPOFFER || type == DHCPACK) {
		memcpy(outbuf.bootp_h.yiaddr, &assigned_ip, sizeof(assigned_ip));
	}

	FILE *optf = fmemopen(&outbuf.options, MAXOPT, "w");
	if (!optf)
		return -1;

	add_dhcp_opt_type(optf, type);
	add_dhcp_opt(optf, OPTION_SERVID, sizeof(serveraddr), &serveraddr);

	if (type == DHCPOFFER || type == DHCPACK) {
		uint32_t leasetime = htonl(g_lease_seconds);
		uint32_t netmask = htonl(SUBNET_MASK);
		add_dhcp_opt(optf, OPTION_LEASETIME, sizeof(leasetime), &leasetime);
		add_dhcp_opt(optf, OPTION_MASK, sizeof(netmask), &netmask);
		add_dhcp_opt(optf, OPTION_ROUTER, sizeof(serveraddr), &serveraddr);
		add_dhcp_opt(optf, OPTION_DNS, sizeof(serveraddr), &serveraddr);
		if (fqdn)
			add_dhcp_opt_fqdn(optf, fqdn);
	}

	add_dhcp_opt_end(optf);
	long optlen = ftell(optf);
	fclose(optf);

	unsigned int sum = 0;
	outbuf.udp_h.uh_ulen = htons(DHCPPKT - sizeof(struct iphdr) + optlen);
	outbuf.ip_h.tot_len = htons(DHCPPKT + optlen);
	memcpy(&outbuf.ip_h.saddr, &serveraddr, sizeof(serveraddr));
	outbuf.ip_h.check = 0;
	sum = chksum(sum, &outbuf.ip_h, sizeof(outbuf.ip_h));
	outbuf.ip_h.check = htons(~sum);

	if (ioth_sendto(fd, &outbuf, DHCPPKT + optlen, 0,
				(const struct sockaddr *)dest_addr, sizeof(*dest_addr)) < 0)
		return -1;

	return 0;
}

static void handle_dhcp_packet(int fd, const struct sockaddr_ll *dest_addr, struct dhcp_pkt *inbuf) {
	time_t now = time(NULL);
	purge_expired_leases(now);

	FILE *optf = fmemopen(&inbuf->options, MAXOPT, "r");
	if (!optf)
		return;

	uint8_t msg_type = 0;
	int has_servid = 0;
	struct in_addr req_servid = {0};
	struct in_addr req_ip = {0};

	for (;;) {
		int opt_type = getc(optf);
		if (opt_type == OPTION_PAD)
			continue;
		if (opt_type == EOF || opt_type == OPTION_END)
			break;
		int opt_len = getc(optf);
		if (opt_len == EOF)
			break;
		long next_opt = ftell(optf) + opt_len;
		switch (opt_type) {
			case OPTION_TYPE:
				if (opt_len >= 1)
					msg_type = (uint8_t)getc(optf);
				break;
			case OPTION_SERVID:
				if (opt_len == 4) {
					fread(&req_servid, 4, 1, optf);
					has_servid = 1;
				}
				break;
			case OPTION_REQIP:
				if (opt_len == 4)
					fread(&req_ip, 4, 1, optf);
				break;
		}
		fseek(optf, next_opt, SEEK_SET);
	}
	fclose(optf);

	struct in_addr ciaddr;
	memcpy(&ciaddr, inbuf->bootp_h.ciaddr, sizeof(ciaddr));

	char macstr[18];
	char ipstr[INET_ADDRSTRLEN];
	format_mac(inbuf->bootp_h.chaddr, macstr, sizeof(macstr));

	/* Se il client indirizza la richiesta a un altro server DHCP, la ignoriamo */
	if (has_servid && req_servid.s_addr != serveraddr.s_addr) {
		return;
	}

	switch (msg_type) {
		case DHCPDISCOVER: {
			struct lease_entry *lease = alloc_lease_for_mac(inbuf->bootp_h.chaddr, req_ip);
			if (!lease) {
				printf("[DISCOVER] MAC %s -> POOL ESAURITO, impossibile offrire IP\n", macstr);
				return;
			}
			lease->state = LEASE_OFFERED;
			lease->expires_at = now + OFFER_TIMEOUT;

			inet_ntop(AF_INET, &lease->ip, ipstr, sizeof(ipstr));
			printf("[DISCOVER] MAC %s -> invio DHCPOFFER per %s (lease %us)\n",
					macstr, ipstr, g_lease_seconds);

			dhcp_server_send(DHCPOFFER, fd, dest_addr, inbuf->bootp_h.xid,
					inbuf->bootp_h.chaddr, lease->ip);
			break;
		}

		case DHCPREQUEST:{
			struct lease_entry *lease = find_lease_by_mac(inbuf->bootp_h.chaddr);

			/*
			 * Riconoscimento RENEW / REBIND:
			 * - E il client ha gia' un lease BOUND oppure ha valorizzato ciaddr.
			 */
			int is_renew_or_rebind = (!has_servid && (ciaddr.s_addr != 0 ||
					(lease != NULL && lease->state == LEASE_BOUND)));

			if (is_renew_or_rebind) {
				const char *phase = (inbuf->ip_h.daddr == BROADCASTADDR) ? "REBIND" : "RENEW";

				if (g_test_mode == MODE_IGNORE_RENEW) {
					printf("[%s] MAC %s -> TEST MODE: richiesta IGNORATA (nessuna risposta)\n",
							phase, macstr);
					return;
				}
				if (g_test_mode == MODE_NAK_RENEW) {
					printf("[%s] MAC %s -> TEST MODE: invio DHCPNAK e revoca lease\n",
							phase, macstr);
					if (lease) {
						lease->state = LEASE_FREE;
						memset(lease->mac, 0, ETH_ALEN);
						lease->expires_at = 0;
					}
					struct in_addr zero_ip = {0};
					dhcp_server_send(DHCPNAK, fd, dest_addr, inbuf->bootp_h.xid,
							inbuf->bootp_h.chaddr, zero_ip);
					return;
				}

				/* Rinnovo normale: verifica che il lease esista e corrisponda all'IP del client */
				if (!lease || (ciaddr.s_addr != 0 && lease->ip.s_addr != ciaddr.s_addr)) {
					printf("[%s] MAC %s -> lease sconosciuto o scaduto, invio DHCPNAK\n",
							phase, macstr);
					struct in_addr zero_ip = {0};
					dhcp_server_send(DHCPNAK, fd, dest_addr, inbuf->bootp_h.xid,
							inbuf->bootp_h.chaddr, zero_ip);
					return;
				}

				lease->state = LEASE_BOUND;
				lease->expires_at = now + g_lease_seconds;
				inet_ntop(AF_INET, &lease->ip, ipstr, sizeof(ipstr));
                uint32_t xid_val;
                memcpy(&xid_val, inbuf->bootp_h.xid, sizeof(xid_val));
                printf("[%ld][%s] MAC %s xid=0x%08x -> rinnovo accettato...\n",(long)now, phase, macstr, ntohl(xid_val));
				printf("[%s] MAC %s -> rinnovo accettato, invio DHCPACK per %s (scade tra %us)\n",
						phase, macstr, ipstr, g_lease_seconds);
				dhcp_server_send(DHCPACK, fd, dest_addr, inbuf->bootp_h.xid,
						inbuf->bootp_h.chaddr, lease->ip);
			} else {
				/* Richiesta iniziale (SELECTING dopo DHCPOFFER) */
				struct in_addr target_ip = (req_ip.s_addr != 0) ? req_ip : ciaddr;
				if (!lease) {
					lease = alloc_lease_for_mac(inbuf->bootp_h.chaddr, target_ip);
				}

				if (!lease || (target_ip.s_addr != 0 && lease->ip.s_addr != target_ip.s_addr)) {
					printf("[REQUEST] MAC %s -> IP richiesto non valido/disponibile, invio DHCPNAK\n",
							macstr);
					struct in_addr zero_ip = {0};
					dhcp_server_send(DHCPNAK, fd, dest_addr, inbuf->bootp_h.xid,
							inbuf->bootp_h.chaddr, zero_ip);
					return;
				}

				lease->state = LEASE_BOUND;
				lease->expires_at = now + g_lease_seconds;
				inet_ntop(AF_INET, &lease->ip, ipstr, sizeof(ipstr));
				printf("[REQUEST] MAC %s -> assegnato %s, invio DHCPACK (scade tra %us)\n",
						macstr, ipstr, g_lease_seconds);
				dhcp_server_send(DHCPACK, fd, dest_addr, inbuf->bootp_h.xid,
						inbuf->bootp_h.chaddr, lease->ip);
			}
			break;
		}

		case DHCPRELEASE: {
			struct lease_entry *lease = find_lease_by_mac(inbuf->bootp_h.chaddr);
			if (lease) {
				inet_ntop(AF_INET, &lease->ip, ipstr, sizeof(ipstr));
				printf("[RELEASE] MAC %s -> IP %s rilasciato nel pool\n", macstr, ipstr);
				lease->state = LEASE_FREE;
				memset(lease->mac, 0, ETH_ALEN);
				lease->expires_at = 0;
			}
			break;
		}

		default:
			break;
	}
}

static int iothconf_dhcp_proto_srv(struct ioth *stack, unsigned int ifidx) {
	int packet_socket = ioth_msocket(stack, AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (packet_socket < 0) {
		perror("ioth_msocket");
		return -1;
	}

	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_ifindex = ifidx,
		.sll_halen = ETH_ALEN,
		.sll_addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	};

	if (ioth_bind(packet_socket, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		perror("ioth_bind");
		ioth_close(packet_socket);
		return -1;
	}

	struct pollfd pfd = { .fd = packet_socket, .events = POLLIN };
	struct dhcp_pkt inbuf;

	printf("Server DHCPv4 avviato su 11.0.0.10 | Pool: 11.0.0.%d - 11.0.0.%d | Lease: %us | Modalita': %s\n",
			POOL_START, POOL_END, g_lease_seconds,
			g_test_mode == MODE_NORMAL ? "NORMAL" :
			(g_test_mode == MODE_IGNORE_RENEW ? "IGNORE_RENEW" : "NAK_RENEW"));

	for (;;) {
		/* Timeout 1000ms per verificare e loggare periodicamente le scadenze dei lease */
		int ev = poll(&pfd, 1, 1000);
		if (ev < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}

		purge_expired_leases(time(NULL));

		if (ev == 0)
			continue;

		ssize_t inbuflen = ioth_recvfrom(packet_socket, &inbuf, sizeof(inbuf), 0, NULL, NULL);
		if (inbuflen <= 0)
			continue;

		if (check_pkt(&inbuf, inbuflen)) {
			handle_dhcp_packet(packet_socket, &sll, &inbuf);
		}
	}

	ioth_close(packet_socket);
	return 0;
}

static void print_usage(const char *prog) {
	printf("Uso: %s [-l <lease_sec>] [-i | -n]\n", prog);
	printf("  -l <sec>  Durata del lease in secondi (default: %d)\n", DEFAULT_LEASE_TIME);
	printf("  -i        Test mode: ignora le richieste RENEW/REBIND (fa scadere il lease)\n");
	printf("  -n        Test mode: risponde con DHCPNAK alle richieste RENEW/REBIND\n");
}

int main(int argc, char *argv[]) {
	int opt;
	while ((opt = getopt(argc, argv, "l:inh")) != -1) {
		switch (opt) {
			case 'l':
				g_lease_seconds = (uint32_t)atoi(optarg);
				if (g_lease_seconds < 4) g_lease_seconds = 4;
				break;
			case 'i':
				g_test_mode = MODE_IGNORE_RENEW;
				break;
			case 'n':
				g_test_mode = MODE_NAK_RENEW;
				break;
			case 'h':
			default:
				print_usage(argv[0]);
				return 0;
		}
	}

	init_pool();

	const char *stack = "vdestack";         
    const char *vnl = "vde:///tmp/mysw";     

	serverstack = ioth_newstack(stack, vnl);
	//if (serverstack == NULL) {
	//	perror("ioth_newstack");
	//	return 1;
	//}

	int rv = ioth_config(serverstack, "ifindex=2,ip=11.0.0.10/24");
	if (rv < 0) {
		perror("ioth_config");
		return 1;
	}
    //if (serverstack == NULL) {
	//	perror("ioth_newstack");
	//	return 1;
	//}

	if (iothconf_dhcp_proto_srv(serverstack, ifindex) < 0) {
		return 1;
	}

	return 0;
}