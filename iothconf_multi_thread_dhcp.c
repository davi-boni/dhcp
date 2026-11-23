/*
 *   iothconf_thread_dhcp.c: auto configuration for ioth.
 *       dhcp (v4) threaded multi-instance implementation of RFC 2131 and RFC 4702/6843 (fqdn)
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
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
	uint32_t instance_id;
	uint8_t xid[4];
	uint8_t macaddr[ETH_ALEN];
	const char *fqdn;
	time_t timestamp;
	struct in_addr serveraddr;
	struct in_addr clientaddr;
	struct in_addr router;
	uint8_t prefixlen;
	uint32_t leasetime;
};

#define DHCP_CLIENTPORT   68
#define DHCP_SERVERPORT   67

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
#define OPTION_DOMAIN_LIST 119
#define OPTION_END      255

#define DHCP_COOKIE {0x63,0x82,0x53,0x63}
#define BOOTP_VEND_LEN 64

// Thread util const
#ifndef UNBOUND
#define UNBOUND -1
#define INIT     0
#define BOUND    1
#define RENEW    2
#define REBIND   3
#endif
#define BROADCASTADDR 0xffffffff
#define DHCP_R_REQUEST 9
#define DHCP_INFINITE_LEASE 0xffffffffU

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
#define MAXOPT (MAXDHCP - DHCPPKT)

struct dhcp_pkt {
	struct iphdr ip_h;
	struct udphdr udp_h;
	struct bootp_head bootp_h;
	struct dhcp_head dhcp_h;
	uint8_t options[MAXOPT];
};

/* IP checksum */
unsigned int chksum(unsigned int sum, void *vbuf, size_t len) {
	uint8_t *buf = vbuf;
	unsigned int i;
	for (i = 0; i < len; i++)
		sum += (i & 1) ? buf[i] : buf[i] << 8;
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	return sum;
}

/* Calculates random exponential backoff (4s..64s) and uniform jitter [-1s, +1s] */
static int dhcp_backoff_ms(int attempt) {
	int base_sec = 4 << (attempt > 4 ? 4 : attempt); /* 4, 8, 16, 32, 64 */
	uint32_t rnd = 0;
	if (getrandom(&rnd, sizeof(rnd), 0) != sizeof(rnd))
		rnd = (uint32_t)rand();
	int jitter_ms = (int)(rnd % 2001U) - 1000; /* [-1000, +1000] ms */
	int total_ms = base_sec * 1000 + jitter_ms;
	return (total_ms < 1000) ? 1000 : total_ms;
}

/* packet composing helper functions */
static void add_dhcp_opt_type(FILE *f, int type) {
	fputc(OPTION_TYPE, f);
	fputc(1, f);
	fputc(type, f);
}

/* Unique Client ID per (interface, instance_id) so the DHCP server allocates distinct IPs */
static void add_dhcp_opt_clientid(FILE *f, const uint8_t *macaddr, uint32_t instance_id) {
	if (instance_id == 0) {
		fputc(OPTION_CLIENTID, f);
		fputc(7, f);
		fputc(1, f); // ethernet
		fwrite(macaddr, ETH_ALEN, 1, f);
	} else {
		uint32_t id_be = htonl(instance_id);
		fputc(OPTION_CLIENTID, f);
		fputc((int)(1 + ETH_ALEN + sizeof(id_be)), f);
		fputc(0, f); // opaque identifier (RFC 2131 / RFC 2132)
		fwrite(macaddr, ETH_ALEN, 1, f);
		fwrite(&id_be, sizeof(id_be), 1, f);
	}
}

static void add_dhcp_opt_fqdn(FILE *f, const char *fqdn) {
	size_t len = strlen(fqdn);
	if (len > 251) return;
	fputc(OPTION_FQDN, f);
	fputc(4 + len, f);
	fputc(0x01, f); // flags
	fputc(0x00, f); // A-res
	fputc(0x00, f); // PTR-res
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

static void add_dhcp_opt(FILE *f, int opttype, uint8_t len, const void *opt) {
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

/* Open and bind AF_PACKET socket to the target interface */
static int dhcp_open_packet_socket(struct ioth *stack, unsigned int ifindex) {
	int fd = ioth_msocket(stack, AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (fd < 0)
		return -1;
	struct sockaddr_ll bind_sll = {
		.sll_family   = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_ifindex  = (int)ifindex
	};
	if (ioth_bind(fd, (struct sockaddr *)&bind_sll, sizeof(bind_sll)) < 0) {
		ioth_close(fd);
		return -1;
	}
	return fd;
}

/* dialog functions. dhcp_send and dhcp_get use indirect recursion.
   In this way temporary data can be stored on the stack */
static int dhcp_get(int sendtype, int fd, int timerfd, const struct sockaddr_ll *dest_addr,
                    struct dhcpdata *data, int timeout_ms);

static int dhcp_send(int type, int fd, int timerfd, const struct sockaddr_ll *dest_addr,
                     struct dhcpdata *data, uint32_t daddr) {
	switch (type) {
		case DHCPDISCOVER:
		case DHCPREQUEST:
		case DHCP_R_REQUEST:
			break;
		default:
			return errno = EINVAL, -1;
	}

	/* In SELECTING (DHCPREQUEST) we keep the same xid from DHCPDISCOVER/DHCPOFFER.
	   In DHCPDISCOVER and RENEW/REBIND we generate a new xid for the new transaction */
	if (type == DHCPDISCOVER || type == DHCP_R_REQUEST) {
		if (getrandom(data->xid, sizeof(data->xid), 0) < 0)
			return -1;
	}

	struct dhcp_pkt outbuf = {
		.ip_h.version = 4,
		.ip_h.ihl = 5,
		.ip_h.ttl = 64,
		.ip_h.protocol = SOL_UDP, // UDP
		.ip_h.saddr = (type == DHCP_R_REQUEST) ? data->clientaddr.s_addr : 0, // RFC 2131 Sez. 4.1
		.ip_h.daddr = daddr,
		.udp_h.uh_sport = htons(DHCP_CLIENTPORT),
		.udp_h.uh_dport = htons(DHCP_SERVERPORT),
		.bootp_h.op = 1, // BOOTREQUEST
		.bootp_h.htype = 1, // ethernet
		.bootp_h.hlen = ETH_ALEN,
		.dhcp_h.dhcp_cookie = DHCP_COOKIE
	};
	memcpy(outbuf.bootp_h.xid, data->xid, sizeof(data->xid));
	memcpy(outbuf.bootp_h.chaddr, data->macaddr, sizeof(data->macaddr));

	/* ciaddr MUST be 0 in DHCPDISCOVER and DHCPREQUEST (SELECTING), set only in RENEW/REBIND.
	   siaddr MUST be 0 always. */
	if (type == DHCP_R_REQUEST) {
		memcpy(outbuf.bootp_h.ciaddr, &data->clientaddr, sizeof(data->clientaddr));
	}

	unsigned int sum = 0;
	FILE *optf = fmemopen(&outbuf.options, MAXOPT, "w");
	add_dhcp_opt_type(optf, (type == DHCP_R_REQUEST) ? DHCPREQUEST : type);
	add_dhcp_opt_maxsize(optf);
	add_dhcp_opt_clientid(optf, data->macaddr, data->instance_id);
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

	uint32_t xid_val;
	memcpy(&xid_val, data->xid, sizeof(xid_val));
	printf("[inst %u] Send type=%u xid=0x%08x\n", data->instance_id, type, ntohl(xid_val));

	/* Randomized exponential backoff (4s, 8s, 16s, 32s..64s +-1s).
	   If timerfd >= 0 (RENEW/REBIND), repeats until T2 or lease expiry.
	   Otherwise (DISCOVER/REQUEST), makes 4 attempts (~60s) before returning ETIME. */
	int attempt = 0;
	for (;;) {
		pthread_testcancel();
		if (ioth_sendto(fd, &outbuf, DHCPPKT + optlen, 0, (struct sockaddr *) dest_addr, sizeof(*dest_addr)) < 0)
			return -1;
		int timeout_ms = dhcp_backoff_ms(attempt);
		if (dhcp_get(type, fd, timerfd, dest_addr, data, timeout_ms) == 0)
			return 0;
		if (errno != ETIME)
			return -1;
		if (timerfd < 0 && attempt >= 3)
			return -1;
		attempt++;
	}
}

/* check if the current packet is the expected one */
static int check_consistency(struct dhcp_pkt inbuf, size_t inbuflen, struct dhcpdata *data) {
	unsigned int sum = 0;
	static uint8_t dhcp_cookie[] = DHCP_COOKIE;
	if (inbuflen < DHCPPKT)
		return 0;
	sum = chksum(sum, &inbuf.ip_h, sizeof(inbuf.ip_h));
	if (sum != 0xffff)
		return 0;
	if (inbuf.ip_h.protocol != SOL_UDP)
		return 0;
	if (inbuf.udp_h.uh_sport != htons(DHCP_SERVERPORT))
		return 0;
	if (inbuf.udp_h.uh_dport != htons(DHCP_CLIENTPORT))
		return 0;
	if (memcmp(inbuf.bootp_h.xid, data->xid, sizeof(data->xid)))
		return 0;
	if (memcmp(inbuf.bootp_h.chaddr, data->macaddr, ETH_ALEN))
		return 0;
	if (memcmp(inbuf.dhcp_h.dhcp_cookie, dhcp_cookie, sizeof(dhcp_cookie)))
		return 0;
	if (inbuf.bootp_h.op != 2) // BOOTREPLY
		return 0;
	return 1;
}

/* mask to prefix conversion. e.g.: 255.255.255.0 -> 24 */
static uint8_t mask2prefix(uint32_t mask) {
	int i;
	for (i = 0; i < 32; i++, mask >>= 1)
		if (mask & 1)
			break;
	return 32 - i;
}

static int dhcp_get(int sendtype, int fd, int timerfd, const struct sockaddr_ll *dest_addr,
                    struct dhcpdata *data, int timeout_ms) {
	int type;
	switch (sendtype) {
		case DHCPDISCOVER:   type = DHCPOFFER; break;
		case DHCPREQUEST:    type = DHCPACK; break;
		case DHCP_R_REQUEST: type = DHCPACK; break;
		default:
			return errno = EINVAL, -1;
	}
	struct dhcp_pkt inbuf;
	struct pollfd pfd[2] = {
		{ .fd = fd,      .events = POLLIN, .revents = 0 },
		{ .fd = timerfd, .events = POLLIN, .revents = 0 }
	};
	nfds_t nfds = (timerfd >= 0) ? 2 : 1;
	int timeout = timeout_ms;
	struct timeval start;
	struct timeval end;
	struct timeval timediff;

	for (;;) {
		int event;
		gettimeofday(&start, NULL);
		event = poll(pfd, nfds, timeout);
		if (event < 0)
			return -1;
		if (event == 0)
			return errno = ETIME, -1;
		if (nfds == 2 && (pfd[1].revents & POLLIN))
			return errno = ETIMEDOUT, -1;

		if (pfd[0].revents & POLLIN) {
			ssize_t inbuflen = ioth_recvfrom(fd, &inbuf, sizeof(inbuf), 0, NULL, NULL);
			if (inbuflen > 0 && check_consistency(inbuf, (size_t)inbuflen, data)) {
				FILE *optf = fmemopen(&inbuf.options, MAXOPT, "r");
				uint8_t answ_type = 0;
				uint8_t *answ_server = NULL;
				uint8_t answ_prefix = 0;
				uint32_t answ_leasetime = 0;
				/* first scan */
				for (;;) {
					int opt_type = getc(optf);
					if (opt_type == OPTION_PAD)
						continue;
					if (opt_type == EOF || opt_type == OPTION_END)
						break;
					int opt_len_i = getc(optf);
					if (opt_len_i == EOF)
						break;
					unsigned int opt_len = (unsigned int)opt_len_i;
					long next_opt = ftell(optf) + opt_len;
					switch (opt_type) {
						case OPTION_TYPE: answ_type = (uint8_t)getc(optf); break;
						case OPTION_SERVID: answ_server = inbuf.options + ftell(optf); break;
						case OPTION_MASK:
							answ_prefix = mask2prefix(
									((uint32_t)getc(optf) << 24) |
									((uint32_t)getc(optf) << 16) |
									((uint32_t)getc(optf) << 8) |
									(uint32_t)getc(optf));
							break;
						case OPTION_LEASETIME:
							answ_leasetime = ((uint32_t)getc(optf) << 24) |
									((uint32_t)getc(optf) << 16) |
									((uint32_t)getc(optf) << 8) |
									(uint32_t)getc(optf);
							break;
					}
					fseek(optf, next_opt, SEEK_SET);
				}
				fclose(optf);

				/* DHCPNAK accounted for only in REQUESTING/RENEW/REBIND */
				if (answ_type == DHCPNAK && sendtype != DHCPDISCOVER)
					return errno = ECANCELED, -1;

				if (answ_type == type && answ_server) {
					memcpy(&data->serveraddr, answ_server, sizeof(data->serveraddr));
					memcpy(&data->clientaddr, inbuf.bootp_h.yiaddr, sizeof(data->clientaddr));
					if (answ_type == DHCPOFFER)
						return dhcp_send(DHCPREQUEST, fd, -1, dest_addr, data, BROADCASTADDR);
					else if (answ_type == DHCPACK) {
						/* Store lease parameters privately in this thread's dhcpdata */
						data->prefixlen = answ_prefix;
						data->leasetime = answ_leasetime;
						data->router.s_addr = 0;

						optf = fmemopen(&inbuf.options, MAXOPT, "r");
						/* second scan: extract router locally, DNS/domain is kept in confdata */
						for (;;) {
							int opt_type = getc(optf);
							if (opt_type == OPTION_PAD)
								continue;
							if (opt_type == EOF || opt_type == OPTION_END)
								break;
							int opt_len_i = getc(optf);
							if (opt_len_i == EOF)
								break;
							unsigned int opt_len = (unsigned int)opt_len_i;
							long pos = ftell(optf);
							long next_opt = pos + opt_len;
							switch (opt_type) {
								case OPTION_ROUTER:
									if (opt_len >= 4 && data->router.s_addr == 0)
										memcpy(&data->router, inbuf.options + pos, 4);
									break;
								case OPTION_DNS:
									ioth_confdata_add(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_DNS,
											data->timestamp, 0, inbuf.options + pos, opt_len);
									break;
								case OPTION_DOMNAME: {
									char domname[opt_len + 1];
									snprintf(domname, opt_len + 1, "%.*s", opt_len, inbuf.options + pos);
									ioth_confdata_add(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_DOMAIN,
											data->timestamp, 0, domname, opt_len + 1);
									break;
								}
							}
							fseek(optf, next_opt, SEEK_SET);
						}
						fclose(optf);
						ioth_confdata_free(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_DNS, data->timestamp);
						ioth_confdata_free(data->stack, data->ifindex, IOTH_CONFDATA_DHCP4_DOMAIN, data->timestamp);
						ioth_confdata_write_timestamp(data->stack, data->ifindex,
								IOTH_CONFDATA_DHCP4_TIMESTAMP, data->timestamp);
						return 0;
					} else
						return errno = EFAULT, -1;
				}
			}
		}

		/* Spurious packet received: wait for remaining backoff time */
		gettimeofday(&end, NULL);
		timersub(&end, &start, &timediff);
		timeout -= timediff.tv_sec * 1000 + timediff.tv_usec / 1000;
		if (timeout <= 0)
			return errno = ETIME, -1;
	}
}

static int iothconf_dhcp_proto(struct ioth *stack, unsigned int ifindex, const char *fqdn,
                               uint32_t config_flags, uint32_t instance_id,
                               int *packet_socket_out, struct dhcpdata *out_data) {
	(void)config_flags;
	int packet_socket = dhcp_open_packet_socket(stack, ifindex);
	if (packet_socket < 0)
		return -1;
	*packet_socket_out = packet_socket;
	struct sockaddr_ll sll = {
		.sll_family   = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_ifindex  = (int)ifindex,
		.sll_halen    = ETH_ALEN,
		.sll_addr     = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	};
	struct dhcpdata dhcpdata = {
		.stack       = stack,
		.ifindex     = ifindex,
		.instance_id = instance_id,
		.xid         = {0, 0, 0, 0},
		.fqdn        = fqdn,
		.timestamp   = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP)
	};
	ioth_linkgetaddr(stack, ifindex, dhcpdata.macaddr);
	int rv = dhcp_send(DHCPDISCOVER, packet_socket, -1, &sll, &dhcpdata, BROADCASTADDR);
	ioth_close(packet_socket);
	*packet_socket_out = -1;
	if (rv == 0 && out_data)
		*out_data = dhcpdata;
	return rv;
}

/* ============================================================================
 * Thread management 
 * ============================================================================ */

#ifndef IOTH_CONFDATA_THREAD_TIMESTAMP
#define IOTH_CONFDATA_THREAD_TIMESTAMP 0x30
#endif
#define IOTH_CONFDATA_THREAD_DHCP4     0x31

struct dhcp_thread_info {
	pthread_t thread_id;
	uint32_t instance_id;
	int status;
	int active;
};

struct dhcp_thread_query {
	pthread_t thread_id;
	uint32_t instance_id;
	int match_by_tid;
	int status;
	int found;
};

struct dhcp_thread_args {
	struct ioth *stack;
	unsigned int ifindex;
	const char *fqdn;
	uint32_t config_flags;
	uint32_t instance_id;
	int state;
};

/* Synchronizes thread registration in ioth_confdata before the new thread starts executing */
static pthread_mutex_t thread_reg_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Callbacks for ioth_confdata_forall */
static int _set_thread_status_cb(void *data, void *arg) {
	struct dhcp_thread_info *info = data;
	struct dhcp_thread_query *q = arg;
	if (pthread_equal(info->thread_id, q->thread_id)) {
		info->status = q->status;
		q->found = 1;
		return IOTH_CONFDATA_FORALL_BREAK;
	}
	return 0;
}

static int _get_thread_info_cb(void *data, void *arg) {
	struct dhcp_thread_info *info = data;
	struct dhcp_thread_query *q = arg;
	int match = q->match_by_tid
		? pthread_equal(info->thread_id, q->thread_id)
		: (info->instance_id == q->instance_id);
	if (match && info->active) {
		q->thread_id = info->thread_id;
		q->instance_id = info->instance_id;
		q->status = info->status;
		q->found = 1;
		return IOTH_CONFDATA_FORALL_BREAK;
	}
	return 0;
}

static int _del_thread_info_cb(void *data, void *arg) {
	struct dhcp_thread_info *info = data;
	pthread_t *target = arg;
	if (pthread_equal(info->thread_id, *target))
		return IOTH_CONFDATA_FORALL_DELETE | IOTH_CONFDATA_FORALL_BREAK;
	return 0;
}

static int _has_other_active_lease_cb(void *data, void *arg) {
	struct dhcp_thread_info *info = data;
	struct dhcp_thread_query *q = arg;
	if (info->active &&
	    !pthread_equal(info->thread_id, q->thread_id) &&
	    (info->status == BOUND || info->status == RENEW || info->status == REBIND)) {
		q->found = 1;
		return IOTH_CONFDATA_FORALL_BREAK;
	}
	return 0;
}

static void set_dhcp_thread_status(struct ioth *stack, unsigned int ifindex, int status) {
	struct dhcp_thread_query q = {
		.thread_id = pthread_self(),
		.status = status
	};
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, _set_thread_status_cb, &q);
}

static void del_dhcp_thread_entry(struct ioth *stack, unsigned int ifindex, pthread_t tid) {
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, _del_thread_info_cb, &tid);
}

int ioth_dhcp_thread(struct ioth *stack, unsigned int ifindex, const char *fqdn,
                     uint32_t config_flags, uint32_t instance_id, int state);

static void *dhcp_pthread_runner(void *arg) {
	struct dhcp_thread_args *args = (struct dhcp_thread_args *)arg;

	/* Wait until parent finishes registering this thread in ioth_confdata */
	pthread_mutex_lock(&thread_reg_mutex);
	pthread_mutex_unlock(&thread_reg_mutex);
    int result = 0;
	pthread_cleanup_push(free, args);

	result = ioth_dhcp_thread(args->stack,
	                              args->ifindex,
	                              args->fqdn,
	                              args->config_flags,
	                              args->instance_id,
	                              args->state);

	del_dhcp_thread_entry(args->stack, args->ifindex, pthread_self());

	pthread_cleanup_pop(1); /* frees args */
	return (void *)(intptr_t)result;
}

/* Launch a DHCPv4 thread with a distinct instance_id */
int iothconf_dhcp_start(struct ioth *stack, unsigned int ifindex, const char *fqdn,
                        uint32_t config_flags, uint32_t instance_id, pthread_t *tid_out) {
	pthread_t dhcp_thread_id = 0;

	struct dhcp_thread_args *args = malloc(sizeof(*args));
	if (!args)
		return -1;

	args->stack = stack;
	args->ifindex = ifindex;
	args->fqdn = fqdn;
	args->config_flags = config_flags;
	args->instance_id = instance_id;
	args->state = INIT;

	pthread_mutex_lock(&thread_reg_mutex);
	int ret = pthread_create(&dhcp_thread_id, NULL, dhcp_pthread_runner, args);
	if (ret != 0) {
		pthread_mutex_unlock(&thread_reg_mutex);
		free(args);
		return ret;
	}
	ioth_confdata_add_data(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, 1, 0,
			struct dhcp_thread_info,
			.thread_id = dhcp_thread_id,
			.instance_id = instance_id,
			.status = UNBOUND,
			.active = 1);
	pthread_mutex_unlock(&thread_reg_mutex);

	printf("D_INFO creato id=%ld (instance_id=%u)\n", (long)dhcp_thread_id, instance_id);
	if (tid_out)
		*tid_out = dhcp_thread_id;
	return 0;
}

/*  Single-instance entry point (instance_id = 0) */
int iothconf_dhcp(struct ioth *stack, unsigned int ifindex, const char *fqdn, uint32_t config_flags) {
	return iothconf_dhcp_start(stack, ifindex, fqdn, config_flags, 0, NULL);
}

/* Kill a specific DHCPv4 thread by pthread_t */
int iothconf_dhcp_kill_tid(struct ioth *stack, unsigned int ifindex, pthread_t tid) {
	struct dhcp_thread_query q = {
		.thread_id = tid,
		.match_by_tid = 1
	};
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, _get_thread_info_cb, &q);
	if (!q.found)
		return 1;

	pthread_cancel(q.thread_id);
	pthread_join(q.thread_id, NULL);
	del_dhcp_thread_entry(stack, ifindex, q.thread_id);
	return 0;
}

/* Single-instance kill (targets instance_id = 0) */
int iothconf_dhcp_kill(struct ioth *stack, unsigned int ifindex) {
	struct dhcp_thread_query q = {
		.instance_id = 0,
		.match_by_tid = 0
	};
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, _get_thread_info_cb, &q);
	if (!q.found)
		return 1;
	return iothconf_dhcp_kill_tid(stack, ifindex, q.thread_id);
}

/* Query status of a specific DHCPv4 thread by pthread_t */
int iothconf_dhcp_info_tid(struct ioth *stack, unsigned int ifindex, pthread_t tid, int *status) {
	struct dhcp_thread_query q = {
		.thread_id = tid,
		.match_by_tid = 1
	};
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, _get_thread_info_cb, &q);
	if (!q.found)
		return -1;
	*status = q.status;
	return 0;
}

/* Single-instance status query (targets instance_id = 0) */
int iothconf_dhcp_info(struct ioth *stack, unsigned int ifindex, int *status) {
	struct dhcp_thread_query q = {
		.instance_id = 0,
		.match_by_tid = 0
	};
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4, _get_thread_info_cb, &q);
	if (!q.found)
		return -1;
	*status = q.status;
	return 0;
}

// Cleanup for ioth packet sockets
void ioth_close_clean(void *arg) {
	int fd = *(int *)arg;
	if (fd >= 0)
		ioth_close(fd);
}

// Cleanup for generic file descriptors
void fd_close_clean(void *arg) {
	int fd = *(int *)arg;
	if (fd >= 0)
		close(fd);
}

int set_timer_poll(int timerfd, struct itimerspec *tspec, uint32_t sec, struct pollfd *plfd) {
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

static void consume_timer(int timerfd) {
	uint64_t exp;
	ssize_t s = read(timerfd, &exp, sizeof(uint64_t));
	(void)s;
}

// IP and Leasetime add/update through Kernel (adds if missing else updates)
static int set_ipv4_lifetime(struct ioth *stack, unsigned int ifindex,
                             struct in_addr addr, uint8_t prefixlen, uint32_t leasetime) {
	struct {
		struct nlmsghdr h;
		struct ifaddrmsg i;
		struct __nlinline_ipv4attr local;
		struct __nlinline_ipv4attr address;
		struct {
			struct nlattr h;
			struct ifa_cacheinfo info;
		} cacheinfo;
	} msg = {
		.h.nlmsg_len = sizeof(msg),
		.h.nlmsg_type = RTM_NEWADDR,
		.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
		.h.nlmsg_seq = 1,
		.i.ifa_family = AF_INET,
		.i.ifa_prefixlen = prefixlen,
		.i.ifa_scope = RT_SCOPE_UNIVERSE,
		.i.ifa_index = ifindex,
		.local.h.nla_len = sizeof(msg.local),
		.local.h.nla_type = IFA_LOCAL,
		.address.h.nla_len = sizeof(msg.address),
		.address.h.nla_type = IFA_ADDRESS,
		.cacheinfo.h.nla_len = sizeof(msg.cacheinfo),
		.cacheinfo.h.nla_type = IFA_CACHEINFO,
		.cacheinfo.info.ifa_prefered = leasetime,
		.cacheinfo.info.ifa_valid = leasetime,
	};

	memcpy(&msg.local.addr, &addr, sizeof(addr));
	memcpy(&msg.address.addr, &addr, sizeof(addr));

	return ioth_nldialog(stack, &msg);
}

/* Remove only this thread's IP; remove default route only if no other thread holds an active lease */
static void halt_network(struct ioth *stack, unsigned int ifindex,
                         struct in_addr client_addr, uint8_t prefixlen,
                         struct in_addr router_addr) {
	if (client_addr.s_addr != 0 && prefixlen > 0) {
		ioth_ipaddr_del(stack, AF_INET, &client_addr, prefixlen, ifindex);
	}
	struct dhcp_thread_query q = { .thread_id = pthread_self(), .found = 0 };
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP4,
	                     _has_other_active_lease_cb, &q);
	if (!q.found) {
		if (router_addr.s_addr != 0)
			ioth_iproute_del(stack, AF_INET, NULL, 0, &router_addr, 0);
		ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_DHCP4_DNS, 0);
		ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_DHCP4_DOMAIN, 0);
		ioth_confdata_del_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP);
	}
}

int ioth_dhcp_thread(struct ioth *stack, unsigned int ifindex, const char *fqdn,
                     uint32_t config_flags, uint32_t instance_id, int state) {
	printf("[inst %u] ioth_dhcp_thread dentro\n", instance_id);
	int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timerfd == -1) {
		perror("timerfd_create");
		return 1;
	}
	struct itimerspec timerspec1, timerspec2;
	struct pollfd plfd;

	struct in_addr dhcp_server_add = {0}, client_addr = {0}, router_addr = {0};
	uint32_t leasetime = 0;
	uint8_t prefixlen = 0;

	int packet_socket = -1;

	pthread_cleanup_push(fd_close_clean, &timerfd);
	pthread_cleanup_push(ioth_close_clean, &packet_socket);

	while (state != UNBOUND) {
		switch (state) {
			case INIT: {
				pthread_testcancel();
				set_dhcp_thread_status(stack, ifindex, INIT);
				printf("[inst %u] Enter INIT\n", instance_id);

				struct dhcpdata acquired = {0};
				int rv = iothconf_dhcp_proto(stack, ifindex, fqdn, config_flags,
				                             instance_id, &packet_socket, &acquired);
				if (rv == 0) {
					dhcp_server_add = acquired.serveraddr;
					client_addr     = acquired.clientaddr;
					router_addr     = acquired.router;
					prefixlen       = acquired.prefixlen;
					leasetime       = acquired.leasetime;
					state = BOUND;
					printf("[inst %u] BOUND raggiunto\n", instance_id);
				} else if (errno == ECANCELED || errno == ETIME) {
					printf("[inst %u] INIT fallito (%s), riprovo in INIT\n",
					       instance_id, strerror(errno));
					state = INIT;
				} else {
					state = UNBOUND;
					printf("[inst %u] UNBOUND raggiunto\n", instance_id);
				}
				break;
			}

			case BOUND: {
				set_dhcp_thread_status(stack, ifindex, BOUND);
				printf("[inst %u] Enter BOUND\n", instance_id);

				/* add/updates IP and kernel lease lifetime only for this thread's ip */
				if (set_ipv4_lifetime(stack, ifindex, client_addr, prefixlen, leasetime) < 0) {
					perror("set_ipv4_lifetime");
				}
				if (router_addr.s_addr != 0) {
					if (ioth_iproute_add(stack, AF_INET, NULL, 0, &router_addr, 0) < 0 &&
					    errno != EEXIST) {
						perror("ioth_iproute_add");
					}
				}

				pthread_testcancel();
				printf("[inst %u] ottenuto leasetime %u\n", instance_id, leasetime);

				if (leasetime == DHCP_INFINITE_LEASE) {
					for (;;) {
						pthread_testcancel();
						pause();
					}
				}

				// loads T1 = 1/2 of leasetime
				if (set_timer_poll(timerfd, &timerspec1, leasetime >> 1, &plfd) == 1) {
					state = UNBOUND;
					break;
				}
				pthread_testcancel();

				int ret1 = poll(&plfd, 1, -1);
				if (ret1 == -1) {
					if (errno == EINTR)
						continue;
					perror("Errore nella poll");
					state = UNBOUND;
					break;
				}

				if (plfd.revents & POLLIN) {
					consume_timer(timerfd);
					printf("[inst %u] concluso T1\n", instance_id);
					uint32_t t2_delta = (uint32_t)(((uint64_t)leasetime * 7ULL) >> 3) - (leasetime >> 1);
					if (set_timer_poll(timerfd, &timerspec2, t2_delta, &plfd) == 1) {
						state = UNBOUND;
						break;
					}
					state = RENEW;
				}
				break;
			}

			case RENEW: {
				pthread_testcancel();
				set_dhcp_thread_status(stack, ifindex, RENEW);
				printf("[inst %u] Enter RENEW\n", instance_id);

				packet_socket = dhcp_open_packet_socket(stack, ifindex);
				if (packet_socket < 0) {
					state = UNBOUND;
					break;
				}
				struct sockaddr_ll sll = {
					.sll_family   = AF_PACKET,
					.sll_protocol = htons(ETH_P_IP),
					.sll_ifindex  = (int)ifindex,
					.sll_halen    = ETH_ALEN,
					.sll_addr     = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				};
				struct dhcpdata dhcpdata = {
					.stack       = stack,
					.ifindex     = ifindex,
					.instance_id = instance_id,
					.xid         = {0, 0, 0, 0},
					.fqdn        = fqdn,
					.timestamp   = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP),
					.serveraddr  = dhcp_server_add,
					.clientaddr  = client_addr,
					.router      = router_addr,
					.prefixlen   = prefixlen,
					.leasetime   = leasetime
				};
				ioth_linkgetaddr(stack, ifindex, dhcpdata.macaddr);

				int rv = dhcp_send(DHCP_R_REQUEST, packet_socket, timerfd, &sll,
				                   &dhcpdata, dhcp_server_add.s_addr);
				ioth_close(packet_socket);
				packet_socket = -1;

				if (rv == 0) {
					dhcp_server_add = dhcpdata.serveraddr;
					client_addr     = dhcpdata.clientaddr;
					router_addr     = dhcpdata.router;
					prefixlen       = dhcpdata.prefixlen;
					leasetime       = dhcpdata.leasetime;
					state = BOUND;
				} else if (errno == ECANCELED) {
					printf("[inst %u] Ricevuto DHCPNAK in RENEW: halt network -> INIT\n", instance_id);
					halt_network(stack, ifindex, client_addr, prefixlen, router_addr);
					client_addr.s_addr = 0;
					router_addr.s_addr = 0;
					state = INIT;
				} else if (poll(&plfd, 1, 0) > 0 && (plfd.revents & POLLIN)) {
					printf("[inst %u] Scaduto T2\n", instance_id);
					consume_timer(timerfd);
					if (set_timer_poll(timerfd, &timerspec2, leasetime >> 3, &plfd) == 1) {
						state = UNBOUND;
						break;
					}
					state = REBIND;
				}
				break;
			}

			case REBIND: {
				pthread_testcancel();
				set_dhcp_thread_status(stack, ifindex, REBIND);
				printf("[inst %u] Enter REBIND\n", instance_id);

				packet_socket = dhcp_open_packet_socket(stack, ifindex);
				if (packet_socket < 0) {
					state = UNBOUND;
					break;
				}
				struct sockaddr_ll sll = {
					.sll_family   = AF_PACKET,
					.sll_protocol = htons(ETH_P_IP),
					.sll_ifindex  = (int)ifindex,
					.sll_halen    = ETH_ALEN,
					.sll_addr     = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
				};
				struct dhcpdata dhcpdata = {
					.stack       = stack,
					.ifindex     = ifindex,
					.instance_id = instance_id,
					.xid         = {0, 0, 0, 0},
					.fqdn        = fqdn,
					.timestamp   = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP4_TIMESTAMP),
					.clientaddr  = client_addr,
					.router      = router_addr,
					.prefixlen   = prefixlen,
					.leasetime   = leasetime
				};
				ioth_linkgetaddr(stack, ifindex, dhcpdata.macaddr);

				int rv = dhcp_send(DHCP_R_REQUEST, packet_socket, timerfd, &sll,
				                   &dhcpdata, BROADCASTADDR);
				ioth_close(packet_socket);
				packet_socket = -1;

				if (rv == 0) {
					dhcp_server_add = dhcpdata.serveraddr;
					client_addr     = dhcpdata.clientaddr;
					router_addr     = dhcpdata.router;
					prefixlen       = dhcpdata.prefixlen;
					leasetime       = dhcpdata.leasetime;
					state = BOUND;
				} else if (errno == ECANCELED) {
					printf("[inst %u] Ricevuto DHCPNAK in REBIND: halt network -> INIT\n", instance_id);
					halt_network(stack, ifindex, client_addr, prefixlen, router_addr);
					client_addr.s_addr = 0;
					router_addr.s_addr = 0;
					state = INIT;
				} else if (poll(&plfd, 1, 0) > 0 && (plfd.revents & POLLIN)) {
					printf("[inst %u] Lease scaduto in REBIND: halt network -> INIT\n", instance_id);
					consume_timer(timerfd);
					halt_network(stack, ifindex, client_addr, prefixlen, router_addr);
					client_addr.s_addr = 0;
					router_addr.s_addr = 0;
					state = INIT;
				}
				break;
			}

			default:
				break;
		}
	}

	set_dhcp_thread_status(stack, ifindex, UNBOUND);
	pthread_cleanup_pop(0);
	pthread_cleanup_pop(0);

	close(timerfd);
	timerfd = -1;
	return UNBOUND;
}