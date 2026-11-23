/*
 *   iothconf_thread_dhcpv6.c: auto configuration library for ioth
 *       dhcpv6: threaded multi-IA_NA client implementation of RFC 9915 and RFC 4704 (fqdn)
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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <poll.h>
#include <endian.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <ioth.h>
#include <iothconf.h>
#include <iothconf_mod.h>
#include <iothconf_hash.h>
#include "iothconf_dns.h"
#include "iothconf_data.h"

/* UDP Ports */
#define DHCP6_CLIENTPORT 546
#define DHCP6_SERVERPORT 547

/* Message Types */
#define DHCP6_SOLICIT     1
#define DHCP6_ADVERTISE   2
#define DHCP6_REQUEST     3
#define DHCP6_CONFIRM     4
#define DHCP6_RENEW       5
#define DHCP6_REBIND      6
#define DHCP6_REPLY       7
#define DHCP6_RELEASE     8
#define DHCP6_DECLINE     9
#define DHCP6_RECONFIGURE 10
#define DHCP6_INFO_REQ    11

/* Option Codes */
#define DHCP6_OPT_CLIENTID      1
#define DHCP6_OPT_SERVERID      2
#define DHCP6_OPT_IA_NA         3
#define DHCP6_OPT_IAADDR        5
#define DHCP6_OPT_ORO           6
#define DHCP6_OPT_PREFERENCE    7
#define DHCP6_OPT_ELAPSED_TIME  8
#define DHCP6_OPT_STATUS_CODE   13
#define DHCP6_OPT_RAPID_COMMIT  14
#define DHCP6_OPT_DNS_SERVERS   23
#define DHCP6_OPT_DOMAIN_LIST   24
#define DHCP6_OPT_CLIENT_FQDN   39
#define DHCP6_OPT_SOL_MAX_RT    82
#define DHCP6_OPT_INF_MAX_RT    83

/* Status Codes */
#define DHCP6_STATUS_SUCCESS       0
#define DHCP6_STATUS_UNSPECFAIL    1
#define DHCP6_STATUS_NOADDRSAVAIL  2
#define DHCP6_STATUS_NOBINDING     3
#define DHCP6_STATUS_NOTONLINK     4
#define DHCP6_STATUS_NOPREFIXAVAIL 6

/* Transmission and Retransmission Parameters (seconds) */
#define SOL_MAX_DELAY      1
#define SOL_TIMEOUT        1
#define SOL_MAX_RT_DEFAULT 3600
#define SOL_MAX_RT_MIN     60
#define SOL_MAX_RT_MAX     86400
#define REQ_TIMEOUT        1
#define REQ_MAX_RT         30
#define REQ_MAX_RC         10
#define REN_TIMEOUT        10
#define REN_MAX_RT         600
#define REB_TIMEOUT        10
#define REB_MAX_RT         600
#define DEC_TIMEOUT        1
#define DEC_MAX_RC         4

/* Infinity */
#define DHCP6_INFINITE_TIME 0xffffffffU

/* Rate Limiting (20 messages in 20 seconds per interface) */
#define DHCP6_RL_CAPACITY 20

/* All_DHCP_Relay_Agents_and_Servers (ff02::1:2) */
#define MCAST_ALL_ROUTERS \
	{0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x02}

/* Thread states  */
#ifndef UNBOUND
#define UNBOUND -1
#define INIT     0
#define BOUND    1
#define RENEW    2
#define REBIND   3
#endif


#ifndef IOTH_CONFDATA_THREAD_TIMESTAMP
#define IOTH_CONFDATA_THREAD_TIMESTAMP 0x30
#endif
#define IOTH_CONFDATA_THREAD_DHCP6     0x32

#define DHCP6_MAX_SERVERID 130 /* 2-byte type + max 128 bytes */

/* DUID-LL type(2)=3, hwtype(2)=1 (Ethernet), mac(6) = 10 bytes */
#define DHCP6_DUID_LL_LEN 10

/* Rate limiter state (token bucket) */
struct dhcp6_ratelimit {
	double tokens;
	struct timespec last_refill;
};

/* Per-IA_NA state maintained privately by the DHCPv6 thread */
struct dhcp6_iana_entry {
	uint8_t iaid[4];
	int has_addr;
	int dad_checked;
	int decline_pending;
	struct in6_addr addr;
	uint32_t preferred_lt;
	uint32_t valid_lt;
	uint32_t t1;
	uint32_t t2;
	int t1_infinite;
	int t2_infinite;
	int valid_infinite;
	struct timespec t1_deadline;
	struct timespec t2_deadline;
	struct timespec valid_deadline;
	uint16_t last_status;
};

/* Offered IA_NA sub-options collected from an ADVERTISE message */
struct dhcp6_adv_iana {
	int has_valid_addr;
	uint8_t *subopts;
	uint16_t subopts_len;
};

struct dhcp6_advertise_choice {
	int valid;
	uint8_t preference;
	size_t valid_iana_count;
	uint8_t serverid[DHCP6_MAX_SERVERID];
	uint16_t serveridlen;
	struct dhcp6_adv_iana *ianas;
	size_t num_iana;
    /* need to track SOL_MAX_RT consistency across Advertises */
	int sol_max_rt_seen;
	int sol_max_rt_conflict;
	uint32_t sol_max_rt_val;
};

/* Temporary per-IA_NA parsing state for a single incoming ADVERTISE or REPLY */
struct dhcp6_rx_iana {
	int present;
	uint32_t t1;
	uint32_t t2;
	uint8_t *subopts;
	uint16_t subopts_len;
	uint16_t status;
	int has_valid_addr;
	int has_zero_valid_addr;
	struct in6_addr valid_addr;
	uint32_t valid_pref_lt;
	uint32_t valid_valid_lt;
	struct in6_addr zero_addr;
};

struct dhcp6data {
	struct ioth *stack;
	unsigned int ifindex;
	time_t timestamp;
	uint8_t tid[3];
	uint8_t macaddr[ETH_ALEN];
	uint8_t duid[DHCP6_DUID_LL_LEN];
	const char *fqdn;
	uint8_t serverid[DHCP6_MAX_SERVERID];
	uint16_t serveridlen;
	struct dhcp6_iana_entry *ianas;
	size_t num_iana;
	const struct dhcp6_advertise_choice *req_adv; /* non-NULL during REQUEST after SOLICIT */
	uint32_t sol_max_rt;
	struct dhcp6_ratelimit rl;
};

/* Monotonic time helpers */
static inline struct timespec ts_now(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts;
}

static inline struct timespec ts_add_sec(struct timespec base, uint32_t sec) {
	base.tv_sec += (time_t)sec;
	return base;
}

static inline int ts_cmp(struct timespec a, struct timespec b) {
	if (a.tv_sec != b.tv_sec)
		return (a.tv_sec < b.tv_sec) ? -1 : 1;
	if (a.tv_nsec != b.tv_nsec)
		return (a.tv_nsec < b.tv_nsec) ? -1 : 1;
	return 0;
}

static inline uint32_t ts_rem_sec(struct timespec deadline, struct timespec now) {
	if (ts_cmp(deadline, now) <= 0)
		return 0;
	time_t diff = deadline.tv_sec - now.tv_sec;
	if (deadline.tv_nsec < now.tv_nsec && diff > 0)
		diff--;
	return (diff <= 0) ? 0 : (uint32_t)diff;
}

/* Binary stream helpers */
static inline void fput_int8(FILE *f, uint8_t data) {
	fputc(data, f);
}

static inline void fput_int16(FILE *f, uint16_t data) {
	fputc((data >> 8) & 0xff, f);
	fputc(data & 0xff, f);
}

static inline void fput_int32(FILE *f, uint32_t data) {
	fputc((data >> 24) & 0xff, f);
	fputc((data >> 16) & 0xff, f);
	fputc((data >> 8) & 0xff, f);
	fputc(data & 0xff, f);
}

static inline void fput_data(FILE *f, const void *data, uint16_t len) {
	if (len > 0)
		fwrite(data, len, 1, f);
}

static inline int fget_int8(FILE *f) {
	return fgetc(f);
}

static inline int fget_int16(FILE *f) {
	int hi = fget_int8(f);
	int lo = fget_int8(f);
	if (hi == EOF || lo == EOF)
		return EOF;
	return (hi << 8) | lo;
}

static inline uint32_t fget_int32(FILE *f) {
	uint32_t b0 = (uint32_t)(fget_int8(f) & 0xff);
	uint32_t b1 = (uint32_t)(fget_int8(f) & 0xff);
	uint32_t b2 = (uint32_t)(fget_int8(f) & 0xff);
	uint32_t b3 = (uint32_t)(fget_int8(f) & 0xff);
	return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

static inline void fget_data(FILE *f, void *data, uint16_t len) {
	if (len > 0) {
		size_t retval = fread(data, len, 1, f);
		(void)retval;
	}
}

/* Build DUID-LL from MAC address */
static void dhcp6_build_duid_ll(uint8_t duid[DHCP6_DUID_LL_LEN], const uint8_t macaddr[ETH_ALEN]) {
	duid[0] = 0x00;
	duid[1] = 0x03; /* DUID-Type = 3 (DUID-LL) */
	duid[2] = 0x00;
	duid[3] = 0x01; /* Hardware type = 1 (Ethernet) */
	memcpy(duid + 4, macaddr, ETH_ALEN);
}

/* Deterministic, unique IAIDs per IA_NA consistent across restarts macaddr+2+i*/
static void dhcp6_init_iaids(struct dhcp6_iana_entry *ianas, size_t num_iana,
                             const uint8_t macaddr[ETH_ALEN]) {
	uint32_t base_net = 0;
	memcpy(&base_net, macaddr + 2, 4);
	uint32_t base_host = ntohl(base_net);
	for (size_t i = 0; i < num_iana; i++) {
		uint32_t id_net = htonl(base_host + (uint32_t)i);
		memcpy(ianas[i].iaid, &id_net, 4);
	}
}

/* Build a single IAADDR option buffer for RENEW/REBIND/DECLINE (lifetimes=0) */
static void dhcp6_build_iaaddr_opt(uint8_t out[28], const struct in6_addr *addr) {
	out[0] = (DHCP6_OPT_IAADDR >> 8) & 0xff;
	out[1] = DHCP6_OPT_IAADDR & 0xff;
	out[2] = 0x00;
	out[3] = 24; /* option-len = 24 */
	memcpy(out + 4, addr, 16);
	memset(out + 20, 0, 8); /* preferred-lifetime = 0, valid-lifetime = 0 */
}

/* Zero lifetimes in IAADDR options before sending Request */
static void ia6_lifetime_zero(uint8_t *iana_addr, uint16_t iana_addrlen) {
	if (!iana_addr || iana_addrlen == 0)
		return;
	uint8_t *p = iana_addr;
	uint8_t *limit = iana_addr + iana_addrlen;
	while (p + 4 <= limit) {
		uint16_t opt_type = (uint16_t)((p[0] << 8) | p[1]);
		uint16_t opt_len = (uint16_t)((p[2] << 8) | p[3]);
		if (p + 4 + opt_len > limit)
			break;
		if (opt_type == DHCP6_OPT_IAADDR && opt_len >= 24) {
			memset(p + 20, 0, 8);
		}
		p += 4 + opt_len;
	}
}

static unsigned int lname2dns6(const char *name, char *out) {
	unsigned int len = 0;
	while (*name) {
		char *itemlen = out++;
		while (*name != 0 && *name != '.')
			*out++ = *name++;
		if (*name == '.') name++;
		*itemlen = (char)(out - itemlen - 1);
		len += (unsigned char)(*itemlen) + 1;
	}
	*out = 0;
	return len + 1;
}

/* Advertise choice memory management */
static void dhcp6_adv_free(struct dhcp6_advertise_choice *adv) {
	if (!adv)
		return;
	if (adv->ianas) {
		for (size_t i = 0; i < adv->num_iana; i++) {
			free(adv->ianas[i].subopts);
		}
		free(adv->ianas);
		adv->ianas = NULL;
	}
	adv->valid = 0;
	adv->valid_iana_count = 0;
	adv->num_iana = 0;
}

/* Packet composing helpers */
static void dhcp6_add_head(FILE *f, uint8_t type, const uint8_t tid[3]) {
	fput_int8(f, type);
	fput_data(f, tid, 3);
}

static void dhcp6_add_option(FILE *f, uint16_t type, uint16_t len) {
	fput_int16(f, type);
	fput_int16(f, len);
}

static void dhcp6_add_opt_clientid(FILE *f, const uint8_t duid[DHCP6_DUID_LL_LEN]) {
	dhcp6_add_option(f, DHCP6_OPT_CLIENTID, DHCP6_DUID_LL_LEN);
	fput_data(f, duid, DHCP6_DUID_LL_LEN);
}

static void dhcp6_add_opt_serverid(FILE *f, const uint8_t *serverid, uint16_t serveridlen) {
	if (serverid && serveridlen > 0) {
		dhcp6_add_option(f, DHCP6_OPT_SERVERID, serveridlen);
		fput_data(f, serverid, serveridlen);
	}
}

static void dhcp6_add_opt_oro(FILE *f, ...) {
	int len;
	va_list ap;
	va_start(ap, f);
	for (len = 0; va_arg(ap, unsigned int) != 0; len++)
		;
	va_end(ap);
	dhcp6_add_option(f, DHCP6_OPT_ORO, (uint16_t)(sizeof(uint16_t) * len));
	va_start(ap, f);
	for (;;) {
		uint16_t opt = (uint16_t)va_arg(ap, unsigned int);
		if (opt == 0) break;
		fput_int16(f, opt);
	}
	va_end(ap);
}

static void dhcp6_add_opt_elapsed_time(FILE *f, uint16_t value) {
	dhcp6_add_option(f, DHCP6_OPT_ELAPSED_TIME, 2);
	fput_int16(f, value);
}

static void dhcp6_add_opt_fqdn(FILE *f, const char *fqdn, uint8_t flags) {
	if (fqdn && *fqdn) {
		char out[strlen(fqdn) + 2];
		unsigned int len = lname2dns6(fqdn, out);
		dhcp6_add_option(f, DHCP6_OPT_CLIENT_FQDN, (uint16_t)(1 + len));
		fput_int8(f, flags);
		fput_data(f, out, (uint16_t)len);
	}
}

/*  Option-len = 12 + sublen, T1=0, T2=0 in client messages */
static void dhcp6_add_opt_iana(FILE *f, const uint8_t iaid[4],
                               const uint8_t *iana_addr, uint16_t iana_addrlen) {
	uint16_t sublen = (iana_addr && iana_addrlen > 0) ? iana_addrlen : 0;
	dhcp6_add_option(f, DHCP6_OPT_IA_NA, (uint16_t)(12 + sublen));
	fput_data(f, iaid, 4);
	fput_int32(f, 0); /* T1 = 0 in client messages */
	fput_int32(f, 0); /* T2 = 0 in client messages */
	if (sublen > 0)
		fput_data(f, iana_addr, sublen);
}

/* Rate limiting token bucket (20 msgs / 20s) */
static void dhcp6_rl_init(struct dhcp6_ratelimit *rl) {
	rl->tokens = DHCP6_RL_CAPACITY;
	clock_gettime(CLOCK_MONOTONIC, &rl->last_refill);
}

static int dhcp6_rl_wait(struct dhcp6_ratelimit *rl, int timerfd) {
	for (;;) {
		struct timespec now = ts_now();
		double elapsed = (double)(now.tv_sec - rl->last_refill.tv_sec) +
		                 (double)(now.tv_nsec - rl->last_refill.tv_nsec) / 1e9;
		if (elapsed > 0) {
			rl->tokens += elapsed;
			if (rl->tokens > DHCP6_RL_CAPACITY)
				rl->tokens = DHCP6_RL_CAPACITY;
			rl->last_refill = now;
		}
		if (rl->tokens >= 1.0) {
			rl->tokens -= 1.0;
			return 0;
		}
		int wait_ms = (int)((1.0 - rl->tokens) * 1000.0) + 1;
		if (timerfd >= 0) {//If we already have a timer T2 we don't want to timout in rl_wait
			struct pollfd pfd = { .fd = timerfd, .events = POLLIN, .revents = 0 };
			int ev = poll(&pfd, 1, wait_ms);
			if (ev < 0) {
				if (errno == EINTR) continue;
				return -1;
			}
			if (ev > 0 && (pfd.revents & POLLIN)) {
				errno = ETIMEDOUT;
				return -1;
			}
		} else {
			struct pollfd dummy = { .fd = -1, .events = 0, .revents = 0 };
			poll(&dummy, 0, wait_ms);
		}
	}
}

/* RAND in [-0.1, +0.1], or strictly (0, +0.1] if positive_only */
static double dhcp6_rand_factor(int positive_only) {
	uint32_t rnd = 0;
	if (getrandom(&rnd, sizeof(rnd), 0) != sizeof(rnd))
		rnd = (uint32_t)rand();
	if (positive_only) {
		return 0.001 + ((double)(rnd % 9900U) / 100000.0);
	}
	return ((double)(rnd % 20001U) / 100000.0) - 0.1;
}

static int dhcp6_next_rt_ms(int attempt, int prev_rt_ms, int irt_sec, int mrt_sec, int solicit_first) {
	double rt;
	if (attempt == 0) {
		double r = dhcp6_rand_factor(solicit_first);
		rt = (double)(irt_sec * 1000) * (1.0 + r);
	} else {
		double r = dhcp6_rand_factor(0);
		rt = (2.0 + r) * (double)prev_rt_ms;
	}
	if (mrt_sec > 0 && rt > (double)(mrt_sec * 1000)) {
		double r = dhcp6_rand_factor(0);
		rt = (double)(mrt_sec * 1000) * (1.0 + r);
	}
	return (rt < 100.0) ? 100 : (int)rt;
}

/*  Elapsed time in hundredths of a second, capped at 0xffff */
static uint16_t dhcp6_elapsed_hs(const struct timespec *start) {
	struct timespec now = ts_now();
	int64_t diff_ms = (int64_t)(now.tv_sec - start->tv_sec) * 1000LL +
	                  (int64_t)(now.tv_nsec - start->tv_nsec) / 1000000LL;
	if (diff_ms <= 0)
		return 0;
	int64_t hs = diff_ms / 10;
	return (hs > 0xffff) ? 0xffff : (uint16_t)hs;
}

/* Resolve T1/T2 when server sets them to 0 */
static void resolve_t1_t2(uint32_t *t1, uint32_t *t2, uint32_t preferred_lt, uint32_t valid_lt) {
	uint32_t base = (preferred_lt > 0 && preferred_lt != DHCP6_INFINITE_TIME) ? preferred_lt : valid_lt;
	if (*t1 == 0) {
		if (base == DHCP6_INFINITE_TIME)
			*t1 = DHCP6_INFINITE_TIME;
		else {
			*t1 = base >> 1; /* 0.5 * preferred_lifetime */
			if (*t1 == 0) *t1 = 1; /* MUST NOT transmit immediately  */
		}
	}
	if (*t2 == 0) {
		if (base == DHCP6_INFINITE_TIME)
			*t2 = DHCP6_INFINITE_TIME;
		else {
			*t2 = (uint32_t)(((uint64_t)base * 4ULL) / 5ULL); /* 0.8 * preferred_lifetime */
			if (*t2 <= *t1)
				*t2 = (*t1 < valid_lt) ? valid_lt : *t1 + 1;
		}
	}
}

/* Validate basic header: msg-type and transaction-id */
static int check_consistency6(int expected_type, const uint8_t *inbuf, size_t inbuflen,
                              const struct dhcp6data *data) {
	if (inbuflen < 4) return 0;
	if (inbuf[0] != expected_type) return 0;
	if (memcmp(inbuf + 1, data->tid, 3) != 0) return 0;
	return 1;
}

/* Opaque DUID comparison */
static int check_clientid6(FILE *f, uint16_t len, const uint8_t duid[DHCP6_DUID_LL_LEN]) {
	if (len != DHCP6_DUID_LL_LEN) return 0;
	uint8_t cmp[DHCP6_DUID_LL_LEN];
	fget_data(f, cmp, DHCP6_DUID_LL_LEN);
	return memcmp(cmp, duid, DHCP6_DUID_LL_LEN) == 0;
}

/* Match IAID against our configured IA_NA array; returns index or -1 */
static ssize_t find_iana_index(const struct dhcp6_iana_entry *ianas, size_t num_iana,
                               const uint8_t iaid[4]) {
	for (size_t i = 0; i < num_iana; i++) {
		if (memcmp(ianas[i].iaid, iaid, 4) == 0)
			return (ssize_t)i;
	}
	return -1;
}

/* Parse IA_NA sub-options (Status Code and IAADDRs) into dhcp6_rx_iana */
static int parse_iana_subopts(const uint8_t *sub, uint16_t sublen, struct dhcp6_rx_iana *out) {
	out->status = DHCP6_STATUS_SUCCESS;
	out->has_valid_addr = 0;
	out->has_zero_valid_addr = 0;
	if (!sub || sublen == 0)
		return 0;

	FILE *f = fmemopen((void *)sub, sublen, "r");
	if (!f)
		return -1;

	int malformed = 0;
	for (;;) {
		int opt_type = fget_int16(f);
		if (opt_type == EOF) break;
		int opt_len_i = fget_int16(f);
		if (opt_len_i == EOF) {
			malformed = 1;
			break;
		}
		uint16_t opt_len = (uint16_t)opt_len_i;
		long pos = ftell(f);
		if (pos < 0 || (size_t)pos + opt_len > sublen) {
			malformed = 1;
			break;
		}
		long next_opt = pos + opt_len;
		if (opt_type == DHCP6_OPT_STATUS_CODE && opt_len >= 2) {
			int st = fget_int16(f);
			if (st != EOF)
				out->status = (uint16_t)st;
		} else if (opt_type == DHCP6_OPT_IAADDR && opt_len >= 24) {
			struct in6_addr a;
			fget_data(f, &a, sizeof(a));
			uint32_t pref = fget_int32(f);
			uint32_t valid = fget_int32(f);
			/* discard if preferred > valid */
			if (pref <= valid) {
				if (valid == 0) {
					out->has_zero_valid_addr = 1;
					out->zero_addr = a;
				} else if (!out->has_valid_addr) {
					out->has_valid_addr = 1;
					out->valid_addr = a;
					out->valid_pref_lt = pref;
					out->valid_valid_lt = valid;
				}
			}
		}
		fseek(f, next_opt, SEEK_SET);
	}
	fclose(f);
	return malformed ? -1 : 0;
}

/* Prune individually expired IA_NAs from kernel before retransmitting RENEW/REBIND */
static void prune_expired_ianas(struct ioth *stack, unsigned int ifindex,
                                struct dhcp6_iana_entry *ianas, size_t num_iana) {
	struct timespec now = ts_now();
	for (size_t i = 0; i < num_iana; i++) {
		if (ianas[i].has_addr && !ianas[i].valid_infinite &&
		    ts_cmp(now, ianas[i].valid_deadline) >= 0) {
			ioth_ipaddr_del(stack, AF_INET6, &ianas[i].addr, 128, ifindex);
			ianas[i].has_addr = 0;
			ianas[i].dad_checked = 0;
			ianas[i].valid_lt = 0;
			ianas[i].preferred_lt = 0;
		}
	}
}

/* Synchronize active IA_NA snapshot into ioth_confdata */
static void sync_confdata_snapshot(struct ioth *stack, unsigned int ifindex, time_t ts,
                                   const uint8_t *serverid, uint16_t serveridlen,
                                   const struct dhcp6_iana_entry *ianas, size_t num_iana) {
	if (serverid && serveridlen > 0) {
		ioth_confdata_add(stack, ifindex, IOTH_CONFDATA_DHCP6_SERVERID,
		                  ts, 0, serverid, serveridlen);
	}
	for (size_t i = 0; i < num_iana; i++) {
		if (ianas[i].has_addr) {
			struct ioth_confdata_ip6addr rec = {
				.addr = ianas[i].addr,
				.prefixlen = 128,
				.preferred_lifetime = ianas[i].preferred_lt,
				.valid_lifetime = ianas[i].valid_lt
			};
			ioth_confdata_add(stack, ifindex, IOTH_CONFDATA_DHCP6_ADDR,
			                  ts, 0, &rec, sizeof(rec));
		}
	}
	ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_DHCP6_ADDR, ts);
	ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_DHCP6_SERVERID, ts);
	ioth_confdata_write_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP6_TIMESTAMP, ts);
}

/* Build and transmit a single DHCPv6 message carrying all relevant IA_NA options */
static int dhcp6_tx_packet(int type, int fd, const struct sockaddr_in6 *dest,
                           struct dhcp6data *data, uint16_t elapsed_hs) {
	char *buf = NULL;
	size_t buflen = 0;
	FILE *f = open_memstream(&buf, &buflen);
	if (!f)
		return -1;

	/* Before transmitting RENEW/REBIND, drop any individually expired leases */
	if (type == DHCP6_RENEW || type == DHCP6_REBIND) {
		prune_expired_ianas(data->stack, data->ifindex, data->ianas, data->num_iana);
	}

	dhcp6_add_head(f, (uint8_t)type, data->tid);
	dhcp6_add_opt_clientid(f, data->duid);

	/* SERVERID MUST be included in REQUEST, RENEW, and DECLINE; MUST NOT be in SOLICIT and REBIND */
	if (type == DHCP6_REQUEST || type == DHCP6_RENEW || type == DHCP6_DECLINE) {
		dhcp6_add_opt_serverid(f, data->serverid, data->serveridlen);
	}

	if (type != DHCP6_DECLINE) {
		/* ORO MUST include SOL_MAX_RT */
		dhcp6_add_opt_oro(f, DHCP6_OPT_SOL_MAX_RT, DHCP6_OPT_DNS_SERVERS, DHCP6_OPT_DOMAIN_LIST, 0);
	}
	dhcp6_add_opt_elapsed_time(f, elapsed_hs);
	if (type != DHCP6_DECLINE) {
		dhcp6_add_opt_fqdn(f, data->fqdn, 0);
	}

	/* Emit IA_NA options according to message type */
	for (size_t i = 0; i < data->num_iana; i++) {
		if (type == DHCP6_SOLICIT) {
			dhcp6_add_opt_iana(f, data->ianas[i].iaid, NULL, 0);
		} else if (type == DHCP6_REQUEST) {
			if (data->req_adv && i < data->req_adv->num_iana &&
			    data->req_adv->ianas[i].has_valid_addr &&
			    data->req_adv->ianas[i].subopts &&
			    data->req_adv->ianas[i].subopts_len > 0) {
				uint16_t slen = data->req_adv->ianas[i].subopts_len;
				uint8_t *tmp = malloc(slen);
				if (tmp) {
					memcpy(tmp, data->req_adv->ianas[i].subopts, slen);
					ia6_lifetime_zero(tmp, slen);
					dhcp6_add_opt_iana(f, data->ianas[i].iaid, tmp, slen);
					free(tmp);
				} else {
					dhcp6_add_opt_iana(f, data->ianas[i].iaid, NULL, 0);
				}
			} else if (!data->req_adv && data->ianas[i].has_addr) {
				/* REQUEST after NoBinding in RENEW/REBIND: include current valid addresses */
				uint8_t iaaddr_opt[28];
				dhcp6_build_iaaddr_opt(iaaddr_opt, &data->ianas[i].addr);
				dhcp6_add_opt_iana(f, data->ianas[i].iaid, iaaddr_opt, sizeof(iaaddr_opt));
			} else {
				/* Keep requesting unfulfilled IA_NAs */
				dhcp6_add_opt_iana(f, data->ianas[i].iaid, NULL, 0);
			}
		} else if (type == DHCP6_RENEW || type == DHCP6_REBIND) {
			if (data->ianas[i].has_addr) {
				uint8_t iaaddr_opt[28];
				dhcp6_build_iaaddr_opt(iaaddr_opt, &data->ianas[i].addr);
				dhcp6_add_opt_iana(f, data->ianas[i].iaid, iaaddr_opt, sizeof(iaaddr_opt));
			} else {
				/* include empty IA_NA to retry acquisition */
				dhcp6_add_opt_iana(f, data->ianas[i].iaid, NULL, 0);
			}
		} else if (type == DHCP6_DECLINE) {
			/* Include ONLY the IA_NAs with conflicting addresses */
			if (data->ianas[i].decline_pending) {
				uint8_t iaaddr_opt[28];
				dhcp6_build_iaaddr_opt(iaaddr_opt, &data->ianas[i].addr);
				dhcp6_add_opt_iana(f, data->ianas[i].iaid, iaaddr_opt, sizeof(iaaddr_opt));
			}
		}
	}

	fclose(f);
	ssize_t sent = ioth_sendto(fd, buf, buflen, 0, (const struct sockaddr *)dest, sizeof(*dest));
	free(buf);
	return (sent < 0) ? -1 : 0;
}

static int dhcp6_send(int type, int fd, int timerfd, struct dhcp6data *data);

/* Wait for ADVERTISE or REPLY within timeout_ms (or until timerfd expires) */
static int dhcp6_get(int sendtype, int fd, int timerfd, struct dhcp6data *data,
                     int timeout_ms, int collect_full_rt,
                     struct dhcp6_advertise_choice *best_adv) {
	int expected_type = (sendtype == DHCP6_SOLICIT) ? DHCP6_ADVERTISE : DHCP6_REPLY;
	struct pollfd pfd[2] = {
		{ .fd = fd,      .events = POLLIN, .revents = 0 },
		{ .fd = timerfd, .events = POLLIN, .revents = 0 }
	};
	nfds_t nfds = (timerfd >= 0) ? 2 : 1;
	int timeout = timeout_ms;
	struct timeval start, end, timediff;

	for (;;) {
		gettimeofday(&start, NULL);
		int event = poll(pfd, nfds, timeout);
		if (event < 0) {
			if (errno == EINTR)
				goto update_timeout;
			return -1;
		}
		if (event == 0) {
			if (sendtype == DHCP6_SOLICIT && best_adv && best_adv->valid)
				return 0; /* First RT elapsed with at least one valid Advertise */
			return errno = ETIME, -1;
		}
		if (nfds == 2 && (pfd[1].revents & POLLIN))
			return errno = ETIMEDOUT, -1;

		if (pfd[0].revents & POLLIN) {
			ssize_t peeklen = ioth_recv(fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
			if (peeklen <= 0)
				goto update_timeout;
			uint8_t *inbuf = malloc((size_t)peeklen);
			if (!inbuf)
				return errno = ENOMEM, -1;

			/* Receive with IPV6_PKTINFO to discard multicast packets */
			struct iovec iov = { .iov_base = inbuf, .iov_len = (size_t)peeklen };
			union {
				char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
				struct cmsghdr align;
			} ctrl;
			memset(&ctrl, 0, sizeof(ctrl));
			struct msghdr msg = {
				.msg_iov = &iov,
				.msg_iovlen = 1,
				.msg_control = ctrl.buf,
				.msg_controllen = sizeof(ctrl.buf)
			};

			ssize_t inbuflen = ioth_recvmsg(fd, &msg, 0);
			int is_multicast = 0;
			if (inbuflen < 0 && errno == ENOSYS) {
				inbuflen = ioth_recv(fd, inbuf, (size_t)peeklen, 0);
			} else if (inbuflen > 0) {
				for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
				     cmsg != NULL;
				     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
					if (cmsg->cmsg_level == IPPROTO_IPV6 &&
					    cmsg->cmsg_type == IPV6_PKTINFO &&
					    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
						struct in6_pktinfo pktinfo;
						memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
						if (IN6_IS_ADDR_MULTICAST(&pktinfo.ipi6_addr))
							is_multicast = 1;
						break;
					}
				}
			}

			if (inbuflen <= 0) {
				free(inbuf);
				goto update_timeout;
			}
            //Check multicast, message type and TID
			if (is_multicast || !check_consistency6(expected_type, inbuf, (size_t)inbuflen, data)) {
				free(inbuf);
				goto update_timeout;
			}

			struct timespec rx_now = ts_now();
			uint8_t *optbuf = inbuf + 4;
			size_t optbuflen = (size_t)inbuflen - 4;
			int malformed = 0;
			int has_clientid = 0, clientid_ok = 0;
			int has_serverid = 0;
			uint8_t *srv_id = NULL;
			uint16_t srv_id_len = 0;
			int has_sol_max_rt = 0;
			uint32_t rx_sol_max_rt = 0;
			uint8_t preference = 0;
			uint16_t top_status = DHCP6_STATUS_SUCCESS;
			uint8_t *dns_serv_addr = NULL;
			uint16_t dns_serv_len = 0;
			uint8_t *dns_search_addr = NULL;
			uint16_t dns_search_len = 0;

			struct dhcp6_rx_iana *rx_ianas = calloc(data->num_iana, sizeof(*rx_ianas));
			if (!rx_ianas) {
				free(inbuf);
				return errno = ENOMEM, -1;
			}

			if (optbuflen > 0) {
				FILE *optf = fmemopen(optbuf, optbuflen, "r");
				if (!optf) {
					free(rx_ianas);
					free(inbuf);
					goto update_timeout;
				}
				for (;;) {
					int opt_type = fget_int16(optf);
					if (opt_type == EOF) break;
					int opt_len_i = fget_int16(optf);
					if (opt_len_i == EOF) {
						malformed = 1;
						break;
					}
					uint16_t opt_len = (uint16_t)opt_len_i;
					long pos = ftell(optf);
					if (pos < 0 || (size_t)pos + opt_len > optbuflen) {
						malformed = 1;
						break;
					}
					long next_opt = pos + opt_len;
					switch (opt_type) {
						case DHCP6_OPT_CLIENTID:
							has_clientid = 1;
							clientid_ok = check_clientid6(optf, opt_len, data->duid);
							break;
						case DHCP6_OPT_SERVERID:
							if (opt_len > 0 && opt_len <= DHCP6_MAX_SERVERID) {
								has_serverid = 1;
								srv_id = optbuf + pos;
								srv_id_len = opt_len;
							}
							break;
						case DHCP6_OPT_IA_NA:
							if (opt_len >= 12) {
								uint8_t rx_iaid[4];
								fget_data(optf, rx_iaid, 4);
								uint32_t rx_t1 = fget_int32(optf);
								uint32_t rx_t2 = fget_int32(optf);
								/* discard ONLY invalid IA_NA (T1 > T2 > 0) */
								if (!(rx_t1 > 0 && rx_t2 > 0 && rx_t1 > rx_t2)) {
									ssize_t idx = find_iana_index(data->ianas, data->num_iana, rx_iaid);
									if (idx >= 0) {
										rx_ianas[idx].present = 1;
										rx_ianas[idx].t1 = rx_t1;
										rx_ianas[idx].t2 = rx_t2;
										rx_ianas[idx].subopts = optbuf + pos + 12;
										rx_ianas[idx].subopts_len = (uint16_t)(opt_len - 12);
									}
								}
							}
							break;
						case DHCP6_OPT_PREFERENCE:
							if (opt_len >= 1) {
								int p = fget_int8(optf);
								if (p != EOF) preference = (uint8_t)p;
							}
							break;
						case DHCP6_OPT_STATUS_CODE:
							if (opt_len >= 2) {
								int st = fget_int16(optf);
								if (st != EOF) top_status = (uint16_t)st;
							}
							break;
						case DHCP6_OPT_SOL_MAX_RT:
							if (opt_len == 4) {
								uint32_t v = fget_int32(optf);
								if (v >= SOL_MAX_RT_MIN && v <= SOL_MAX_RT_MAX) {
									has_sol_max_rt = 1;
									rx_sol_max_rt = v;
								}
							}
							break;
						case DHCP6_OPT_DNS_SERVERS:
							dns_serv_addr = optbuf + pos;
							dns_serv_len = opt_len;
							break;
						case DHCP6_OPT_DOMAIN_LIST:
							dns_search_addr = optbuf + pos;
							dns_search_len = opt_len;
							break;
					}
					fseek(optf, next_opt, SEEK_SET);
				}
				fclose(optf);
			}

			/* MUST discard if malformed, missing Server ID, or mismatched Client ID */
			if (malformed || !has_serverid || !has_clientid || !clientid_ok) {
				free(rx_ianas);
				free(inbuf);
				goto update_timeout;
			}

			/* Parse sub-options of every received IA_NA */
			int sub_malformed = 0;
			size_t valid_iana_count = 0;
			for (size_t i = 0; i < data->num_iana; i++) {
				if (rx_ianas[i].present) {
					if (parse_iana_subopts(rx_ianas[i].subopts, rx_ianas[i].subopts_len, &rx_ianas[i]) < 0) {
						sub_malformed = 1;
						break;
					}
					if (rx_ianas[i].status == DHCP6_STATUS_SUCCESS && rx_ianas[i].has_valid_addr) {
						valid_iana_count++;
					}
				}
			}

			if (expected_type == DHCP6_ADVERTISE) {
				/* process SOL_MAX_RT even if Advertise is ignored;
				   revert to default if multiple Advertises disagree */
				if (has_sol_max_rt && best_adv) {
					if (!best_adv->sol_max_rt_seen) {
						best_adv->sol_max_rt_seen = 1;
						best_adv->sol_max_rt_val = rx_sol_max_rt;
						data->sol_max_rt = rx_sol_max_rt;
					} else if (best_adv->sol_max_rt_val != rx_sol_max_rt) {
						best_adv->sol_max_rt_conflict = 1;
						data->sol_max_rt = SOL_MAX_RT_DEFAULT;
					}
				}

				/* ignore Advertise with no usable addresses in any IA_NA */
				if (!sub_malformed && top_status == DHCP6_STATUS_SUCCESS &&
				    valid_iana_count > 0 && best_adv) {
					int is_better = !best_adv->valid ||
					                (preference > best_adv->preference) ||
					                (preference == best_adv->preference &&
					                 valid_iana_count > best_adv->valid_iana_count);
					if (is_better) {
						if (!best_adv->ianas) {
							best_adv->ianas = calloc(data->num_iana, sizeof(*best_adv->ianas));
							best_adv->num_iana = data->num_iana;
						}
						if (best_adv->ianas) {
							for (size_t i = 0; i < data->num_iana; i++) {
								free(best_adv->ianas[i].subopts);
								best_adv->ianas[i].subopts = NULL;
								best_adv->ianas[i].subopts_len = 0;
								best_adv->ianas[i].has_valid_addr = 0;

								if (rx_ianas[i].present &&
								    rx_ianas[i].status == DHCP6_STATUS_SUCCESS &&
								    rx_ianas[i].has_valid_addr &&
								    rx_ianas[i].subopts_len > 0) {
									best_adv->ianas[i].subopts = malloc(rx_ianas[i].subopts_len);
									if (best_adv->ianas[i].subopts) {
										memcpy(best_adv->ianas[i].subopts,
										       rx_ianas[i].subopts,
										       rx_ianas[i].subopts_len);
										best_adv->ianas[i].subopts_len = rx_ianas[i].subopts_len;
										best_adv->ianas[i].has_valid_addr = 1;
									}
								}
							}
							memcpy(best_adv->serverid, srv_id, srv_id_len);
							best_adv->serveridlen = srv_id_len;
							best_adv->preference = preference;
							best_adv->valid_iana_count = valid_iana_count;
							best_adv->valid = 1;
						}
					}
					/* immediately proceed if pref==255 or past first RT */
					if (best_adv->valid && (preference == 255 || !collect_full_rt)) {
						free(rx_ianas);
						free(inbuf);
						return 0;
					}
				} else {
					printf("DHCP6 ignore ADVERTISE: top_st=%u valid_ianas=%zu/%zu pref=%u\n",
					       top_status, valid_iana_count, data->num_iana, preference);
				}
				free(rx_ianas);
				free(inbuf);
				goto update_timeout;
			}

			/* apply SOL_MAX_RT on validated Reply even on failure status */
			if (has_sol_max_rt)
				data->sol_max_rt = rx_sol_max_rt;

			/* valid Reply completes Decline regardless of Status Code */
			if (sendtype == DHCP6_DECLINE) {
				free(rx_ianas);
				free(inbuf);
				return 0;
			}

			/* Handling DHCP6_REPLY */
			if (sub_malformed || top_status == DHCP6_STATUS_UNSPECFAIL) {
				free(rx_ianas);
				free(inbuf);
				goto update_timeout;
			}
			if (top_status == DHCP6_STATUS_NOTONLINK || top_status == DHCP6_STATUS_NOADDRSAVAIL) {
				free(rx_ianas);
				free(inbuf);
				return errno = ECANCELED, -1;
			}

			int any_nobinding = 0;
			int any_present = 0;

			/* Apply granular per-IA_NA updates  */
			for (size_t i = 0; i < data->num_iana; i++) {
				if (!rx_ianas[i].present) {
					/* IA omitted from Reply: leave existing binding unchanged */
					continue;
				}
				any_present = 1;
				data->ianas[i].last_status = rx_ianas[i].status;

				if (rx_ianas[i].status == DHCP6_STATUS_NOBINDING &&
				    (sendtype == DHCP6_RENEW || sendtype == DHCP6_REBIND)) {
					any_nobinding = 1;
					continue;
				}

				if (rx_ianas[i].status == DHCP6_STATUS_NOTONLINK) {
					if (data->ianas[i].has_addr) {
						ioth_ipaddr_del(data->stack, AF_INET6, &data->ianas[i].addr, 128, data->ifindex);
						data->ianas[i].has_addr = 0;
						data->ianas[i].dad_checked = 0;
					}
					continue;
				}

				if (rx_ianas[i].status == DHCP6_STATUS_NOADDRSAVAIL) {
					/* Partial NoAddrsAvail: keep slot empty to retry in subsequent Renew/Rebind */
					continue;
				}

				/* Discard address explicitly revoked with valid_lifetime == 0 */
				if (rx_ianas[i].has_zero_valid_addr && data->ianas[i].has_addr &&
				    memcmp(&rx_ianas[i].zero_addr, &data->ianas[i].addr, sizeof(struct in6_addr)) == 0) {
					ioth_ipaddr_del(data->stack, AF_INET6, &data->ianas[i].addr, 128, data->ifindex);
					data->ianas[i].has_addr = 0;
					data->ianas[i].dad_checked = 0;
				}

				if (rx_ianas[i].has_valid_addr) {
					/* If server replaced the address in this IA_NA, remove old one and re-run DAD */
					if (data->ianas[i].has_addr &&
					    memcmp(&data->ianas[i].addr, &rx_ianas[i].valid_addr, sizeof(struct in6_addr)) != 0) {
						ioth_ipaddr_del(data->stack, AF_INET6, &data->ianas[i].addr, 128, data->ifindex);
						data->ianas[i].dad_checked = 0;
					}
					data->ianas[i].addr = rx_ianas[i].valid_addr;
					data->ianas[i].preferred_lt = rx_ianas[i].valid_pref_lt;
					data->ianas[i].valid_lt = rx_ianas[i].valid_valid_lt;
					data->ianas[i].t1 = rx_ianas[i].t1;
					data->ianas[i].t2 = rx_ianas[i].t2;

					resolve_t1_t2(&data->ianas[i].t1, &data->ianas[i].t2,
					              data->ianas[i].preferred_lt, data->ianas[i].valid_lt);

					data->ianas[i].t1_infinite = (data->ianas[i].t1 == DHCP6_INFINITE_TIME);
					data->ianas[i].t2_infinite = (data->ianas[i].t2 == DHCP6_INFINITE_TIME);
					data->ianas[i].valid_infinite = (data->ianas[i].valid_lt == DHCP6_INFINITE_TIME);

					if (!data->ianas[i].t1_infinite)
						data->ianas[i].t1_deadline = ts_add_sec(rx_now, data->ianas[i].t1);
					if (!data->ianas[i].t2_infinite)
						data->ianas[i].t2_deadline = ts_add_sec(rx_now, data->ianas[i].t2);
					if (!data->ianas[i].valid_infinite)
						data->ianas[i].valid_deadline = ts_add_sec(rx_now, data->ianas[i].valid_lt);

					data->ianas[i].has_addr = 1;
				}
			}

			/* On NoBinding in Renew/Rebind, send Request with all IAs */
			if (any_nobinding) {
				memcpy(data->serverid, srv_id, srv_id_len);
				data->serveridlen = srv_id_len;
				free(rx_ianas);
				free(inbuf);
				return errno = ENOENT, -1;
			}

			size_t active_count = 0;
			for (size_t i = 0; i < data->num_iana; i++) {
				if (data->ianas[i].has_addr)
					active_count++;
			}

			if (!any_present || active_count == 0) {
				free(rx_ianas);
				free(inbuf);
				return errno = ECANCELED, -1;
			}

			/* Commit valid REPLY metadata into data and ioth_confdata */
			memcpy(data->serverid, srv_id, srv_id_len);
			data->serveridlen = srv_id_len;

			if (dns_serv_addr != NULL && dns_serv_len > 0) {
				ioth_confdata_add(data->stack, data->ifindex, IOTH_CONFDATA_DHCP6_DNS,
				                  data->timestamp, 0, dns_serv_addr, dns_serv_len);
			}
			ioth_confdata_free(data->stack, data->ifindex, IOTH_CONFDATA_DHCP6_DNS, data->timestamp);

			if (dns_search_addr != NULL && dns_search_len > 0) {
				char dns_search_mstr[dns_search_len + 1];
				int mstr_len = iothconf_domain2mstr(dns_search_addr, dns_search_mstr, dns_search_len);
				ioth_confdata_add(data->stack, data->ifindex, IOTH_CONFDATA_DHCP6_DOMAIN,
				                  data->timestamp, 0, dns_search_mstr, (uint16_t)mstr_len);
			}
			ioth_confdata_free(data->stack, data->ifindex, IOTH_CONFDATA_DHCP6_DOMAIN, data->timestamp);

			sync_confdata_snapshot(data->stack, data->ifindex, data->timestamp,
			                       data->serverid, data->serveridlen,
			                       data->ianas, data->num_iana);

			free(rx_ianas);
			free(inbuf);
			return 0;
		}

update_timeout:
		gettimeofday(&end, NULL);
		timersub(&end, &start, &timediff);
		timeout -= (int)(timediff.tv_sec * 1000 + timediff.tv_usec / 1000);
		if (timeout <= 0) {
			if (sendtype == DHCP6_SOLICIT && best_adv && best_adv->valid)
				return 0;
			return errno = ETIME, -1;
		}
	}
}

/* Reliable transmission with exponential backoff and rate limiting */
static int dhcp6_send(int type, int fd, int timerfd, struct dhcp6data *data) {
	int irt_sec = 1, mrt_sec = 0, mrc = 0;
	switch (type) {
		case DHCP6_SOLICIT:
			irt_sec = SOL_TIMEOUT;
			mrt_sec = (int)data->sol_max_rt;
			mrc = 0; /* MRC=0, MRD=0 */
			break;
		case DHCP6_REQUEST:
			irt_sec = REQ_TIMEOUT;
			mrt_sec = REQ_MAX_RT;
			mrc = REQ_MAX_RC;
			break;
		case DHCP6_RENEW:
			irt_sec = REN_TIMEOUT;
			mrt_sec = REN_MAX_RT;
			mrc = 0; /* Bounded by timerfd (earliest T2) */
			break;
		case DHCP6_REBIND:
			irt_sec = REB_TIMEOUT;
			mrt_sec = REB_MAX_RT;
			mrc = 0; /* Bounded by timerfd (latest valid_lifetime) */
			break;
		case DHCP6_DECLINE:
			irt_sec = DEC_TIMEOUT;
			mrt_sec = 0;
			mrc = DEC_MAX_RC;
			break;
		default:
			return errno = EINVAL, -1;
	}

	/* New random transaction ID per exchange, unchanged on retransmissions */
	if (getrandom(data->tid, sizeof(data->tid), 0) < 0)
		return -1;

	struct sockaddr_in6 dest = {
		.sin6_family       = AF_INET6,
		.sin6_port         = htons(DHCP6_SERVERPORT),
		.sin6_addr.s6_addr = MCAST_ALL_ROUTERS,
		.sin6_scope_id     = data->ifindex
	};

	struct timespec tx_start = ts_now();
	struct dhcp6_advertise_choice best_adv = {0};
	int attempt = 0;
	int rt_ms = 0;

	for (;;) {
		pthread_testcancel();
		if (dhcp6_rl_wait(&data->rl, timerfd) < 0) {
			dhcp6_adv_free(&best_adv);
			return -1;
		}
		uint16_t elapsed_hs = (attempt == 0) ? 0 : dhcp6_elapsed_hs(&tx_start);
		if (dhcp6_tx_packet(type, fd, &dest, data, elapsed_hs) < 0) {
			dhcp6_adv_free(&best_adv);
			return -1;
		}

		if (type == DHCP6_SOLICIT)
			mrt_sec = (int)data->sol_max_rt;

		rt_ms = dhcp6_next_rt_ms(attempt, rt_ms, irt_sec, mrt_sec,
		                         (type == DHCP6_SOLICIT && attempt == 0));

		int rv = dhcp6_get(type, fd, timerfd, data, rt_ms,//collect full adv on the first solicit
		                   (type == DHCP6_SOLICIT && attempt == 0),
		                   (type == DHCP6_SOLICIT) ? &best_adv : NULL);
		if (rv == 0) {
			if (type == DHCP6_SOLICIT) {
				/* Proceed to 4-message exchange: send REQUEST with all IA_NAs to selected server */
				memcpy(data->serverid, best_adv.serverid, best_adv.serveridlen);
				data->serveridlen = best_adv.serveridlen;
				data->req_adv = &best_adv;
				int req_rv = dhcp6_send(DHCP6_REQUEST, fd, -1, data);
				data->req_adv = NULL;
				dhcp6_adv_free(&best_adv);
				return req_rv;
			}
			return 0;
		}
		if (errno != ETIME) {
			dhcp6_adv_free(&best_adv);
			return -1;
		}
		attempt++;
		if (mrc > 0 && attempt >= mrc) {
			dhcp6_adv_free(&best_adv);
			return errno = ETIME, -1;
		}
	}
}

static int dhcp6_open_socket(struct ioth *stack, unsigned int ifindex) {
	struct sockaddr_in6 bindaddr = {
		.sin6_family   = AF_INET6,
		.sin6_port     = htons(DHCP6_CLIENTPORT),
		.sin6_scope_id = ifindex
	};
	int fd = ioth_msocket(stack, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return -1;
	int on = 1;
	if (ioth_setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
		perror("IPV6_RECVPKTINFO");
	}
	if (ioth_bind(fd, (struct sockaddr *)&bindaddr, sizeof(bindaddr)) < 0) {
		ioth_close(fd);
		return -1;
	}
	return fd;
}

static int iothconf_dhcpv6_proto(struct ioth *stack, unsigned int ifindex, const char *fqdn,
                                 uint32_t config_flags, time_t timestamp, int *sock_out,
                                 uint8_t serverid[DHCP6_MAX_SERVERID], uint16_t *serveridlen,
                                 struct dhcp6_iana_entry *ianas, size_t num_iana,
                                 uint32_t *sol_max_rt, struct dhcp6_ratelimit *rl) {
	(void)config_flags;
	int fd = dhcp6_open_socket(stack, ifindex);
	if (fd < 0)
		return -1;
	*sock_out = fd;

	struct dhcp6data dhcpdata = {
		.stack = stack,
		.ifindex = ifindex,
		.timestamp = timestamp,
		.fqdn = fqdn,
		.ianas = ianas,
		.num_iana = num_iana,
		.req_adv = NULL,
		.sol_max_rt = *sol_max_rt,
		.rl = *rl
	};
	ioth_linkgetaddr(stack, ifindex, dhcpdata.macaddr);
	dhcp6_build_duid_ll(dhcpdata.duid, dhcpdata.macaddr);

	int rv = dhcp6_send(DHCP6_SOLICIT, fd, -1, &dhcpdata);
	int saved_errno = errno;
	if (rv == 0) {
		memcpy(serverid, dhcpdata.serverid, dhcpdata.serveridlen);
		*serveridlen = dhcpdata.serveridlen;
	}
	*sol_max_rt = dhcpdata.sol_max_rt;
	*rl = dhcpdata.rl;

	ioth_close(fd);
	*sock_out = -1;
	errno = saved_errno;
	return rv;
}

/* ============================================================================
 * Thread management 
 * ============================================================================ */

struct dhcp6_thread_info {
	pthread_t thread_id;
	time_t timestamp;
	int status;
	int active;
};

struct dhcp6_timed_status {
	time_t timestamp;
	int status;
};

struct dhcp6_thread_args {
	struct ioth *stack;
	unsigned int ifindex;
	const char *fqdn;
	uint32_t config_flags;
	time_t timestamp;
	size_t num_iana;
	int state;
};

static pthread_mutex_t dhcp6_reg_mutex = PTHREAD_MUTEX_INITIALIZER;

int ioth_dhcpv6_thread(struct ioth *stack, unsigned int ifindex, const char *fqdn,
                       uint32_t config_flags, time_t timestamp, size_t num_iana, int state);

static void *dhcp6_pthread_runner(void *arg) {
	struct dhcp6_thread_args *args = (struct dhcp6_thread_args *)arg;
	int result = 0;

	pthread_mutex_lock(&dhcp6_reg_mutex);
	pthread_mutex_unlock(&dhcp6_reg_mutex);

	pthread_cleanup_push(free, args);

	result = ioth_dhcpv6_thread(args->stack,
	                            args->ifindex,
	                            args->fqdn,
	                            args->config_flags,
	                            args->timestamp,
	                            args->num_iana,
	                            args->state);

	ioth_confdata_free(args->stack, args->ifindex, IOTH_CONFDATA_THREAD_DHCP6, 0);

	pthread_cleanup_pop(1); /* frees args */
	return (void *)(intptr_t)result;
}

/* Multi-IA_NA entry point: request num_iana distinct IPv6 addresses in a single DHCPv6 thread */
int iothconf_dhcpv6_multi(struct ioth *stack, unsigned int ifindex, const char *fqdn,
                          uint32_t config_flags, size_t num_iana) {
	if (num_iana == 0)
		num_iana = 1;

	pthread_t dhcp6_thread_id = 0;
	time_t timestamp = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_THREAD_TIMESTAMP);

	struct dhcp6_thread_args *args = malloc(sizeof(*args));
	if (!args)
		return -1;

	args->stack = stack;
	args->ifindex = ifindex;
	args->fqdn = fqdn;
	args->config_flags = config_flags;
	args->timestamp = timestamp;
	args->num_iana = num_iana;
	args->state = INIT;

	pthread_mutex_lock(&dhcp6_reg_mutex);
	int ret = pthread_create(&dhcp6_thread_id, NULL, dhcp6_pthread_runner, args);
	if (ret != 0) {
		pthread_mutex_unlock(&dhcp6_reg_mutex);
		free(args);
		return ret;
	}
	ioth_confdata_add_data(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP6, timestamp, 0,
			struct dhcp6_thread_info,
			.thread_id = dhcp6_thread_id,
			.timestamp = timestamp,
			.status = UNBOUND,
			.active = 1);
	pthread_mutex_unlock(&dhcp6_reg_mutex);

	printf("D_INFO6 creato id in dhcpv6 %ld (num_iana=%zu)\n", (long)dhcp6_thread_id, num_iana);
	return 0;
}

/* Single-IA_NA entry point */
int iothconf_dhcpv6(struct ioth *stack, unsigned int ifindex, const char *fqdn, uint32_t config_flags) {
	return iothconf_dhcpv6_multi(stack, ifindex, fqdn, config_flags, 1);
}

static int _set_thread6_status(void *data, void *arg) {
	struct dhcp6_thread_info *thread_info = data;
	struct dhcp6_timed_status *dhcp_status = arg;
	time_t timestamp = ioth_confdata_gettimestamp(data);
	if (timestamp >= dhcp_status->timestamp) {
		thread_info->status = dhcp_status->status;
	}
	return 0;
}

static int _get_thread6_info(void *data, void *arg) {
	struct dhcp6_thread_info *out_info = arg;
	struct dhcp6_thread_info *saved_info = data;
	time_t timestamp = ioth_confdata_gettimestamp(data);
	if (timestamp >= out_info->timestamp) {
		memcpy(out_info, saved_info, sizeof(struct dhcp6_thread_info));
	}
	return 0;
}

int iothconf_dhcpv6_kill(struct ioth *stack, unsigned int ifindex) {
	time_t timestamp = ioth_confdata_read_timestamp(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP6);
	struct dhcp6_thread_info d_i = {0, 0, 0, 0};
	d_i.timestamp = timestamp;

	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP6, _get_thread6_info, &d_i);
	if (!d_i.active) return 1;

	pthread_cancel(d_i.thread_id);
	pthread_join(d_i.thread_id, NULL);
	ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP6, 0);
	return 0;
}

int iothconf_dhcpv6_info(struct ioth *stack, unsigned int ifindex, int *status) {
	time_t timestamp = ioth_confdata_read_timestamp(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP6);
	struct dhcp6_thread_info d_i = {0, 0, 0, 0};
	d_i.timestamp = timestamp;

	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP6, _get_thread6_info, &d_i);
	if (!d_i.active) return -1;

	*status = d_i.status;
	return 0;
}

/* Cleanup handlers */
static void ioth6_close_clean(void *arg) {
	int fd = *(int *)arg;
	if (fd >= 0)
		ioth_close(fd);
}

static void fd6_close_clean(void *arg) {
	int fd = *(int *)arg;
	if (fd >= 0)
		close(fd);
}

static void set_dhcp6_thread_status(struct ioth *stack, unsigned int ifindex, int status) {
	time_t timestamp = ioth_confdata_read_timestamp(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP6);
	struct dhcp6_timed_status t_status = {timestamp, status};
	ioth_confdata_forall(stack, ifindex, IOTH_CONFDATA_THREAD_DHCP6, _set_thread6_status, &t_status);
}

static int set_timer6_poll(int timerfd, struct itimerspec *tspec, uint32_t sec, struct pollfd *plfd) {
	tspec->it_value.tv_sec = sec;
	tspec->it_value.tv_nsec = (sec == 0) ? 1 : 0;
	tspec->it_interval.tv_sec = 0;
	tspec->it_interval.tv_nsec = 0;

	if (timerfd_settime(timerfd, 0, tspec, NULL) == -1) {
		perror("timerfd_settime");
		return 1;
	}

	plfd->fd = timerfd;
	plfd->events = POLLIN;
	plfd->revents = 0;
	return 0;
}

static void consume_timer6(int timerfd) {
	uint64_t exp;
	ssize_t s = read(timerfd, &exp, sizeof(uint64_t));
	(void)s;
}

/* Kernel IPv6 address & preferred/valid lifetime management via Netlink (creates or updates /128) */
static int set_ipv6_lifetime(struct ioth *stack, unsigned int ifindex,
                             struct in6_addr addr, uint8_t prefixlen,
                             uint32_t preferred_lifetime, uint32_t valid_lifetime) {
	struct {
		struct nlmsghdr h;
		struct ifaddrmsg i;
		struct __nlinline_ipv6attr local;
		struct __nlinline_ipv6attr address;
		struct {
			struct nlattr h;
			struct ifa_cacheinfo info;
		} cacheinfo;
	} msg = {
		.h.nlmsg_len = sizeof(msg),
		.h.nlmsg_type = RTM_NEWADDR,
		.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
		.h.nlmsg_seq = 1,
		.i.ifa_family = AF_INET6,
		.i.ifa_prefixlen = prefixlen,
		.i.ifa_scope = RT_SCOPE_UNIVERSE,
		.i.ifa_index = ifindex,
		.local.h.nla_len = sizeof(msg.local),
		.local.h.nla_type = IFA_LOCAL,
		.address.h.nla_len = sizeof(msg.address),
		.address.h.nla_type = IFA_ADDRESS,
		.cacheinfo.h.nla_len = sizeof(msg.cacheinfo),
		.cacheinfo.h.nla_type = IFA_CACHEINFO,
		.cacheinfo.info.ifa_prefered = preferred_lifetime,
		.cacheinfo.info.ifa_valid = valid_lifetime,
	};

	memcpy(&msg.local.addr, &addr, sizeof(addr));
	memcpy(&msg.address.addr, &addr, sizeof(addr));

	return ioth_nldialog(stack, &msg);
}

/* Batched Netlink RTM_GETADDR query to check DAD status for all unchecked IA_NAs in one pass.
 * Per-slot status: 0 = passed, 1 = failed (conflict), 2 = still tentative.
 * Returns -1 on Netlink error (unsupported), 0 otherwise. */
static int query_ipv6_dad_batch(struct ioth *stack, unsigned int ifindex,
                                const struct dhcp6_iana_entry *ianas, size_t num_iana,
                                int *statuses) {
	for (size_t i = 0; i < num_iana; i++) {
		if (ianas[i].has_addr && !ianas[i].dad_checked)
			statuses[i] = 1; /* Default to failed if kernel already purged it */
		else
			statuses[i] = 0;
	}

	int fd = ioth_msocket(stack, AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	struct sockaddr_nl sanl = { .nl_family = AF_NETLINK };
	if (ioth_bind(fd, (struct sockaddr *)&sanl, sizeof(sanl)) < 0) {
		ioth_close(fd);
		return -1;
	}

	struct {
		struct nlmsghdr h;
		struct ifaddrmsg i;
	} req = {
		.h.nlmsg_len = sizeof(req),
		.h.nlmsg_type = RTM_GETADDR,
		.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		.h.nlmsg_seq = 1,
		.i.ifa_family = AF_INET6
	};

	if (ioth_send(fd, &req, sizeof(req), 0) < 0) {
		ioth_close(fd);
		return -1;
	}

	uint8_t buf[8192];
	int err = 0;
	int done = 0;

	while (!done) {
		ssize_t len = ioth_recv(fd, buf, sizeof(buf), 0);
		if (len <= 0) {
			err = -1;
			break;
		}
		for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
		     NLMSG_OK(nlh, (unsigned int)len);
		     nlh = NLMSG_NEXT(nlh, len)) {
			if (nlh->nlmsg_type == NLMSG_DONE) {
				done = 1;
				break;
			}
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				err = -1;
				done = 1;
				break;
			}
			if (nlh->nlmsg_type != RTM_NEWADDR)
				continue;

			struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
			if (ifa->ifa_index != ifindex || ifa->ifa_family != AF_INET6)
				continue;

			uint32_t flags = ifa->ifa_flags;
			struct in6_addr nl_addr;
			int has_nl_addr = 0;
			int rtalen = IFA_PAYLOAD(nlh);
			for (struct rtattr *rta = IFA_RTA(ifa); RTA_OK(rta, rtalen); rta = RTA_NEXT(rta, rtalen)) {
				if ((rta->rta_type == IFA_LOCAL || rta->rta_type == IFA_ADDRESS) &&
				    RTA_PAYLOAD(rta) == sizeof(nl_addr)) {
					memcpy(&nl_addr, RTA_DATA(rta), sizeof(nl_addr));
					has_nl_addr = 1;
				} else if (rta->rta_type == IFA_FLAGS && RTA_PAYLOAD(rta) == sizeof(uint32_t)) {
					memcpy(&flags, RTA_DATA(rta), sizeof(flags));
				}
			}

			if (!has_nl_addr)
				continue;

			for (size_t i = 0; i < num_iana; i++) {
				if (ianas[i].has_addr && !ianas[i].dad_checked &&
				    memcmp(&nl_addr, &ianas[i].addr, sizeof(nl_addr)) == 0) {
					if (flags & IFA_F_DADFAILED)
						statuses[i] = 1;
					else if (flags & IFA_F_TENTATIVE)
						statuses[i] = 2;
					else
						statuses[i] = 0;
				}
			}
		}
	}

	ioth_close(fd);
	return err;
}

/* Wait for kernel RFC 4862 DAD on all newly acquired addresses (up to 5s total).
 * Marks passed addresses as dad_checked=1; removes failed addresses and sets decline_pending=1.
 * Returns number of addresses that failed DAD. */
static size_t check_ipv6_dad_multi(struct ioth *stack, unsigned int ifindex,
                                   struct dhcp6_iana_entry *ianas, size_t num_iana) {
	size_t pending = 0;
	for (size_t i = 0; i < num_iana; i++) {
		if (ianas[i].has_addr && !ianas[i].dad_checked)
			pending++;
	}
	if (pending == 0)
		return 0;

	int *statuses = calloc(num_iana, sizeof(*statuses));
	if (!statuses)
		return 0;

	for (int iter = 0; iter < 50; iter++) {
		pthread_testcancel();
		if (query_ipv6_dad_batch(stack, ifindex, ianas, num_iana, statuses) < 0) {
			/* Netlink dump unsupported: assume passed */
			for (size_t i = 0; i < num_iana; i++) {
				if (ianas[i].has_addr && !ianas[i].dad_checked)
					ianas[i].dad_checked = 1;
			}
			free(statuses);
			return 0;
		}
		int any_tentative = 0;
		for (size_t i = 0; i < num_iana; i++) {
			if (ianas[i].has_addr && !ianas[i].dad_checked && statuses[i] == 2) {
				any_tentative = 1;
				break;
			}
		}
		if (!any_tentative)
			break;
		struct pollfd dummy = { .fd = -1, .events = 0, .revents = 0 };
		poll(&dummy, 0, 100);
	}

	size_t failed_count = 0;
	for (size_t i = 0; i < num_iana; i++) {
		if (ianas[i].has_addr && !ianas[i].dad_checked) {
			if (statuses[i] == 1) {
				/* Remove conflicting address before sending DECLINE */
				ioth_ipaddr_del(stack, AF_INET6, &ianas[i].addr, 128, ifindex);
				ianas[i].has_addr = 0;
				ianas[i].dad_checked = 0;
				ianas[i].decline_pending = 1;
				failed_count++;
			} else {
				ianas[i].dad_checked = 1;
			}
		}
	}

	free(statuses);
	return failed_count;
}

/* Stop using all IPv6 addresses across all IA_NAs and clean DHCP6 confdata */
static void halt_all_network6(struct ioth *stack, unsigned int ifindex,
                              struct dhcp6_iana_entry *ianas, size_t num_iana) {
	for (size_t i = 0; i < num_iana; i++) {
		if (ianas[i].has_addr) {
			ioth_ipaddr_del(stack, AF_INET6, &ianas[i].addr, 128, ifindex);
			ianas[i].has_addr = 0;
		}
		ianas[i].dad_checked = 0;
		ianas[i].decline_pending = 0;
	}
	ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_DHCP6_ADDR, 0);
	ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_DHCP6_SERVERID, 0);
	ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_DHCP6_DNS, 0);
	ioth_confdata_free(stack, ifindex, IOTH_CONFDATA_DHCP6_DOMAIN, 0);
	ioth_confdata_del_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP6_TIMESTAMP);
}

/* Compute earliest finite T1 deadline across all active IA_NAs.
 * Returns 1 if a finite T1 exists, 0 if all active IA_NAs have infinite T1/valid_lt. */
static int compute_earliest_t1(const struct dhcp6_iana_entry *ianas, size_t num_iana,
                               struct timespec *out_deadline) {
	int found = 0;
	for (size_t i = 0; i < num_iana; i++) {
		if (!ianas[i].has_addr || ianas[i].t1_infinite || ianas[i].valid_infinite)
			continue;
		if (!found || ts_cmp(ianas[i].t1_deadline, *out_deadline) < 0) {
			*out_deadline = ianas[i].t1_deadline;
			found = 1;
		}
	}
	return found;
}

/* Compute earliest finite T2 deadline across all active IA_NAs.
 * Returns 1 if a finite T2 exists, 0 if all active IA_NAs have infinite T2/valid_lt. */
static int compute_earliest_t2(const struct dhcp6_iana_entry *ianas, size_t num_iana,
                               struct timespec *out_deadline) {
	int found = 0;
	for (size_t i = 0; i < num_iana; i++) {
		if (!ianas[i].has_addr || ianas[i].t2_infinite || ianas[i].valid_infinite)
			continue;
		if (!found || ts_cmp(ianas[i].t2_deadline, *out_deadline) < 0) {
			*out_deadline = ianas[i].t2_deadline;
			found = 1;
		}
	}
	return found;
}

/* Compute latest finite valid_lifetime deadline across all active IA_NAs .
 * Returns 1 if a finite valid_lt exists, 0 if any active IA_NA has infinite valid_lt (or none active). */
static int compute_latest_valid(const struct dhcp6_iana_entry *ianas, size_t num_iana,
                                struct timespec *out_deadline) {
	int found = 0;
	for (size_t i = 0; i < num_iana; i++) {
		if (!ianas[i].has_addr)
			continue;
		if (ianas[i].valid_infinite)
			return 0; /* At least one lease never expires */
		if (!found || ts_cmp(ianas[i].valid_deadline, *out_deadline) > 0) {
			*out_deadline = ianas[i].valid_deadline;
			found = 1;
		}
	}
	return found;
}

int ioth_dhcpv6_thread(struct ioth *stack, unsigned int ifindex, const char *fqdn,
                       uint32_t config_flags, time_t timestamp, size_t num_iana, int state) {
	(void)timestamp;
	printf("ioth_dhcpv6_thread dentro (num_iana=%zu)\n", num_iana);

	struct dhcp6_iana_entry *ianas = calloc(num_iana, sizeof(*ianas));
	if (!ianas) {
		perror("calloc ianas");
		return 1;
	}

	uint8_t macaddr[ETH_ALEN] = {0};
	ioth_linkgetaddr(stack, ifindex, macaddr);
	dhcp6_init_iaids(ianas, num_iana, macaddr);

	int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timerfd == -1) {
		perror("timerfd_create");
		free(ianas);
		return 1;
	}
	struct itimerspec timerspec1, timerspec2;
	struct pollfd plfd;

	uint8_t serverid[DHCP6_MAX_SERVERID] = {0};
	uint16_t serveridlen = 0;
	uint32_t sol_max_rt = SOL_MAX_RT_DEFAULT;
	time_t dhcp_timestamp = 0;

	struct dhcp6_ratelimit rl;
	dhcp6_rl_init(&rl);

	int dhcp_socket = -1;

	pthread_cleanup_push(free, ianas);
	pthread_cleanup_push(fd6_close_clean, &timerfd);
	pthread_cleanup_push(ioth6_close_clean, &dhcp_socket);

	while (state != UNBOUND) {
		switch (state) {
			case INIT: {
				pthread_testcancel();
				set_dhcp6_thread_status(stack, ifindex, INIT);
				printf("DHCP6 Enter INIT (richieste %zu IA_NA)\n", num_iana);

				dhcp_timestamp = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP6_TIMESTAMP);
				int rv = iothconf_dhcpv6_proto(stack, ifindex, fqdn, config_flags, dhcp_timestamp,
				                               &dhcp_socket, serverid, &serveridlen,
				                               ianas, num_iana, &sol_max_rt, &rl);
				if (rv == 0) {
					state = BOUND;
					printf("DHCP6 BOUND raggiunto\n");
				} else if (errno == ECANCELED || errno == ETIME) {
					printf("DHCP6 INIT fallito (%s), riprovo in INIT\n", strerror(errno));
					state = INIT;
				} else {
					state = UNBOUND;
					printf("DHCP6 UNBOUND raggiunto (errno=%d: %s)\n", errno, strerror(errno));
				}
				break;
			}

			case BOUND: {
				set_dhcp6_thread_status(stack, ifindex, BOUND);
				printf("DHCP6 Enter BOUND\n");

				/* Install/refresh all active IPv6 addresses directly on the interface */
				size_t active_before_dad = 0;
				for (size_t i = 0; i < num_iana; i++) {
					if (ianas[i].has_addr) {
						char astr[INET6_ADDRSTRLEN];
						inet_ntop(AF_INET6, &ianas[i].addr, astr, sizeof(astr));
						if (set_ipv6_lifetime(stack, ifindex, ianas[i].addr, 128,
						                      ianas[i].preferred_lt, ianas[i].valid_lt) < 0) {
							perror("set_ipv6_lifetime");
						} else {
							printf("DHCP6 IA_NA[%zu]: %s/128 pref=%u valid=%u T1=%u T2=%u\n",
							       i, astr, ianas[i].preferred_lt, ianas[i].valid_lt,
							       ianas[i].t1, ianas[i].t2);
						}
						active_before_dad++;
					}
				}
				if (active_before_dad == 0) {
					state = INIT;
					break;
				}
				pthread_testcancel();

				/* Batched DAD check + selective DECLINE */
				size_t dad_failed = check_ipv6_dad_multi(stack, ifindex, ianas, num_iana);
				if (dad_failed > 0) {
					printf("DHCP6 DAD failed su %zu IA_NA: invio DECLINE selettivo\n", dad_failed);
					dhcp_socket = dhcp6_open_socket(stack, ifindex);
					if (dhcp_socket >= 0) {
						struct dhcp6data decl_data = {
							.stack = stack,
							.ifindex = ifindex,
							.timestamp = dhcp_timestamp,
							.fqdn = NULL,
							.serveridlen = serveridlen,
							.ianas = ianas,
							.num_iana = num_iana,
							.req_adv = NULL,
							.sol_max_rt = sol_max_rt,
							.rl = rl
						};
						memcpy(decl_data.serverid, serverid, serveridlen);
						memcpy(decl_data.macaddr, macaddr, ETH_ALEN);
						dhcp6_build_duid_ll(decl_data.duid, decl_data.macaddr);

						dhcp6_send(DHCP6_DECLINE, dhcp_socket, -1, &decl_data);
						rl = decl_data.rl;
						ioth_close(dhcp_socket);
						dhcp_socket = -1;
					}
					for (size_t i = 0; i < num_iana; i++)
						ianas[i].decline_pending = 0;

					size_t remaining_active = 0;
					for (size_t i = 0; i < num_iana; i++) {
						if (ianas[i].has_addr)
							remaining_active++;
					}
					if (remaining_active == 0) {
						halt_all_network6(stack, ifindex, ianas, num_iana);
						state = INIT;
						break;
					}
					/* Retain non-conflicting bindings and refresh confdata snapshot */
					dhcp_timestamp = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP6_TIMESTAMP);
					sync_confdata_snapshot(stack, ifindex, dhcp_timestamp,
					                       serverid, serveridlen, ianas, num_iana);
				}

				/* Compute earliest T1 across all active IA_NAs */
				struct timespec t1_dl;
				if (!compute_earliest_t1(ianas, num_iana, &t1_dl)) {
					/* All active leases have infinite T1 or valid_lifetime */
					for (;;) {
						pthread_testcancel();
						pause();
					}
				}

				struct timespec now = ts_now();
				uint32_t t1_wait = ts_rem_sec(t1_dl, now);
				if (t1_wait == 0) t1_wait = 1;

				if (set_timer6_poll(timerfd, &timerspec1, t1_wait, &plfd) == 1) {
					state = UNBOUND;
					break;
				}
				pthread_testcancel();

				int ret1 = poll(&plfd, 1, -1);//wait on T1
				if (ret1 == -1) {
					if (errno == EINTR)
						continue;
					perror("Errore nella poll");
					state = UNBOUND;
					break;
				}

				if (plfd.revents & POLLIN) {
					consume_timer6(timerfd);
					printf("DHCP6 concluso earliest T1 -> RENEW\n");

					struct timespec t2_dl;
					struct timespec now2 = ts_now();
					uint32_t t2_delta = 1;
					if (compute_earliest_t2(ianas, num_iana, &t2_dl)) {
						t2_delta = ts_rem_sec(t2_dl, now2);
						if (t2_delta == 0) t2_delta = 1;
					} else if (compute_latest_valid(ianas, num_iana, &t2_dl)) {
						t2_delta = ts_rem_sec(t2_dl, now2);
						if (t2_delta == 0) t2_delta = 1;
					}
					if (set_timer6_poll(timerfd, &timerspec2, t2_delta, &plfd) == 1) {
						state = UNBOUND;
						break;
					}
					state = RENEW;
				}
				break;
			}

			case RENEW: {
				pthread_testcancel();
				set_dhcp6_thread_status(stack, ifindex, RENEW);
				printf("DHCP6 Enter RENEW\n");

				dhcp_socket = dhcp6_open_socket(stack, ifindex);
				if (dhcp_socket < 0) {
					state = UNBOUND;
					break;
				}

				struct dhcp6data dhcpdata = {
					.stack = stack,
					.ifindex = ifindex,
					.timestamp = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP6_TIMESTAMP),
					.fqdn = fqdn,
					.serveridlen = serveridlen,
					.ianas = ianas,
					.num_iana = num_iana,
					.req_adv = NULL,
					.sol_max_rt = sol_max_rt,
					.rl = rl
				};
				memcpy(dhcpdata.serverid, serverid, serveridlen);
				memcpy(dhcpdata.macaddr, macaddr, ETH_ALEN);
				dhcp6_build_duid_ll(dhcpdata.duid, dhcpdata.macaddr);

				int rv = dhcp6_send(DHCP6_RENEW, dhcp_socket, timerfd, &dhcpdata);

				/* If any IA returned NoBinding, send REQUEST with all IAs */
				if (rv < 0 && errno == ENOENT) {
					printf("DHCP6 NoBinding in RENEW: invio REQUEST con tutte le IA_NA\n");
					rv = dhcp6_send(DHCP6_REQUEST, dhcp_socket, timerfd, &dhcpdata);
				}

				int saved_errno = errno;
				sol_max_rt = dhcpdata.sol_max_rt;
				rl = dhcpdata.rl;
				ioth_close(dhcp_socket);
				dhcp_socket = -1;

				if (rv == 0) {
					dhcp_timestamp = dhcpdata.timestamp;
					memcpy(serverid, dhcpdata.serverid, dhcpdata.serveridlen);
					serveridlen = dhcpdata.serveridlen;
					state = BOUND;
				} else if (saved_errno == ECANCELED) {
					printf("DHCP6 RENEW rifiutato/scaduto: halt network -> INIT\n");
					halt_all_network6(stack, ifindex, ianas, num_iana);
					state = INIT;
				} else if (poll(&plfd, 1, 0) > 0 && (plfd.revents & POLLIN)) {
					consume_timer6(timerfd);
					struct timespec t2_check;
					if (!compute_earliest_t2(ianas, num_iana, &t2_check)) {
						/* all T2 == infinity -> never rebind */
						halt_all_network6(stack, ifindex, ianas, num_iana);
						state = INIT;
					} else {
						printf("DHCP6 Scaduto earliest T2 -> REBIND\n");
						struct timespec max_valid_dl;
						uint32_t rem = 1;
						if (compute_latest_valid(ianas, num_iana, &max_valid_dl)) {
							rem = ts_rem_sec(max_valid_dl, ts_now());
							if (rem == 0) rem = 1;
						}
						if (set_timer6_poll(timerfd, &timerspec2, rem, &plfd) == 1) {
							state = UNBOUND;
							break;
						}
						state = REBIND;
					}
				}
				break;
			}

			case REBIND: {
				pthread_testcancel();
				set_dhcp6_thread_status(stack, ifindex, REBIND);
				printf("DHCP6 Enter REBIND\n");

				dhcp_socket = dhcp6_open_socket(stack, ifindex);
				if (dhcp_socket < 0) {
					state = UNBOUND;
					break;
				}

				struct dhcp6data dhcpdata = {
					.stack = stack,
					.ifindex = ifindex,
					.timestamp = ioth_confdata_new_timestamp(stack, ifindex, IOTH_CONFDATA_DHCP6_TIMESTAMP),
					.fqdn = fqdn,
					.serveridlen = 0, /* MUST NOT include Server ID in REBIND */
					.ianas = ianas,
					.num_iana = num_iana,
					.req_adv = NULL,
					.sol_max_rt = sol_max_rt,
					.rl = rl
				};
				memcpy(dhcpdata.macaddr, macaddr, ETH_ALEN);
				dhcp6_build_duid_ll(dhcpdata.duid, dhcpdata.macaddr);

				int rv = dhcp6_send(DHCP6_REBIND, dhcp_socket, timerfd, &dhcpdata);

				/* if any IA returned NoBinding, send REQUEST with all IAs */
				if (rv < 0 && errno == ENOENT) {
					printf("DHCP6 NoBinding in REBIND: invio REQUEST con tutte le IA_NA\n");
					rv = dhcp6_send(DHCP6_REQUEST, dhcp_socket, timerfd, &dhcpdata);
				}

				int saved_errno = errno;
				sol_max_rt = dhcpdata.sol_max_rt;
				rl = dhcpdata.rl;
				ioth_close(dhcp_socket);
				dhcp_socket = -1;

				if (rv == 0) {
					dhcp_timestamp = dhcpdata.timestamp;
					memcpy(serverid, dhcpdata.serverid, dhcpdata.serveridlen);
					serveridlen = dhcpdata.serveridlen;
					state = BOUND;
				} else if (saved_errno == ECANCELED) {
					printf("DHCP6 REBIND rifiutato: halt network -> INIT\n");
					halt_all_network6(stack, ifindex, ianas, num_iana);
					state = INIT;
				} else if (poll(&plfd, 1, 0) > 0 && (plfd.revents & POLLIN)) {
					printf("DHCP6 Tutti i lease scaduti in REBIND: halt network -> INIT\n");
					consume_timer6(timerfd);
					halt_all_network6(stack, ifindex, ianas, num_iana);
					state = INIT;
				}
				break;
			}

			default:
				break;
		}
	}

	set_dhcp6_thread_status(stack, ifindex, UNBOUND);
	pthread_cleanup_pop(0); /* dhcp_socket */
	pthread_cleanup_pop(0); /* timerfd */
	pthread_cleanup_pop(1); /* frees ianas */

	close(timerfd);
	timerfd = -1;
	return UNBOUND;
}
