#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#include "nc_stack.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/timeouts.h"
#include "lwip/inet_chksum.h"
#include "lwip/priv/tcp_priv.h"

void nc_lwip_assert_failed(void) { abort(); }

/* feat/nc-wg: lwIP is initialised once per process. WireGuard netifs (nc_wg.c) live in the same instance and
   may outlive a TUN restart, so a second lwip_init() (which re-initialises the pools under live PCBs) is never
   run; nc_shutdown purges the TUN's own PCBs instead. */
static int g_lwip_ready;
void nc_lwip_ensure_init(void) {
  if (g_lwip_ready) return;
  lwip_init();
  g_lwip_ready = 1;
}

/* Abort every TUN-side PCB — unbound, or (fix/nc-tcp1) bound to the TUN netif `tun_idx` like every accepted PCB
   since listeners are TUN-bound; WireGuard client PCBs are bound to their own netif — including ones still closing
   / in TIME-WAIT after we dropped them. */
static void nc_purge_unbound(struct tcp_pcb **list, u8_t tun_idx) {
  for (;;) {
    struct tcp_pcb *p = *list;
    while (p && p->netif_idx != NETIF_NO_INDEX && p->netif_idx != tun_idx) p = p->next;
    if (!p) return;
    tcp_arg(p, NULL);
    tcp_recv(p, NULL);
    tcp_sent(p, NULL);
    tcp_err(p, NULL);
    tcp_abort(p);
  }
}

#ifdef NC_STACK_TEST_CLOCK
/* fix/nc-tcp1: host soak test (tools/nc-stack-test/nc_soak_test.c) drives a simulated clock so minutes of
   traffic — listener idle expiry, TIME_WAIT (2×MSL), UDP idle — run in milliseconds. Never defined in the app. */
static u32_t g_test_now_ms;
void nc_test_set_now(u32_t ms) { g_test_now_ms = ms; }
u32_t sys_now(void) { return g_test_now_ms; }
#else
u32_t sys_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (u32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}
#endif

/* ------------------------------------------------------------------ state */

/* fix/nc-tcp1: one listener per destination PORT (any address, v4+v6), so this bounds distinct ports, not
   destinations; it must not exceed lwIP's listen-PCB pool or tcp_listen fails before the table ever evicts. */
#define NC_MAX_LISTENERS 24
#define NC_MAX_UDP_SESSIONS 64
/* fix/nc-stack-pool-capacity: 96 → 288. At 96 the accept callback aborted
   burst connections outright (conn_full fired 14–23× in 12–15 s clean
   single-app device sessions, 2460× in a full-config session): apps whose
   connect() is aborted mid-burst show dead content while neighbours survive.
   288 + 24 listeners stays under MEMP_NUM_TCP_PCB (384) with TIME_WAIT room. */
#define NC_MAX_TCP_CONNS 288
#define NC_UDP_IDLE_MS (120 * 1000)
#define NC_LISTENER_IDLE_MS (300 * 1000)

typedef struct {
  int used;
  ip_addr_t dst;
  u16_t port;
  struct tcp_pcb *lpcb;
  int active;
  u32_t last_used;
} nc_listener;

typedef struct nc_conn {
  int used;
  struct tcp_pcb *pcb;
  nc_listener *listener;
  int closing; /* we called tcp_close; slot frees when lwIP is done with it */
} nc_conn;

typedef struct {
  int used;
  uint32_t id;
  ip_addr_t src;
  u16_t src_port;
  ip_addr_t dst;
  u16_t dst_port;
  struct udp_pcb *pcb;
  u32_t last_used;
} nc_udp_session;

static nc_callbacks g_cbs;
static void *g_ctx;
static struct netif g_netif;
static int g_up;
static nc_listener g_listeners[NC_MAX_LISTENERS];
static nc_conn g_conns[NC_MAX_TCP_CONNS];
static nc_udp_session g_udp[NC_MAX_UDP_SESSIONS];
static uint32_t g_next_udp_id = 1;
static uint8_t g_scratch[70000];
static nc_stats g_stats;
/* fix/nc-tcp1: set by nc_input for the packet being fed — TCP / UDP is always terminated here (see nc_lwip_dest_ours). */
static int g_input_l4_ours;
#if NC_MAX_LISTENERS > MEMP_NUM_TCP_PCB_LISTEN
#error "NC_MAX_LISTENERS must fit lwIP's listen-PCB pool (MEMP_NUM_TCP_PCB_LISTEN)"
#endif

void nc_get_stats(nc_stats *out) {
  if (out) *out = g_stats;
}

void nc_lwip_count_not_ours(int is6) {
  if (is6) g_stats.v6_not_ours++; else g_stats.v4_not_ours++;
}

/* SYN-ACK / RST accounting for packets the stack emits (TCP flags of a v4 / v6 packet without extension headers). */
static void nc_count_out(const uint8_t *p, u16_t n) {
  g_stats.out_pkts++;
  if (n < 20) return;
  const uint8_t *t = NULL;
  if ((p[0] >> 4) == 4 && p[9] == 6) {
    u16_t ihl = (u16_t)((p[0] & 0x0f) * 4);
    if (n >= ihl + 20) t = p + ihl;
  } else if ((p[0] >> 4) == 6 && n >= 60 && p[6] == 6) {
    t = p + 40;
  }
  if (!t) return;
  if ((t[13] & 0x12) == 0x12) g_stats.out_synack++;
  if (t[13] & 0x04) g_stats.out_rst++;
}

/* ------------------------------------------------------- address helpers */

static void nc_ip_to_bytes(const ip_addr_t *ip, uint8_t out[16], int *is6) {
  if (IP_IS_V6(ip)) {
    *is6 = 1;
    const ip6_addr_t *a6 = ip_2_ip6(ip);
    for (int i = 0; i < 4; i++) {
      uint32_t v = lwip_ntohl(a6->addr[i]);
      out[i * 4 + 0] = (uint8_t)(v >> 24);
      out[i * 4 + 1] = (uint8_t)(v >> 16);
      out[i * 4 + 2] = (uint8_t)(v >> 8);
      out[i * 4 + 3] = (uint8_t)(v);
    }
  } else {
    *is6 = 0;
    uint32_t v = lwip_ntohl(ip_2_ip4(ip)->addr);
    memset(out, 0, 16);
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
  }
}

static int nc_ip_equal(const ip_addr_t *a, const ip_addr_t *b) {
  return ip_addr_cmp(a, b);
}

/* ------------------------------------------------------------ netif glue */

static err_t nc_netif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
  (void)netif;
  (void)ipaddr;
  if (p->tot_len == 0 || p->tot_len > sizeof(g_scratch)) return ERR_OK;
  u16_t n = pbuf_copy_partial(p, g_scratch, p->tot_len, 0);
  nc_count_out(g_scratch, n);
  if (g_cbs.output) g_cbs.output(g_ctx, g_scratch, n);
  return ERR_OK;
}

#if LWIP_IPV6
static err_t nc_netif_output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
  (void)netif;
  (void)ipaddr;
  if (p->tot_len == 0 || p->tot_len > sizeof(g_scratch)) return ERR_OK;
  u16_t n = pbuf_copy_partial(p, g_scratch, p->tot_len, 0);
  nc_count_out(g_scratch, n);
  if (g_cbs.output) g_cbs.output(g_ctx, g_scratch, n);
  return ERR_OK;
}
#endif

static err_t nc_netif_init(struct netif *netif) {
  netif->name[0] = 't';
  netif->name[1] = 'n';
  netif->output = nc_netif_output;
#if LWIP_IPV6
  netif->output_ip6 = nc_netif_output6;
#endif
  netif->mtu = 4064;
  netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
  return ERR_OK;
}

/* ------------------------------------------------------------------- TCP */

static void nc_conn_free_slot(nc_conn *c) {
  if (c->listener) c->listener->active--;
  memset(c, 0, sizeof(*c));
}

static void nc_tcp_err_cb(void *arg, err_t err) {
  nc_conn *c = (nc_conn *)arg;
  if (!c || !c->used) return;
  c->pcb = NULL;
  if (g_cbs.tcp_err) g_cbs.tcp_err(g_ctx, c, (int)err);
  nc_conn_free_slot(c);
}

static err_t nc_tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len) {
  (void)pcb;
  nc_conn *c = (nc_conn *)arg;
  /* rv2-life: send window opened — the engine drains its outbox and resumes the relay read (back-pressure). */
  if (c && c->used && c->pcb && g_cbs.tcp_sent) g_cbs.tcp_sent(g_ctx, c, (uint32_t)len);
  return ERR_OK;
}

static err_t nc_tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
  nc_conn *c = (nc_conn *)arg;
  if (!c || !c->used) {
    if (p) pbuf_free(p);
    return ERR_OK;
  }
  if (err != ERR_OK) {
    if (p) pbuf_free(p);
    return ERR_OK;
  }
  if (p == NULL) {
    /* FIN from the peer. */
    if (g_cbs.tcp_recv) g_cbs.tcp_recv(g_ctx, c, NULL, 0);
    return ERR_OK;
  }
  u16_t total = p->tot_len;
  if (total <= sizeof(g_scratch)) {
    u16_t n = pbuf_copy_partial(p, g_scratch, total, 0);
    if (g_cbs.tcp_recv) g_cbs.tcp_recv(g_ctx, c, g_scratch, n);
  } else {
    tcp_recved(pcb, total); /* cannot happen (tot_len is u16); never leave the window shut */
  }
  /* rv2-life: no tcp_recved here — the engine acknowledges with nc_tcp_recved once the relay took the bytes. */
  pbuf_free(p);
  return ERR_OK;
}

static err_t nc_tcp_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
  nc_listener *lst = (nc_listener *)arg;
  if (err != ERR_OK || newpcb == NULL) return ERR_OK;
  nc_conn *slot = NULL;
  for (int i = 0; i < NC_MAX_TCP_CONNS; i++) {
    if (!g_conns[i].used) {
      slot = &g_conns[i];
      break;
    }
  }
  if (!slot) {
    g_stats.conn_full++;
    tcp_abort(newpcb);
    return ERR_ABRT;
  }
  memset(slot, 0, sizeof(*slot));
  slot->used = 1;
  slot->pcb = newpcb;
  slot->listener = lst;
  if (lst) {
    lst->active++;
    lst->last_used = sys_now();
  }
  tcp_arg(newpcb, slot);
  tcp_recv(newpcb, nc_tcp_recv_cb);
  tcp_err(newpcb, nc_tcp_err_cb);
  tcp_sent(newpcb, nc_tcp_sent_cb);
  tcp_nagle_disable(newpcb);

  uint8_t dstb[16], srcb[16];
  int d6 = 0, s6 = 0;
  nc_ip_to_bytes(&newpcb->local_ip, dstb, &d6);
  nc_ip_to_bytes(&newpcb->remote_ip, srcb, &s6);
  int keep = 1;
  g_stats.accepted++;
  if (g_cbs.tcp_accept) {
    keep = g_cbs.tcp_accept(g_ctx, slot, dstb, newpcb->local_port, srcb, newpcb->remote_port, d6);
  }
  if (!keep) {
    g_stats.accept_refused++;
    tcp_abort(newpcb);
    nc_conn_free_slot(slot);
    return ERR_ABRT;
  }
  return ERR_OK;
}

/* fix/nc-tcp1 (build433 "listen fail" / "not-ours" after ~60 s): listeners used to be keyed by (destination IP,
   port) — one lwIP listen PCB per distinct server address, kept 5 min. MEMP_NUM_TCP_PCB_LISTEN is 24 (nc-memory)
   while the table had 48 slots, so with real (redir-host) or many fake-ip destinations the 25th distinct address
   made tcp_listen() fail: the SYN was counted "listen fail", no listener → ip4/ip6_input_accept said "not ours" →
   silently dropped, the app retransmitted (each retry counted again) and never connected. Worse, the bound PCB
   from the failed tcp_listen was leaked every time, so after ~128 failures the TCP PCB pool itself was empty.
   Now: one listener per PORT bound to the any-type address (lwIP matches it for every v4/v6 destination and gives
   the accepted PCB the real destination as local_ip), bound to the TUN netif (WireGuard netifs never match it),
   SOF_REUSEADDR so a re-listen after idle expiry / eviction is not refused by live connections on that port;
   when the table is full the least recently used listener is closed (accepted connections live on: they are
   independent PCBs); a failed bind / listen frees its PCB. */
static void nc_listener_close(nc_listener *l) {
  for (int i = 0; i < NC_MAX_TCP_CONNS; i++) {
    if (g_conns[i].used && g_conns[i].listener == l) g_conns[i].listener = NULL;
  }
  if (l->lpcb) {
    tcp_arg(l->lpcb, NULL);
    tcp_accept(l->lpcb, NULL);
    tcp_close(l->lpcb); /* a LISTEN pcb always closes (frees) */
  }
  memset(l, 0, sizeof(*l));
}

static nc_listener *nc_ensure_listener(const ip_addr_t *dst, u16_t port) {
  (void)dst;
  int free_idx = -1, lru_idx = -1, lru_any = -1;
  u32_t now = sys_now(), lru_age = 0, any_age = 0;
  for (int i = 0; i < NC_MAX_LISTENERS; i++) {
    nc_listener *l = &g_listeners[i];
    if (!l->used) {
      if (free_idx < 0) free_idx = i;
      continue;
    }
    if (l->port == port) {
      l->last_used = now;
      return l;
    }
    u32_t age = now - l->last_used; /* ages: sys_now() wraps */
    if (l->active == 0 && (lru_idx < 0 || age > lru_age)) { lru_age = age; lru_idx = i; }
    if (lru_any < 0 || age > any_age) { any_age = age; lru_any = i; }
  }
  int idx = free_idx >= 0 ? free_idx : (lru_idx >= 0 ? lru_idx : lru_any);
  if (idx < 0) return NULL;
  nc_listener *l = &g_listeners[idx];
  if (l->used) nc_listener_close(l);
  struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (!pcb) return NULL;
  ip_set_option(pcb, SOF_REUSEADDR);
  tcp_bind_netif(pcb, &g_netif);
  if (tcp_bind(pcb, IP_ANY_TYPE, port) != ERR_OK) {
    tcp_abort(pcb);
    return NULL;
  }
  struct tcp_pcb *lpcb = tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG);
  if (!lpcb) {
    tcp_abort(pcb); /* tcp_listen leaves the original PCB to the caller on failure — it used to leak here */
    return NULL;
  }
  l->used = 1;
  ip_addr_set_any(1, &l->dst);
  l->port = port;
  l->lpcb = lpcb;
  l->last_used = now;
  tcp_arg(lpcb, l);
  tcp_accept(lpcb, nc_tcp_accept_cb);
  return l;
}

/* ------------------------------------------------------------------- UDP */

static void nc_udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                           const ip_addr_t *addr, u16_t port) {
  (void)pcb;
  nc_udp_session *s = (nc_udp_session *)arg;
  if (!s || !s->used) {
    if (p) pbuf_free(p);
    return;
  }
  if (p == NULL) return;
  s->last_used = sys_now();
  uint8_t srcb[16], dstb[16];
  int s6 = 0, d6 = 0;
  nc_ip_to_bytes(addr, srcb, &s6);
  nc_ip_to_bytes(&s->dst, dstb, &d6);
  if (p->tot_len <= sizeof(g_scratch)) {
    u16_t n = pbuf_copy_partial(p, g_scratch, p->tot_len, 0);
    if (g_cbs.udp_recv) {
      g_cbs.udp_recv(g_ctx, s->id, srcb, port, dstb, s->dst_port, d6, g_scratch, n);
    }
  }
  pbuf_free(p);
}

/* rv2-life: tell the engine a session it may hold a relay for is gone (expiry / eviction). */
static void nc_udp_notify_closed(nc_udp_session *s) {
  if (s->used && g_cbs.udp_closed) g_cbs.udp_closed(g_ctx, s->id);
}

#define NC_UDP_DNS_IDLE_MS (10 * 1000)

static nc_udp_session *nc_ensure_udp_session(const ip_addr_t *src, u16_t src_port,
                                             const ip_addr_t *dst, u16_t dst_port) {
  int free_idx = -1, lru_idx = -1, dns_idx = -1;
  u32_t lru_age = 0, dns_age = 0;
  u32_t now = sys_now();
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    nc_udp_session *s = &g_udp[i];
    if (!s->used) {
      if (free_idx < 0) free_idx = i;
      continue;
    }
    if (s->src_port == src_port && s->dst_port == dst_port &&
        nc_ip_equal(&s->src, src) && nc_ip_equal(&s->dst, dst)) {
      return s;
    }
    /* ages, not raw timestamps: sys_now() wraps after ~49 days */
    u32_t age = now - s->last_used;
    if (lru_idx < 0 || age > lru_age) {
      lru_age = age;
      lru_idx = i;
    }
    /* rv2-life: idle DNS sessions (one query, one answer) go first, before any live flow */
    if (s->dst_port == 53 && age >= NC_UDP_DNS_IDLE_MS && (dns_idx < 0 || age > dns_age)) {
      dns_age = age;
      dns_idx = i;
    }
  }
  int idx = free_idx >= 0 ? free_idx : (dns_idx >= 0 ? dns_idx : lru_idx);
  if (idx < 0) return NULL;
  nc_udp_session *s = &g_udp[idx];
  if (s->used) {
    /* rv2-life: evicting a live session — the engine drops its relay too (it used to keep it and silently lose
       every reply, since nc_udp_send no longer finds the id) */
    nc_udp_notify_closed(s);
    if (s->pcb) udp_remove(s->pcb);
  }
  memset(s, 0, sizeof(*s));
  struct udp_pcb *pcb = udp_new_ip_type(dst->type);
  if (!pcb) return NULL;
  ip_set_option(pcb, SOF_REUSEADDR);
  if (udp_bind(pcb, dst, dst_port) != ERR_OK) {
    udp_remove(pcb);
    return NULL;
  }
  udp_connect(pcb, src, src_port);
  s->used = 1;
  s->id = g_next_udp_id++;
  if (g_next_udp_id == 0) g_next_udp_id = 1;
  s->src = *src;
  s->src_port = src_port;
  s->dst = *dst;
  s->dst_port = dst_port;
  s->pcb = pcb;
  s->last_used = sys_now();
  udp_recv(pcb, nc_udp_recv_cb, s);
  return s;
}

/* --------------------------------------------------------- packet intake */

/* Peek at a raw IP packet; install a listener/session for new TCP SYNs and
   new UDP flows before lwIP sees the packet. Returns 1 when the packet is
   TCP/UDP and was classified, 0 otherwise (lwIP still gets the packet). */
static void nc_peek(const uint8_t *pkt, uint32_t len) {
  if (len < 20) return;
  uint8_t v = pkt[0] >> 4;
  if (v == 4) {
    uint32_t ihl = (pkt[0] & 0x0f) * 4;
    if (len < ihl + 8) return;
    uint8_t proto = pkt[9];
    ip_addr_t src, dst;
    IP_ADDR4(&src, pkt[12], pkt[13], pkt[14], pkt[15]);
    IP_ADDR4(&dst, pkt[16], pkt[17], pkt[18], pkt[19]);
    const uint8_t *l4 = pkt + ihl;
    if (proto == 6 && len >= ihl + 20) {
      uint16_t sport = (uint16_t)(l4[0] << 8 | l4[1]);
      uint16_t dport = (uint16_t)(l4[2] << 8 | l4[3]);
      uint8_t flags = l4[13];
      (void)sport;
      if ((flags & 0x02) && !(flags & 0x10)) { /* SYN, not ACK */
        g_stats.syn_v4++;
        if (!nc_ensure_listener(&dst, dport)) g_stats.listen_fail++;
      }
    } else if (proto == 17 && len >= ihl + 8) {
      uint16_t sport = (uint16_t)(l4[0] << 8 | l4[1]);
      uint16_t dport = (uint16_t)(l4[2] << 8 | l4[3]);
      if (!nc_ensure_udp_session(&src, sport, &dst, dport)) g_stats.udp_session_fail++;
    }
  } else if (v == 6) {
    if (len < 48) return;
    uint8_t next = pkt[6];
    ip_addr_t src, dst;
    /* fix/nc-tcp0: IP6_ADDR takes the words in NETWORK order (what the header holds). This used lwip_ntohl, so on
       a little-endian CPU every v6 listener / UDP session was bound to a byte-swapped address that no packet ever
       carries — lwIP then dropped all IPv6 TCP / UDP as "not for us". memcpy: the header may be unaligned. */
    uint32_t w[8];
    memcpy(w, pkt + 8, sizeof(w));
    IP_ADDR6(&src, w[0], w[1], w[2], w[3]);
    IP_ADDR6(&dst, w[4], w[5], w[6], w[7]);
    const uint8_t *l4 = pkt + 40;
    if (next == 6 && len >= 60) {
      uint16_t dport = (uint16_t)(l4[2] << 8 | l4[3]);
      uint8_t flags = l4[13];
      if ((flags & 0x02) && !(flags & 0x10)) {
        g_stats.syn_v6++;
        if (!nc_ensure_listener(&dst, dport)) g_stats.listen_fail++;
      }
    } else if (next == 17) {
      uint16_t sport = (uint16_t)(l4[0] << 8 | l4[1]);
      uint16_t dport = (uint16_t)(l4[2] << 8 | l4[3]);
      if (!nc_ensure_udp_session(&src, sport, &dst, dport)) g_stats.udp_session_fail++;
    }
  }
}

/* -------------------------------------------------------------- public API */

int nc_init(const nc_callbacks *cbs, void *ctx, const char *ip4, const char *ip6, uint16_t mtu) {
  if (g_up) nc_shutdown();
  memset(g_listeners, 0, sizeof(g_listeners));
  memset(g_conns, 0, sizeof(g_conns));
  memset(g_udp, 0, sizeof(g_udp));
  memset(&g_stats, 0, sizeof(g_stats));
  if (cbs) g_cbs = *cbs;
  g_ctx = ctx;
  nc_lwip_ensure_init();
  ip4_addr_t a4, mask, gw;
  ip4_addr_set_zero(&a4);
  ip4_addr_set_zero(&gw);
  if (ip4 && !ip4addr_aton(ip4, &a4)) return -1;
  IP4_ADDR(&mask, 255, 255, 0, 0);
  netif_add(&g_netif, &a4, &mask, &gw, NULL, nc_netif_init, ip_input);
  if (mtu) g_netif.mtu = mtu;
#if LWIP_IPV6
  netif_create_ip6_linklocal_address(&g_netif, 1);
  if (ip6) {
    ip6_addr_t a6;
    if (ip6addr_aton(ip6, &a6)) {
      s8_t idx = netif_add_ip6_address(&g_netif, &a6, NULL);
      if (idx >= 0) netif_ip6_addr_set_state(&g_netif, idx, IP6_ADDR_PREFERRED);
    }
  }
#endif
  netif_set_default(&g_netif);
  netif_set_up(&g_netif);
  netif_set_link_up(&g_netif); /* ip4_route() refuses a default netif without link */

  g_up = 1;
  return 0;
}

void nc_shutdown(void) {
  if (!g_up) return;
  for (int i = 0; i < NC_MAX_LISTENERS; i++) {
    if (g_listeners[i].used) nc_listener_close(&g_listeners[i]);
  }
  for (int i = 0; i < NC_MAX_TCP_CONNS; i++) {
    if (g_conns[i].used && g_conns[i].pcb) tcp_abort(g_conns[i].pcb);
  }
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    if (g_udp[i].used && g_udp[i].pcb) udp_remove(g_udp[i].pcb);
  }
  u8_t tun_idx = netif_get_index(&g_netif);
  nc_purge_unbound(&tcp_active_pcbs, tun_idx);
  nc_purge_unbound(&tcp_tw_pcbs, tun_idx);
  netif_remove(&g_netif);
  memset(g_listeners, 0, sizeof(g_listeners));
  memset(g_conns, 0, sizeof(g_conns));
  memset(g_udp, 0, sizeof(g_udp));
  g_up = 0;
}

void nc_input(const uint8_t *pkt, uint32_t len) {
  if (!g_up || len == 0) return;
  uint8_t v = pkt[0] >> 4;
  if (v == 4 && len >= 20) g_stats.in_v4++;
  else if (v == 6 && len >= 40) g_stats.in_v6++;
  else g_stats.in_other++;
  nc_peek(pkt, len);
  /* fix/nc-tcp1: every TCP / UDP packet the TUN delivers is terminated here (TCP by the per-port listener or an
     established PCB — anything else gets a RST from lwIP instead of a silent drop; UDP by the session nc_peek just
     ensured). Only other protocols (ICMP) still go by the per-destination tables. v6: no extension-header walk. */
  g_input_l4_ours = (v == 4 && len >= 20 && (pkt[9] == 6 || pkt[9] == 17)) ||
                    (v == 6 && len >= 40 && (pkt[6] == 6 || pkt[6] == 17));
  struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
  if (!p) {
    g_stats.input_err++;
    return;
  }
  pbuf_take(p, pkt, (u16_t)len);
  if (g_netif.input(p, &g_netif) != ERR_OK) {
    g_stats.input_err++;
    pbuf_free(p);
  }
  g_input_l4_ours = 0;
}

void nc_poll(void) {
  if (!g_up) return;
  sys_check_timeouts();
  u32_t now = sys_now();
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    nc_udp_session *s = &g_udp[i];
    if (s->used && now - s->last_used > NC_UDP_IDLE_MS) {
      nc_udp_notify_closed(s); /* rv2-life: keep the engine's session table in step */
      udp_remove(s->pcb);
      memset(s, 0, sizeof(*s));
    }
  }
  for (int i = 0; i < NC_MAX_LISTENERS; i++) {
    nc_listener *l = &g_listeners[i];
    if (l->used && l->active == 0 && now - l->last_used > NC_LISTENER_IDLE_MS) nc_listener_close(l);
  }
}

int nc_tcp_write(void *conn, const uint8_t *data, uint32_t len) {
  nc_conn *c = (nc_conn *)conn;
  if (!c || !c->used || !c->pcb) return -1;
  u32_t off = 0;
  while (off < len) {
    /* lwIP's tcp_write is all-or-nothing against the send buffer (TCP_SND_BUF,
       16 * MSS = 23360 B): a call larger than the free space returns ERR_MEM and
       queues NOTHING. Chunking by the u16 API limit (0xffff), as this used to do,
       made every write over ~23 KB a guaranteed no-op — and the engine's drain
       passes whole relay reads (up to 64 KB) as single writes, so any flow whose
       relay ever delivered a >23 KB chunk wedged for good: the response sat in
       the outbox, no tcp_sent could ever fire for it, and the tick retried the
       same oversized head until the app gave up (device builds 545-547: XHS /
       YouTube content flows stalling after the first burst, Ximalaya audio
       pausing once the player buffer drained). Size each chunk by the space
       actually free; a partial result just means "retry after tcp_sent". */
    u16_t avail = tcp_sndbuf(c->pcb);
    if (avail == 0) break;
    u32_t want = len - off;
    if (want > avail) want = avail;
    err_t e = tcp_write(c->pcb, data + off, (u16_t)want, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK) break;
    off += (u16_t)want;
  }
  if (off > 0) tcp_output(c->pcb);
  return (int)off;
}

void nc_tcp_recved(void *conn, uint32_t len) {
  nc_conn *c = (nc_conn *)conn;
  if (!c || !c->used || !c->pcb) return;
  while (len > 0) {
    u16_t chunk = (u16_t)(len > 0xffff ? 0xffff : len);
    tcp_recved(c->pcb, chunk); /* lwIP clamps the window at TCP_WND */
    len -= chunk;
  }
}

void nc_tcp_output(void *conn) {
  nc_conn *c = (nc_conn *)conn;
  if (c && c->used && c->pcb) tcp_output(c->pcb);
}

void nc_tcp_close(void *conn) {
  nc_conn *c = (nc_conn *)conn;
  if (!c || !c->used || !c->pcb) return;
  struct tcp_pcb *pcb = c->pcb;
  c->pcb = NULL;
  tcp_arg(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_err(pcb, NULL);
  if (tcp_close(pcb) != ERR_OK) {
    tcp_abort(pcb);
  }
  nc_conn_free_slot(c);
}

void nc_tcp_abort(void *conn) {
  nc_conn *c = (nc_conn *)conn;
  if (!c || !c->used || !c->pcb) return;
  struct tcp_pcb *pcb = c->pcb;
  c->pcb = NULL;
  tcp_arg(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_err(pcb, NULL);
  tcp_abort(pcb);
  nc_conn_free_slot(c);
}

/* UDP replies are emitted as hand-built IP packets, not through udp_send():
   lwIP refuses to send from a PCB whose local address differs from the
   netif's own address (udp.c: "local_ip doesn't match, drop the packet"),
   but in TUN mode every session is bound to the destination the app dialed,
   which is almost never the netif address. Building the 20/40-byte header
   here is simpler and safer than patching that check out of the stack. */
static uint8_t g_udp_out[65536];
static uint16_t g_ip_id = 1;

/* fix/nc-tcp0: RFC 1071 sum over bytes as big-endian 16-bit words (byte-order independent), folded, NOT inverted.
   The old code used inet_chksum / inet_chksum_pseudo, which return the sum in NETWORK order as a u16, and wrote it
   out with >> 8 — on the (little-endian) iPhone every hand-built UDP reply had its IPv4 header checksum and its
   UDP checksum byte-swapped, and the UDP sum skipped the UDP header (it covered only the payload pbuf). XNU drops
   such packets (bad IP header checksum / bad UDP checksum), so no DNS answer from the tunnel resolver ever
   reached an app: no lookup → no TCP connection → "tcp accepted 0". */
static uint32_t nc_sum16(const uint8_t *b, uint32_t n, uint32_t acc) {
  uint32_t i = 0;
  for (; i + 1 < n; i += 2) acc += ((uint32_t)b[i] << 8) | b[i + 1];
  if (n & 1) acc += (uint32_t)b[n - 1] << 8;
  return acc;
}
static uint16_t nc_fold(uint32_t acc) {
  while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
  return (uint16_t)acc;
}
static void nc_put16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v & 0xff);
}

int nc_udp_send(uint32_t session, const uint8_t *data, uint32_t len) {
  nc_udp_session *s = NULL;
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    if (g_udp[i].used && g_udp[i].id == session) { s = &g_udp[i]; break; }
  }
  if (!s) return -1;
  if (len > 65507) return -1;

  uint8_t srcb[16], dstb[16];
  int src6 = 0, dst6 = 0;
  nc_ip_to_bytes(&s->dst, srcb, &src6); /* reply source = original destination */
  nc_ip_to_bytes(&s->src, dstb, &dst6); /* reply target = the app endpoint */

  uint8_t *out = g_udp_out;
  uint32_t total;
  uint16_t udp_len = (uint16_t)(8 + len);
  uint8_t *u;
  uint32_t pseudo;
  if (!src6 && !dst6) {
    if (20u + udp_len > sizeof(g_udp_out)) return -1;
    uint16_t total_len = (uint16_t)(20 + udp_len);
    memset(out, 0, 28);
    out[0] = 0x45;
    nc_put16(out + 2, total_len);
    nc_put16(out + 4, g_ip_id++);
    out[6] = 0x40; /* DF */
    out[8] = 64;
    out[9] = 17;
    memcpy(out + 12, srcb, 4);
    memcpy(out + 16, dstb, 4);
    nc_put16(out + 10, (uint16_t)~nc_fold(nc_sum16(out, 20, 0)));
    u = out + 20;
    pseudo = nc_sum16(out + 12, 8, 0) + 17u + udp_len;
    total = total_len;
  } else if (src6 && dst6) {
    if (40u + udp_len > sizeof(g_udp_out)) return -1;
    memset(out, 0, 48);
    out[0] = 0x60;
    nc_put16(out + 4, udp_len);
    out[6] = 17;
    out[7] = 64;
    memcpy(out + 8, srcb, 16);
    memcpy(out + 24, dstb, 16);
    u = out + 40;
    pseudo = nc_sum16(out + 8, 32, 0) + 17u + udp_len;
    total = 40u + udp_len;
  } else {
    return -1;
  }
  nc_put16(u + 0, s->dst_port);
  nc_put16(u + 2, s->src_port);
  nc_put16(u + 4, udp_len);
  u[6] = u[7] = 0;
  if (len) memcpy(u + 8, data, len);
  uint16_t ucs = (uint16_t)~nc_fold(nc_sum16(u, udp_len, pseudo));
  if (ucs == 0) ucs = 0xffff; /* 0 means "no checksum" (and is illegal for IPv6) */
  nc_put16(u + 6, ucs);
  if (g_cbs.output) g_cbs.output(g_ctx, out, total);
  g_stats.out_pkts++;
  g_stats.out_udp++;
  s->last_used = sys_now();
  return 0;
}

void nc_udp_close(uint32_t session) {
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    nc_udp_session *s = &g_udp[i];
    if (s->used && s->id == session) {
      udp_remove(s->pcb);
      memset(s, 0, sizeof(*s));
      return;
    }
  }
}

/* fix/nc-tcp0: called from the patched ip6_input_accept (core/ip6.c) — the IPv6 twin of nc_lwip_dest_ours. */
int nc_lwip_dest_ours6(const ip6_addr_t *dest) {
  ip_addr_t d;
  if (g_input_l4_ours) return 1;
  ip_addr_copy_from_ip6(d, *dest);
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    if (g_udp[i].used && nc_ip_equal(&g_udp[i].dst, &d)) return 1;
  }
  for (int i = 0; i < NC_MAX_TCP_CONNS; i++) {
    if (g_conns[i].used && g_conns[i].pcb && nc_ip_equal(&g_conns[i].pcb->local_ip, &d)) return 1;
  }
  return 0;
}

/* Called from the patched ip4_input_accept (core/ip4.c): is this destination
   one we terminate (listener, UDP session, or live connection)? */
int nc_lwip_dest_ours(const ip4_addr_t *dest) {
  ip_addr_t d;
  if (g_input_l4_ours) return 1;
  ip_addr_copy_from_ip4(d, *dest);
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    if (g_udp[i].used && nc_ip_equal(&g_udp[i].dst, &d)) return 1;
  }
  for (int i = 0; i < NC_MAX_TCP_CONNS; i++) {
    if (g_conns[i].used && g_conns[i].pcb && nc_ip_equal(&g_conns[i].pcb->local_ip, &d)) return 1;
  }
  return 0;
}
