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

/* Abort every PCB not bound to a netif (= every TUN-side PCB; WireGuard client PCBs are netif-bound),
   including ones still closing / in TIME-WAIT after we dropped them. */
static void nc_purge_unbound(struct tcp_pcb **list) {
  for (;;) {
    struct tcp_pcb *p = *list;
    while (p && p->netif_idx != NETIF_NO_INDEX) p = p->next;
    if (!p) return;
    tcp_arg(p, NULL);
    tcp_recv(p, NULL);
    tcp_sent(p, NULL);
    tcp_err(p, NULL);
    tcp_abort(p);
  }
}

u32_t sys_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (u32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}

/* ------------------------------------------------------------------ state */

#define NC_MAX_LISTENERS 48
#define NC_MAX_UDP_SESSIONS 64
#define NC_MAX_TCP_CONNS 96
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
  if (g_cbs.output) g_cbs.output(g_ctx, g_scratch, n);
  return ERR_OK;
}

#if LWIP_IPV6
static err_t nc_netif_output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
  (void)netif;
  (void)ipaddr;
  if (p->tot_len == 0 || p->tot_len > sizeof(g_scratch)) return ERR_OK;
  u16_t n = pbuf_copy_partial(p, g_scratch, p->tot_len, 0);
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
  (void)arg;
  (void)pcb;
  (void)len;
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
  }
  tcp_recved(pcb, total);
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
  if (g_cbs.tcp_accept) {
    keep = g_cbs.tcp_accept(g_ctx, slot, dstb, newpcb->local_port, srcb, newpcb->remote_port, d6);
  }
  if (!keep) {
    tcp_abort(newpcb);
    nc_conn_free_slot(slot);
    return ERR_ABRT;
  }
  return ERR_OK;
}

static nc_listener *nc_ensure_listener(const ip_addr_t *dst, u16_t port) {
  int free_idx = -1, lru_idx = -1;
  u32_t lru_time = 0xffffffffu;
  for (int i = 0; i < NC_MAX_LISTENERS; i++) {
    nc_listener *l = &g_listeners[i];
    if (!l->used) {
      if (free_idx < 0) free_idx = i;
      continue;
    }
    if (l->port == port && nc_ip_equal(&l->dst, dst)) {
      l->last_used = sys_now();
      return l;
    }
    if (l->active == 0 && l->last_used < lru_time) {
      lru_time = l->last_used;
      lru_idx = i;
    }
  }
  int idx = free_idx >= 0 ? free_idx : lru_idx;
  if (idx < 0) return NULL;
  nc_listener *l = &g_listeners[idx];
  if (l->used && l->lpcb) {
    tcp_close(l->lpcb);
  }
  memset(l, 0, sizeof(*l));
  struct tcp_pcb *pcb = tcp_new_ip_type(dst->type);
  if (!pcb) return NULL;
  err_t e = tcp_bind(pcb, dst, port);
  if (e != ERR_OK) {
    tcp_abort(pcb);
    return NULL;
  }
  struct tcp_pcb *lpcb = tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG);
  if (!lpcb) return NULL;
  l->used = 1;
  l->dst = *dst;
  l->port = port;
  l->lpcb = lpcb;
  l->last_used = sys_now();
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

static nc_udp_session *nc_ensure_udp_session(const ip_addr_t *src, u16_t src_port,
                                             const ip_addr_t *dst, u16_t dst_port) {
  int free_idx = -1, lru_idx = -1;
  u32_t lru_time = 0xffffffffu;
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
    if (s->last_used < lru_time) {
      lru_time = s->last_used;
      lru_idx = i;
    }
  }
  int idx = free_idx >= 0 ? free_idx : lru_idx;
  if (idx < 0) return NULL;
  nc_udp_session *s = &g_udp[idx];
  if (s->used && s->pcb) udp_remove(s->pcb);
  memset(s, 0, sizeof(*s));
  struct udp_pcb *pcb = udp_new_ip_type(dst->type);
  if (!pcb) return NULL;
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
        nc_ensure_listener(&dst, dport);
      }
    } else if (proto == 17 && len >= ihl + 8) {
      uint16_t sport = (uint16_t)(l4[0] << 8 | l4[1]);
      uint16_t dport = (uint16_t)(l4[2] << 8 | l4[3]);
      nc_ensure_udp_session(&src, sport, &dst, dport);
    }
  } else if (v == 6) {
    if (len < 48) return;
    uint8_t next = pkt[6];
    ip_addr_t src, dst;
    IP_ADDR6(&src, lwip_ntohl(*(uint32_t *)(pkt + 8)), lwip_ntohl(*(uint32_t *)(pkt + 12)),
             lwip_ntohl(*(uint32_t *)(pkt + 16)), lwip_ntohl(*(uint32_t *)(pkt + 20)));
    IP_ADDR6(&dst, lwip_ntohl(*(uint32_t *)(pkt + 24)), lwip_ntohl(*(uint32_t *)(pkt + 28)),
             lwip_ntohl(*(uint32_t *)(pkt + 32)), lwip_ntohl(*(uint32_t *)(pkt + 36)));
    const uint8_t *l4 = pkt + 40;
    if (next == 6 && len >= 60) {
      uint16_t dport = (uint16_t)(l4[2] << 8 | l4[3]);
      uint8_t flags = l4[13];
      if ((flags & 0x02) && !(flags & 0x10)) {
        nc_ensure_listener(&dst, dport);
      }
    } else if (next == 17) {
      uint16_t sport = (uint16_t)(l4[0] << 8 | l4[1]);
      uint16_t dport = (uint16_t)(l4[2] << 8 | l4[3]);
      nc_ensure_udp_session(&src, sport, &dst, dport);
    }
  }
}

/* -------------------------------------------------------------- public API */

int nc_init(const nc_callbacks *cbs, void *ctx, const char *ip4, const char *ip6, uint16_t mtu) {
  if (g_up) nc_shutdown();
  memset(g_listeners, 0, sizeof(g_listeners));
  memset(g_conns, 0, sizeof(g_conns));
  memset(g_udp, 0, sizeof(g_udp));
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
    if (g_listeners[i].used && g_listeners[i].lpcb) tcp_close(g_listeners[i].lpcb);
  }
  for (int i = 0; i < NC_MAX_TCP_CONNS; i++) {
    if (g_conns[i].used && g_conns[i].pcb) tcp_abort(g_conns[i].pcb);
  }
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    if (g_udp[i].used && g_udp[i].pcb) udp_remove(g_udp[i].pcb);
  }
  nc_purge_unbound(&tcp_active_pcbs);
  nc_purge_unbound(&tcp_tw_pcbs);
  netif_remove(&g_netif);
  memset(g_listeners, 0, sizeof(g_listeners));
  memset(g_conns, 0, sizeof(g_conns));
  memset(g_udp, 0, sizeof(g_udp));
  g_up = 0;
}

void nc_input(const uint8_t *pkt, uint32_t len) {
  if (!g_up || len == 0) return;
  nc_peek(pkt, len);
  struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
  if (!p) return;
  pbuf_take(p, pkt, (u16_t)len);
  if (g_netif.input(p, &g_netif) != ERR_OK) {
    pbuf_free(p);
  }
}

void nc_poll(void) {
  if (!g_up) return;
  sys_check_timeouts();
  u32_t now = sys_now();
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    nc_udp_session *s = &g_udp[i];
    if (s->used && now - s->last_used > NC_UDP_IDLE_MS) {
      udp_remove(s->pcb);
      memset(s, 0, sizeof(*s));
    }
  }
  for (int i = 0; i < NC_MAX_LISTENERS; i++) {
    nc_listener *l = &g_listeners[i];
    if (l->used && l->active == 0 && now - l->last_used > NC_LISTENER_IDLE_MS) {
      tcp_close(l->lpcb);
      memset(l, 0, sizeof(*l));
    }
  }
}

int nc_tcp_write(void *conn, const uint8_t *data, uint32_t len) {
  nc_conn *c = (nc_conn *)conn;
  if (!c || !c->used || !c->pcb) return -1;
  u32_t off = 0;
  while (off < len) {
    u16_t chunk = (u16_t)((len - off) > 0xffff ? 0xffff : (len - off));
    err_t e = tcp_write(c->pcb, data + off, chunk, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK) break;
    off += chunk;
  }
  if (off > 0) tcp_output(c->pcb);
  return (int)off;
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

int nc_udp_send(uint32_t session, const uint8_t *data, uint32_t len) {
  nc_udp_session *s = NULL;
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    if (g_udp[i].used && g_udp[i].id == session) { s = &g_udp[i]; break; }
  }
  if (!s) return -1;
  if (len > 65507) return -1;
  struct pbuf *pb = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
  if (!pb) return -1;
  if (len) pbuf_take(pb, data, (u16_t)len);

  uint8_t srcb[16], dstb[16];
  int src6 = 0, dst6 = 0;
  nc_ip_to_bytes(&s->dst, srcb, &src6); /* reply source = original destination */
  nc_ip_to_bytes(&s->src, dstb, &dst6); /* reply target = the app endpoint */

  uint8_t *out = g_udp_out;
  uint32_t total;
  if (!src6 && !dst6) {
    uint16_t udp_len = (uint16_t)(8 + len);
    uint16_t total_len = (uint16_t)(20 + udp_len);
    memset(out, 0, 28);
    out[0] = 0x45;
    out[2] = (uint8_t)(total_len >> 8);
    out[3] = (uint8_t)(total_len & 0xff);
    uint16_t id = g_ip_id++;
    out[4] = (uint8_t)(id >> 8);
    out[5] = (uint8_t)(id & 0xff);
    out[6] = 0x40; /* DF */
    out[8] = 64;
    out[9] = 17;
    memcpy(out + 12, srcb, 4);
    memcpy(out + 16, dstb, 4);
    uint8_t *u = out + 20;
    u[0] = (uint8_t)(s->dst_port >> 8);
    u[1] = (uint8_t)(s->dst_port & 0xff);
    u[2] = (uint8_t)(s->src_port >> 8);
    u[3] = (uint8_t)(s->src_port & 0xff);
    u[4] = (uint8_t)(udp_len >> 8);
    u[5] = (uint8_t)(udp_len & 0xff);
    uint16_t ucs = inet_chksum_pseudo(pb, IP_PROTO_UDP, (u16_t)udp_len,
                                      (const ip4_addr_t *)(out + 12), (const ip4_addr_t *)(out + 16));
    u[6] = (uint8_t)(ucs >> 8);
    u[7] = (uint8_t)(ucs & 0xff);
    /* IP header checksum over the finished header */
    uint16_t ics = inet_chksum(out, 20);
    out[10] = (uint8_t)(ics >> 8);
    out[11] = (uint8_t)(ics & 0xff);
    memcpy(out + 28, data, len);
    total = total_len;
  } else if (src6 && dst6) {
    uint16_t udp_len = (uint16_t)(8 + len);
    memset(out, 0, 48);
    out[0] = 0x60;
    out[4] = (uint8_t)(udp_len >> 8);
    out[5] = (uint8_t)(udp_len & 0xff);
    out[6] = 17;
    out[7] = 64;
    memcpy(out + 8, srcb, 16);
    memcpy(out + 24, dstb, 16);
    uint8_t *u = out + 40;
    u[0] = (uint8_t)(s->dst_port >> 8);
    u[1] = (uint8_t)(s->dst_port & 0xff);
    u[2] = (uint8_t)(s->src_port >> 8);
    u[3] = (uint8_t)(s->src_port & 0xff);
    u[4] = (uint8_t)(udp_len >> 8);
    u[5] = (uint8_t)(udp_len & 0xff);
    ip_addr_t sa, da;
    IP_ADDR6(&sa, lwip_htonl(((uint32_t)srcb[0] << 24) | ((uint32_t)srcb[1] << 16) | ((uint32_t)srcb[2] << 8) | srcb[3]),
             lwip_htonl(((uint32_t)srcb[4] << 24) | ((uint32_t)srcb[5] << 16) | ((uint32_t)srcb[6] << 8) | srcb[7]),
             lwip_htonl(((uint32_t)srcb[8] << 24) | ((uint32_t)srcb[9] << 16) | ((uint32_t)srcb[10] << 8) | srcb[11]),
             lwip_htonl(((uint32_t)srcb[12] << 24) | ((uint32_t)srcb[13] << 16) | ((uint32_t)srcb[14] << 8) | srcb[15]));
    IP_ADDR6(&da, lwip_htonl(((uint32_t)dstb[0] << 24) | ((uint32_t)dstb[1] << 16) | ((uint32_t)dstb[2] << 8) | dstb[3]),
             lwip_htonl(((uint32_t)dstb[4] << 24) | ((uint32_t)dstb[5] << 16) | ((uint32_t)dstb[6] << 8) | dstb[7]),
             lwip_htonl(((uint32_t)dstb[8] << 24) | ((uint32_t)dstb[9] << 16) | ((uint32_t)dstb[10] << 8) | dstb[11]),
             lwip_htonl(((uint32_t)dstb[12] << 24) | ((uint32_t)dstb[13] << 16) | ((uint32_t)dstb[14] << 8) | dstb[15]));
    uint16_t ucs = ip6_chksum_pseudo(pb, IP_PROTO_UDP, (u16_t)udp_len, ip_2_ip6(&sa), ip_2_ip6(&da));
    u[6] = (uint8_t)(ucs >> 8);
    u[7] = (uint8_t)(ucs & 0xff);
    memcpy(out + 48, data, len);
    total = 40 + udp_len;
  } else {
    pbuf_free(pb);
    return -1;
  }
  pbuf_free(pb);
  if (g_cbs.output) g_cbs.output(g_ctx, out, total);
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

/* Called from the patched ip4_input_accept (core/ip4.c): is this destination
   one we terminate (listener, UDP session, or live connection)? */
int nc_lwip_dest_ours(const ip4_addr_t *dest) {
  ip_addr_t d;
  ip_addr_copy_from_ip4(d, *dest);
  for (int i = 0; i < NC_MAX_LISTENERS; i++) {
    if (g_listeners[i].used && nc_ip_equal(&g_listeners[i].dst, &d)) return 1;
  }
  for (int i = 0; i < NC_MAX_UDP_SESSIONS; i++) {
    if (g_udp[i].used && nc_ip_equal(&g_udp[i].dst, &d)) return 1;
  }
  for (int i = 0; i < NC_MAX_TCP_CONNS; i++) {
    if (g_conns[i].used && g_conns[i].pcb && nc_ip_equal(&g_conns[i].pcb->local_ip, &d)) return 1;
  }
  return 0;
}
