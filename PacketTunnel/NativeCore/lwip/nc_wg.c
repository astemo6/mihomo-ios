/* nc_wg: WireGuard netifs + client PCBs over the shared lwIP instance.
   feat/nc-wg, based on astemo6/Muse NativeCore — see nc_wg.h and
   docs/nc-proto-wireguard-tuic-udp.md §2 (option a: second netif). */
#include "nc_wg.h"

#include <string.h>
#include <stdlib.h>

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/timeouts.h"

/* nc_stack.c: lwip_init() exactly once per process (TUN restarts and WG
   devices share the instance). */
extern void nc_lwip_ensure_init(void);

#define NC_WG_MAX_DEVS 8
#define NC_WG_MAX_TCP 96
#define NC_WG_MAX_UDP 48
#define NC_WG_MTU_MIN 576
#define NC_WG_MTU_MAX 4000

typedef struct {
  int used;
  struct netif netif;
  int has4;
  int has6;
  ip_addr_t addr4;
  ip_addr_t addr6;
} nc_wg_dev;

typedef struct {
  int used;
  uint32_t id;
  int32_t dev;
  struct tcp_pcb *pcb;
  int connected;
} nc_wg_tcp;

typedef struct {
  int used;
  uint32_t id;
  int32_t dev;
  struct udp_pcb *pcb;
} nc_wg_udp;

static nc_wg_callbacks g_wcbs;
static void *g_wctx;
static nc_wg_dev g_devs[NC_WG_MAX_DEVS];
static nc_wg_tcp g_wtcp[NC_WG_MAX_TCP];
static nc_wg_udp g_wudp[NC_WG_MAX_UDP];
static uint32_t g_next_id = 1;
static uint8_t g_wg_out[NC_WG_MTU_MAX + 96];

static uint32_t nc_wg_new_id(void) {
  uint32_t id = g_next_id++;
  if (g_next_id == 0) g_next_id = 1;
  return id;
}

static nc_wg_dev *nc_wg_dev_get(int32_t dev) {
  if (dev < 1 || dev > NC_WG_MAX_DEVS) return NULL;
  nc_wg_dev *d = &g_devs[dev - 1];
  return d->used ? d : NULL;
}

static void nc_wg_bytes_to_ip(const uint8_t b[16], int is6, ip_addr_t *out) {
  if (is6) {
    IP_ADDR6(out, lwip_htonl(((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3]),
             lwip_htonl(((uint32_t)b[4] << 24) | ((uint32_t)b[5] << 16) | ((uint32_t)b[6] << 8) | b[7]),
             lwip_htonl(((uint32_t)b[8] << 24) | ((uint32_t)b[9] << 16) | ((uint32_t)b[10] << 8) | b[11]),
             lwip_htonl(((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16) | ((uint32_t)b[14] << 8) | b[15]));
  } else {
    IP_ADDR4(out, b[0], b[1], b[2], b[3]);
  }
}

static void nc_wg_ip_to_bytes(const ip_addr_t *ip, uint8_t out[16], int *is6) {
  memset(out, 0, 16);
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
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
  }
}

/* ------------------------------------------------------------ netif glue */

static void nc_wg_emit(struct netif *netif, struct pbuf *p) {
  nc_wg_dev *d = (nc_wg_dev *)netif->state;
  if (!d || !g_wcbs.output || p->tot_len == 0) return;
  int32_t dev = (int32_t)(d - g_devs) + 1;
  if (p->tot_len <= sizeof(g_wg_out)) {
    u16_t n = pbuf_copy_partial(p, g_wg_out, p->tot_len, 0);
    g_wcbs.output(g_wctx, dev, g_wg_out, n);
  }
}

static err_t nc_wg_netif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
  (void)ipaddr;
  nc_wg_emit(netif, p);
  return ERR_OK;
}

#if LWIP_IPV6
static err_t nc_wg_netif_output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
  (void)ipaddr;
  nc_wg_emit(netif, p);
  return ERR_OK;
}
#endif

static err_t nc_wg_netif_init(struct netif *netif) {
  /* "wg": ip4.c's NC PATCH (accept any destination) applies to the TUN netif ("tn") only. */
  netif->name[0] = 'w';
  netif->name[1] = 'g';
  netif->output = nc_wg_netif_output;
#if LWIP_IPV6
  netif->output_ip6 = nc_wg_netif_output6;
#endif
  netif->mtu = 1408;
  netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
  return ERR_OK;
}

void nc_wg_set_callbacks(const nc_wg_callbacks *cbs, void *ctx) {
  if (cbs) g_wcbs = *cbs;
  else memset(&g_wcbs, 0, sizeof(g_wcbs));
  g_wctx = ctx;
}

int32_t nc_wg_dev_add(const char *ip4, const char *ip6, uint16_t mtu) {
  nc_lwip_ensure_init();
  int idx = -1;
  for (int i = 0; i < NC_WG_MAX_DEVS; i++) {
    if (!g_devs[i].used) { idx = i; break; }
  }
  if (idx < 0) return 0;
  nc_wg_dev *d = &g_devs[idx];
  memset(d, 0, sizeof(*d));
  ip4_addr_t a4, mask, gw;
  ip4_addr_set_zero(&a4);
  ip4_addr_set_zero(&gw);
  IP4_ADDR(&mask, 255, 255, 255, 255);
  if (ip4 && ip4[0]) {
    if (!ip4addr_aton(ip4, &a4)) return 0;
    d->has4 = 1;
    ip_addr_copy_from_ip4(d->addr4, a4);
  }
#if LWIP_IPV6
  ip6_addr_t a6;
  if (ip6 && ip6[0]) {
    if (!ip6addr_aton(ip6, &a6)) return 0;
    d->has6 = 1;
  }
#else
  (void)ip6;
#endif
  if (!d->has4 && !d->has6) return 0;
  if (!netif_add(&d->netif, &a4, &mask, &gw, d, nc_wg_netif_init, ip_input)) return 0;
  uint16_t m = mtu ? mtu : 1408;
  if (m < NC_WG_MTU_MIN) m = NC_WG_MTU_MIN;
  if (m > NC_WG_MTU_MAX) m = NC_WG_MTU_MAX;
  d->netif.mtu = m;
#if LWIP_IPV6
#if LWIP_ND6_ALLOW_RA_UPDATES
  d->netif.mtu6 = m;
#endif
  if (d->has6) {
    s8_t chosen = -1;
    if (netif_add_ip6_address(&d->netif, &a6, &chosen) != ERR_OK || chosen < 0) {
      netif_remove(&d->netif);
      return 0;
    }
    netif_ip6_addr_set_state(&d->netif, chosen, IP6_ADDR_PREFERRED);
    ip_addr_copy_from_ip6(d->addr6, *netif_ip6_addr(&d->netif, chosen));
  }
#endif
  /* Never the default netif: the TUN stays default for its own (unbound) PCBs. */
  netif_set_up(&d->netif);
  netif_set_link_up(&d->netif);
  d->used = 1;
  return (int32_t)idx + 1;
}

static void nc_wg_tcp_detach(nc_wg_tcp *c, int abort_pcb) {
  struct tcp_pcb *pcb = c->pcb;
  memset(c, 0, sizeof(*c));
  if (!pcb) return;
  tcp_arg(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_sent(pcb, NULL);
  tcp_err(pcb, NULL);
  if (abort_pcb || tcp_close(pcb) != ERR_OK) tcp_abort(pcb);
}

void nc_wg_dev_remove(int32_t dev) {
  nc_wg_dev *d = nc_wg_dev_get(dev);
  if (!d) return;
  for (int i = 0; i < NC_WG_MAX_TCP; i++) {
    if (g_wtcp[i].used && g_wtcp[i].dev == dev) {
      uint32_t id = g_wtcp[i].id;
      nc_wg_tcp_detach(&g_wtcp[i], 1);
      if (g_wcbs.tcp_err) g_wcbs.tcp_err(g_wctx, id, (int32_t)ERR_ABRT);
    }
  }
  for (int i = 0; i < NC_WG_MAX_UDP; i++) {
    if (g_wudp[i].used && g_wudp[i].dev == dev) {
      if (g_wudp[i].pcb) udp_remove(g_wudp[i].pcb);
      memset(&g_wudp[i], 0, sizeof(g_wudp[i]));
    }
  }
  netif_remove(&d->netif);
  memset(d, 0, sizeof(*d));
}

void nc_wg_input(int32_t dev, const uint8_t *pkt, uint32_t len) {
  nc_wg_dev *d = nc_wg_dev_get(dev);
  if (!d || len == 0 || len > 0xffff) return;
  struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
  if (!p) return;
  pbuf_take(p, pkt, (u16_t)len);
  if (d->netif.input(p, &d->netif) != ERR_OK) pbuf_free(p);
}

void nc_wg_poll(void) {
  for (int i = 0; i < NC_WG_MAX_DEVS; i++) {
    if (g_devs[i].used) {
      sys_check_timeouts();
      return;
    }
  }
}

/* ------------------------------------------------------------------- TCP */

static nc_wg_tcp *nc_wg_tcp_get(uint32_t id) {
  if (id == 0) return NULL;
  for (int i = 0; i < NC_WG_MAX_TCP; i++) {
    if (g_wtcp[i].used && g_wtcp[i].id == id) return &g_wtcp[i];
  }
  return NULL;
}

static void nc_wg_tcp_err_cb(void *arg, err_t err) {
  nc_wg_tcp *c = (nc_wg_tcp *)arg;
  if (!c || !c->used) return;
  uint32_t id = c->id;
  memset(c, 0, sizeof(*c)); /* lwIP already freed the pcb */
  if (g_wcbs.tcp_err) g_wcbs.tcp_err(g_wctx, id, (int32_t)err);
}

static err_t nc_wg_tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
  (void)pcb;
  nc_wg_tcp *c = (nc_wg_tcp *)arg;
  if (!c || !c->used) {
    if (p) pbuf_free(p);
    return ERR_OK;
  }
  if (err != ERR_OK) {
    if (p) pbuf_free(p);
    return ERR_OK;
  }
  uint32_t id = c->id;
  if (p == NULL) {
    if (g_wcbs.tcp_recv) g_wcbs.tcp_recv(g_wctx, id, NULL, 0);
    return ERR_OK;
  }
  /* One callback per pbuf segment, no copy here (Swift copies). The window
     reopens only when Swift calls nc_wg_tcp_recved — that is the backpressure. */
  for (struct pbuf *q = p; q != NULL; q = q->next) {
    if (q->len && g_wcbs.tcp_recv) g_wcbs.tcp_recv(g_wctx, id, (const uint8_t *)q->payload, q->len);
  }
  pbuf_free(p);
  return ERR_OK;
}

static err_t nc_wg_tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len) {
  (void)pcb;
  nc_wg_tcp *c = (nc_wg_tcp *)arg;
  if (c && c->used && g_wcbs.tcp_sent) g_wcbs.tcp_sent(g_wctx, c->id, len);
  return ERR_OK;
}

static err_t nc_wg_tcp_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err) {
  nc_wg_tcp *c = (nc_wg_tcp *)arg;
  if (!c || !c->used) return ERR_OK;
  c->connected = 1;
  /* fix/nc-masque-ip: tcp_in.c re-derives the send MSS from ip_route() (the TUN netif), not the netif this PCB is
   * bound to, so segments could exceed the device MTU (seen: 1280-byte packets on a 1193-MTU MASQUE CONNECT-IP netif,
   * whose QUIC datagrams Network.framework may drop silently). Clamp to the bound device's MTU. */
  nc_wg_dev *d = nc_wg_dev_get(c->dev);
  if (pcb && d) {
    u16_t hdr = IP_IS_V6(&pcb->remote_ip) ? 60 : 40;
    u16_t m = d->netif.mtu; /* mtu6 == mtu for these devices (nc_wg_dev_add) */
    if (m > hdr + 536 && pcb->mss > (u16_t)(m - hdr)) pcb->mss = (u16_t)(m - hdr);
  }
  if (g_wcbs.tcp_connected) g_wcbs.tcp_connected(g_wctx, c->id, (int32_t)err);
  return ERR_OK;
}

uint32_t nc_wg_tcp_connect(int32_t dev, const uint8_t ip[16], int32_t is6, uint16_t port) {
  nc_wg_dev *d = nc_wg_dev_get(dev);
  if (!d || !ip) return 0;
  if (is6 ? !d->has6 : !d->has4) return 0;
  nc_wg_tcp *slot = NULL;
  for (int i = 0; i < NC_WG_MAX_TCP; i++) {
    if (!g_wtcp[i].used) { slot = &g_wtcp[i]; break; }
  }
  if (!slot) return 0;
  ip_addr_t dst;
  nc_wg_bytes_to_ip(ip, is6, &dst);
  struct tcp_pcb *pcb = tcp_new_ip_type(is6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
  if (!pcb) return 0;
  tcp_bind_netif(pcb, &d->netif);
  if (tcp_bind(pcb, is6 ? &d->addr6 : &d->addr4, 0) != ERR_OK) {
    tcp_abort(pcb);
    return 0;
  }
  memset(slot, 0, sizeof(*slot));
  slot->used = 1;
  slot->id = nc_wg_new_id();
  slot->dev = dev;
  slot->pcb = pcb;
  tcp_arg(pcb, slot);
  tcp_recv(pcb, nc_wg_tcp_recv_cb);
  tcp_sent(pcb, nc_wg_tcp_sent_cb);
  tcp_err(pcb, nc_wg_tcp_err_cb);
  tcp_nagle_disable(pcb);
  if (tcp_connect(pcb, &dst, port, nc_wg_tcp_connected_cb) != ERR_OK) {
    nc_wg_tcp_detach(slot, 1);
    return 0;
  }
  return slot->id;
}

int32_t nc_wg_tcp_write(uint32_t conn, const uint8_t *data, uint32_t len) {
  nc_wg_tcp *c = nc_wg_tcp_get(conn);
  if (!c || !c->pcb) return -1;
  if (!c->connected) return 0;
  uint32_t room = tcp_sndbuf(c->pcb);
  if (room > len) room = len;
  uint32_t off = 0;
  while (off < room) {
    u16_t chunk = (u16_t)((room - off) > 0xffff ? 0xffff : (room - off));
    if (tcp_sndqueuelen(c->pcb) >= TCP_SND_QUEUELEN) break;
    err_t e = tcp_write(c->pcb, data + off, chunk, TCP_WRITE_FLAG_COPY);
    if (e != ERR_OK) break;
    off += chunk;
  }
  if (off > 0) tcp_output(c->pcb);
  return (int32_t)off;
}

void nc_wg_tcp_recved(uint32_t conn, uint32_t len) {
  nc_wg_tcp *c = nc_wg_tcp_get(conn);
  if (!c || !c->pcb) return;
  while (len > 0) {
    u16_t n = (u16_t)(len > 0xffff ? 0xffff : len);
    tcp_recved(c->pcb, n);
    len -= n;
  }
}

void nc_wg_tcp_close(uint32_t conn) {
  nc_wg_tcp *c = nc_wg_tcp_get(conn);
  if (c) nc_wg_tcp_detach(c, 0);
}

void nc_wg_tcp_abort(uint32_t conn) {
  nc_wg_tcp *c = nc_wg_tcp_get(conn);
  if (c) nc_wg_tcp_detach(c, 1);
}

/* ------------------------------------------------------------------- UDP */

static nc_wg_udp *nc_wg_udp_get(uint32_t id) {
  if (id == 0) return NULL;
  for (int i = 0; i < NC_WG_MAX_UDP; i++) {
    if (g_wudp[i].used && g_wudp[i].id == id) return &g_wudp[i];
  }
  return NULL;
}

static uint8_t g_wg_udp_in[NC_WG_MTU_MAX + 96];

static void nc_wg_udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
  (void)pcb;
  nc_wg_udp *s = (nc_wg_udp *)arg;
  if (!p) return;
  if (!s || !s->used || p->tot_len > sizeof(g_wg_udp_in)) {
    pbuf_free(p);
    return;
  }
  uint32_t id = s->id;
  u16_t n = pbuf_copy_partial(p, g_wg_udp_in, p->tot_len, 0);
  pbuf_free(p);
  uint8_t src[16];
  int is6 = 0;
  nc_wg_ip_to_bytes(addr, src, &is6);
  if (g_wcbs.udp_recv) g_wcbs.udp_recv(g_wctx, id, src, port, is6, g_wg_udp_in, n);
}

uint32_t nc_wg_udp_open(int32_t dev, int32_t is6) {
  nc_wg_dev *d = nc_wg_dev_get(dev);
  if (!d) return 0;
  if (is6 ? !d->has6 : !d->has4) return 0;
  nc_wg_udp *slot = NULL;
  for (int i = 0; i < NC_WG_MAX_UDP; i++) {
    if (!g_wudp[i].used) { slot = &g_wudp[i]; break; }
  }
  if (!slot) return 0;
  struct udp_pcb *pcb = udp_new_ip_type(is6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
  if (!pcb) return 0;
  udp_bind_netif(pcb, &d->netif);
  if (udp_bind(pcb, is6 ? &d->addr6 : &d->addr4, 0) != ERR_OK) {
    udp_remove(pcb);
    return 0;
  }
  memset(slot, 0, sizeof(*slot));
  slot->used = 1;
  slot->id = nc_wg_new_id();
  slot->dev = dev;
  slot->pcb = pcb;
  udp_recv(pcb, nc_wg_udp_recv_cb, slot);
  return slot->id;
}

int32_t nc_wg_udp_send(uint32_t sock, const uint8_t ip[16], int32_t is6, uint16_t port,
                       const uint8_t *data, uint32_t len) {
  nc_wg_udp *s = nc_wg_udp_get(sock);
  if (!s || !s->pcb || !ip || len > 0xffff - 48) return -1;
  ip_addr_t dst;
  nc_wg_bytes_to_ip(ip, is6, &dst);
  struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
  if (!p) return -1;
  if (len) pbuf_take(p, data, (u16_t)len);
  err_t e = udp_sendto(s->pcb, p, &dst, port);
  pbuf_free(p);
  return e == ERR_OK ? 0 : -1;
}

void nc_wg_udp_close(uint32_t sock) {
  nc_wg_udp *s = nc_wg_udp_get(sock);
  if (!s) return;
  if (s->pcb) udp_remove(s->pcb);
  memset(s, 0, sizeof(*s));
}
