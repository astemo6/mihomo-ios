/* fix/nc-tcp1: many-flow / long-duration soak of the TUN bridge (nc_stack.c + vendored lwIP), run by Checks → nc-stack-c.
   build433 on device: the first ~24 distinct destinations were accepted, then nearly every SYN was counted
   "listen fail" + "not-ours" and silently dropped (data plane dead after ~60 s). This drives a simulated clock
   through ≥7 minutes of app-like traffic and fails on any SYN that is not accepted:
     - ≥800 TCP flows, v4 + v6, hundreds of distinct real (redir-host style) destination IPs, varied ports;
     - short flows closed by the stack first (→ lwIP TIME_WAIT, 2×MSL) and by the app first, plus long-lived ones
       with periodic traffic that outlive listener idle expiry;
     - a UDP DNS query (new source port each) before every flow, v4 + v6, every one answered;
     - a quiet gap long enough for TIME_WAIT and listener idle expiry, then a second burst to the same ports;
   and asserts accepted == SYN count (no retransmit ever needed), not-ours == 0, listen fail == 0, every flow and
   DNS query completed, no TCP PCB leaked. The client side is a minimal TCP state machine; engine callbacks act
   like NCDataPlane (echo relay, acknowledge with nc_tcp_recved, close on FIN). */
#include "nc_stack.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"

void nc_test_set_now(uint32_t ms);

enum { K_SERVER_CLOSE, K_CLIENT_CLOSE, K_LONG };
enum { S_IDLE, S_SYN, S_EST, S_DONE, S_FAIL };
#define MAXF 2000
typedef struct {
  int used, is6, kind, state;
  uint8_t dst[16];
  uint16_t sport, dport;
  uint32_t snd_nxt, rcv_nxt, srv_isn;
  uint32_t start_ms, syn_at, next_ping, close_at;
  int syn_tx, req_bytes, echoed, pings_left;
  int client_fin_sent, client_fin_acked, server_fin;
  uint32_t fin_seq;
  void *conn;
  int engine_closed;
  /* DNS before the flow */
  uint16_t dns_port; int dns_sent, dns_ok;
} flow;
static flow F[MAXF];
static int nflows;
static flow *by_port[65536];
static flow *dns_by_port[65536];
static uint32_t now_ms;
static int count_list(struct tcp_pcb *p) { int n = 0; for (; p; p = p->next) n++; return n; }

/* ---------------- packet builders / queue */
static uint16_t csum(const uint8_t *b, int n, uint32_t s) { for (int i = 0; i + 1 < n; i += 2) s += (b[i] << 8) | b[i + 1]; if (n & 1) s += b[n - 1] << 8; while (s >> 16) s = (s & 0xffff) + (s >> 16); return (uint16_t)~s; }
static uint32_t psum(const uint8_t *a, int alen, const uint8_t *b, int proto, int len) { uint32_t x = 0; for (int i = 0; i < alen; i += 2) x += (a[i] << 8 | a[i + 1]) + (b[i] << 8 | b[i + 1]); return x + proto + len; }
static const uint8_t SRC4[4] = {198, 18, 0, 1}, DNS4[4] = {198, 18, 0, 2};
static const uint8_t SRC6[16] = {0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t DNS6[16] = {0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

typedef struct { uint8_t b[1600]; uint32_t n; } pkt;
#define QMAX 8192
static pkt Q[QMAX]; static int qh, qt;
static void qpush(const uint8_t *b, uint32_t n) { if ((qt + 1) % QMAX == qh) { printf("FAIL: client queue overflow\n"); exit(20); } memcpy(Q[qt].b, b, n); Q[qt].n = n; qt = (qt + 1) % QMAX; }

static void build(int is6, const uint8_t *src, const uint8_t *dst, int proto, const uint8_t *l4, int l4n) {
  uint8_t p[1600];
  if (!is6) {
    memset(p, 0, 20); p[0] = 0x45; int tl = 20 + l4n; p[2] = tl >> 8; p[3] = tl; p[6] = 0x40; p[8] = 64; p[9] = proto;
    memcpy(p + 12, src, 4); memcpy(p + 16, dst, 4); uint16_t c = csum(p, 20, 0); p[10] = c >> 8; p[11] = c;
    memcpy(p + 20, l4, l4n); int off = proto == 6 ? 16 : 6; p[20 + off] = p[21 + off] = 0;
    c = csum(p + 20, l4n, psum(src, 4, dst, proto, l4n)); p[20 + off] = c >> 8; p[21 + off] = c; qpush(p, tl);
  } else {
    memset(p, 0, 40); p[0] = 0x60; p[4] = l4n >> 8; p[5] = l4n; p[6] = proto; p[7] = 64; memcpy(p + 8, src, 16); memcpy(p + 24, dst, 16);
    memcpy(p + 40, l4, l4n); int off = proto == 6 ? 16 : 6; p[40 + off] = p[41 + off] = 0;
    uint16_t c = csum(p + 40, l4n, psum(src, 16, dst, proto, l4n)); p[40 + off] = c >> 8; p[41 + off] = c; qpush(p, 40 + l4n);
  }
}
static void tcp_send(flow *f, uint8_t flags, int datalen, int syn) {
  uint8_t t[1500]; int hl = syn ? 24 : 20; memset(t, 0, hl + datalen);
  t[0] = f->sport >> 8; t[1] = f->sport; t[2] = f->dport >> 8; t[3] = f->dport;
  uint32_t seq = f->snd_nxt, ack = (flags & 0x10) ? f->rcv_nxt : 0;
  t[4] = seq >> 24; t[5] = seq >> 16; t[6] = seq >> 8; t[7] = seq; t[8] = ack >> 24; t[9] = ack >> 16; t[10] = ack >> 8; t[11] = ack;
  t[12] = (hl / 4) << 4; t[13] = flags; t[14] = 0xff; t[15] = 0xff;
  if (syn) { t[20] = 2; t[21] = 4; t[22] = 0x05; t[23] = 0xb4; } /* MSS 1460 */
  for (int i = 0; i < datalen; i++) t[hl + i] = (uint8_t)('a' + i % 26);
  build(f->is6, f->is6 ? SRC6 : SRC4, f->dst, 6, t, hl + datalen);
}
static void dns_send(flow *f) {
  uint8_t u[8 + 30]; memset(u, 0, sizeof(u));
  u[0] = f->dns_port >> 8; u[1] = f->dns_port; u[3] = 53; u[5] = sizeof(u);
  for (int i = 8; i < (int)sizeof(u); i++) u[i] = (uint8_t)i;
  build(f->is6, f->is6 ? SRC6 : SRC4, f->is6 ? DNS6 : DNS4, 17, u, sizeof(u));
  f->dns_sent = 1;
}

/* ---------------- engine side (NCDataPlane-like) */
typedef struct { int op; void *conn; uint32_t sess, n; } act; /* 1 recved+echo, 2 close, 3 udp reply */
static act A[QMAX]; static int ah, at;
static void apush(int op, void *conn, uint32_t sess, uint32_t n) { if ((at + 1) % QMAX == ah) { printf("FAIL: engine queue overflow\n"); exit(21); } A[at].op = op; A[at].conn = conn; A[at].sess = sess; A[at].n = n; at = (at + 1) % QMAX; }
static flow *flow_of_conn(void *conn) { for (int i = 0; i < nflows; i++) if (F[i].conn == conn) return &F[i]; return NULL; }

static int cb_accept(void *c, void *conn, const uint8_t d[16], uint16_t dp, const uint8_t s[16], uint16_t sp, int is6) {
  flow *f = by_port[sp];
  if (!f || f->is6 != is6 || f->dport != dp || memcmp(d, f->dst, is6 ? 16 : 4) != 0) { printf("FAIL: accept for unknown flow sport %u dport %u\n", sp, dp); exit(22); }
  f->conn = conn;
  return 1;
}
static void cb_recv(void *c, void *conn, const uint8_t *d, uint32_t n) {
  if (d) apush(1, conn, 0, n); else apush(2, conn, 0, 0);
}
static void cb_err(void *c, void *conn, int e) {
  flow *f = flow_of_conn(conn);
  if (f) { f->conn = NULL; f->engine_closed = 1; if (f->state != S_DONE) { printf("FAIL: tcp err %d on flow sport %u (state %d)\n", e, f->sport, f->state); f->state = S_FAIL; } }
}
static void cb_udp(void *c, uint32_t s, const uint8_t si[16], uint16_t sp, const uint8_t di[16], uint16_t dp, int is6, const uint8_t *d, uint32_t n) { apush(3, NULL, s, n); }

/* ---------------- client side: parse what the stack emits */
static uint32_t rd32(const uint8_t *b) { return (uint32_t)b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]; }
static int rst_seen, bad_csum;
static void cb_out(void *c, const uint8_t *p, uint32_t n) {
  int v = p[0] >> 4, proto, hl;
  if (v == 4) { hl = (p[0] & 15) * 4; proto = p[9]; if (csum(p, hl, 0) != 0) bad_csum++; }
  else { hl = 40; proto = p[6]; }
  const uint8_t *l4 = p + hl; int l4n = (int)n - hl;
  if (csum(l4, l4n, v == 4 ? psum(p + 12, 4, p + 16, proto, l4n) : psum(p + 8, 16, p + 24, proto, l4n)) != 0) bad_csum++;
  uint16_t cport = (uint16_t)(l4[2] << 8 | l4[3]);
  if (proto == 17) { flow *f = dns_by_port[cport]; if (f) f->dns_ok = 1; return; }
  if (proto != 6) return;
  flow *f = by_port[cport];
  if (!f) return;
  uint8_t fl = l4[13]; uint32_t seq = rd32(l4 + 4), ack = rd32(l4 + 8);
  int dlen = l4n - (l4[12] >> 4) * 4;
  if (fl & 0x04) { rst_seen++; if (f->state != S_DONE) { printf("FAIL: RST on flow sport %u dport %u state %d\n", f->sport, f->dport, f->state); f->state = S_FAIL; } return; }
  if (f->state == S_SYN && (fl & 0x12) == 0x12) {
    f->srv_isn = seq; f->rcv_nxt = seq + 1; f->snd_nxt += 1; f->state = S_EST;
    tcp_send(f, 0x10, 0, 0);
    f->req_bytes = 300; tcp_send(f, 0x18, 300, 0); f->snd_nxt += 300;
    return;
  }
  if (f->state != S_EST) return;
  if (f->client_fin_sent && (fl & 0x10) && (int32_t)(ack - (f->fin_seq + 1)) >= 0) f->client_fin_acked = 1;
  int adv = 0;
  if (dlen > 0 && seq == f->rcv_nxt) { f->rcv_nxt += dlen; f->echoed += dlen; adv = 1; }
  else if (dlen > 0) adv = 1; /* duplicate: re-ACK */
  if ((fl & 0x01) && seq + (uint32_t)dlen == f->rcv_nxt) { f->rcv_nxt += 1; f->server_fin = 1; adv = 1; }
  else if (fl & 0x01) adv = 1;
  if (adv) tcp_send(f, 0x10, 0, 0);
  if (f->server_fin && !f->client_fin_sent) { f->fin_seq = f->snd_nxt; tcp_send(f, 0x11, 0, 0); f->snd_nxt += 1; f->client_fin_sent = 1; }
  if (f->kind == K_CLIENT_CLOSE && !f->client_fin_sent && f->echoed >= f->req_bytes) { f->fin_seq = f->snd_nxt; tcp_send(f, 0x11, 0, 0); f->snd_nxt += 1; f->client_fin_sent = 1; }
  if (f->server_fin && f->client_fin_acked) f->state = S_DONE;
}

static void run_queues(void) {
  for (int guard = 0; guard < 100000; guard++) {
    if (qh != qt) { pkt *k = &Q[qh]; qh = (qh + 1) % QMAX; nc_input(k->b, k->n); continue; }
    if (ah != at) {
      act a = A[ah]; ah = (ah + 1) % QMAX;
      if (a.op == 3) { uint8_t r[64]; memset(r, 0x55, sizeof(r)); nc_udp_send(a.sess, r, a.n > 64 ? 64 : a.n); continue; }
      flow *f = flow_of_conn(a.conn);
      if (!f || f->engine_closed) continue;
      if (a.op == 1) {
        nc_tcp_recved(a.conn, a.n);
        uint8_t buf[1500]; memset(buf, 'e', sizeof(buf));
        nc_tcp_write(a.conn, buf, a.n);
        f->req_bytes += 0; /* echo */
        static int echoed_total;
        echoed_total += a.n;
        if (f->kind == K_SERVER_CLOSE) { f->engine_closed = 1; f->conn = NULL; nc_tcp_close(a.conn); } /* relay done: stack closes first → TIME_WAIT */
      } else if (a.op == 2) { f->engine_closed = 1; f->conn = NULL; nc_tcp_close(a.conn); }
      continue;
    }
    return;
  }
  printf("FAIL: queues never drained\n"); exit(23);
}

static uint32_t rng = 12345;
static uint32_t rnd(void) { rng = rng * 1103515245u + 12345u; return rng >> 8; }
static const uint16_t PORTS[] = {443, 443, 443, 443, 443, 443, 80, 80, 8080, 5223, 51888, 39955, 993, 853, 5228, 8443};

static void start_flow(int i) {
  flow *f = &F[nflows++];
  memset(f, 0, sizeof(*f)); f->used = 1;
  f->is6 = (i % 4 == 3);
  uint32_t h = rnd();
  /* ~400 distinct v4 / ~150 distinct v6 destinations, with repeats (same CDN IP reused) */
  if (!f->is6) { uint32_t k = h % 400; f->dst[0] = (uint8_t)(20 + k % 180); f->dst[1] = (uint8_t)(k * 7); f->dst[2] = (uint8_t)(k >> 3); f->dst[3] = (uint8_t)(1 + k % 250); }
  else { uint32_t k = h % 150; uint8_t d[16] = {0x24, 0x00, 0xcb, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; d[4] = (uint8_t)(k >> 8); d[5] = (uint8_t)k; d[14] = (uint8_t)(k * 3); d[15] = (uint8_t)(1 + k % 200); memcpy(f->dst, d, 16); }
  f->dport = (rnd() % 20 == 0) ? (uint16_t)(1024 + rnd() % 60000) : PORTS[rnd() % (sizeof(PORTS) / sizeof(PORTS[0]))];
  f->sport = (uint16_t)(20000 + i);
  f->kind = (i % 25 == 0) ? K_LONG : (i % 2 ? K_SERVER_CLOSE : K_CLIENT_CLOSE);
  if (f->kind == K_LONG) { f->pings_left = 9; f->kind = K_LONG; }
  f->snd_nxt = 1000u + (uint32_t)i * 7919u;
  f->dns_port = (uint16_t)(40000 + i % 20000);
  by_port[f->sport] = f; dns_by_port[f->dns_port] = f;
  f->start_ms = now_ms;
  dns_send(f);
  f->state = S_SYN; f->syn_at = now_ms; f->syn_tx = 1; tcp_send(f, 0x02, 0, 1);
  f->next_ping = now_ms + 10000;
}

static void tick_flows(void) {
  for (int i = 0; i < nflows; i++) {
    flow *f = &F[i];
    if (f->state == S_SYN && now_ms - f->syn_at >= 1000u * (uint32_t)f->syn_tx) {
      if (f->syn_tx >= 4) { printf("FAIL: flow sport %u → port %u (v%d) never got a SYN-ACK\n", f->sport, f->dport, f->is6 ? 6 : 4); f->state = S_FAIL; continue; }
      f->syn_tx++; uint32_t s = f->snd_nxt; tcp_send(f, 0x02, 0, 1); f->snd_nxt = s; /* iOS-like SYN retransmit */
    }
    if (f->state == S_EST && f->kind == K_LONG && !f->client_fin_sent && now_ms >= f->next_ping) {
      if (f->pings_left-- > 0) { tcp_send(f, 0x18, 100, 0); f->snd_nxt += 100; f->req_bytes += 100; f->next_ping = now_ms + 10000; }
      else { f->fin_seq = f->snd_nxt; tcp_send(f, 0x11, 0, 0); f->snd_nxt += 1; f->client_fin_sent = 1; }
    }
  }
}

int main(void) {
  setvbuf(stdout, 0, _IONBF, 0);
  const uint32_t base = 5000000;
  now_ms = 0; nc_test_set_now(base);
  nc_callbacks cb = {0}; cb.output = cb_out; cb.tcp_accept = cb_accept; cb.tcp_recv = cb_recv; cb.tcp_err = cb_err; cb.udp_recv = cb_udp;
  if (nc_init(&cb, 0, "198.18.0.1", "fdfe:dcba:9876::1", 4064) != 0) { printf("FAIL: init\n"); return 1; }
  int started = 0;
  const uint32_t END = 760000; /* 12.7 simulated minutes */
  uint32_t next_start = 0;
  int first_fail_reported = 0, peak_tw = 0, peak_active = 0;
  for (now_ms = 0; now_ms <= END; now_ms += 50) {
    nc_test_set_now(base + now_ms);
    /* burst 1: 0–200 s, one flow every 300 ms; quiet until 520 s (TIME_WAIT 2×MSL and listener idle 300 s expire);
       burst 2: 520–600 s to the same ports / addresses */
    int in_burst = (now_ms < 200000) || (now_ms >= 520000 && now_ms < 600000);
    if (in_burst && now_ms >= next_start && nflows < MAXF) { start_flow(started++); next_start = now_ms + 300; }
    tick_flows();
    run_queues();
    nc_poll();
    run_queues();
    { int a = count_list(tcp_active_pcbs), w = count_list(tcp_tw_pcbs); if (a > peak_active) peak_active = a; if (w > peak_tw) peak_tw = w; }
    if (!first_fail_reported) {
      nc_stats st; nc_get_stats(&st);
      if (st.listen_fail || st.v4_not_ours || st.v6_not_ours) {
        printf("first failure at t=%u.%03u s after %d flows: listen_fail=%u not_ours v4=%u v6=%u accepted=%u\n", now_ms / 1000, now_ms % 1000, started, st.listen_fail, st.v4_not_ours, st.v6_not_ours, st.accepted);
        first_fail_reported = 1;
      }
    }
  }
  nc_stats st; nc_get_stats(&st);
  int done = 0, failed = 0, pending = 0, dns_ok = 0, v6 = 0;
  for (int i = 0; i < nflows; i++) { if (F[i].state == S_DONE) done++; else if (F[i].state == S_FAIL) failed++; else pending++; dns_ok += F[i].dns_ok; v6 += F[i].is6; }
  printf("flows %d (v6 %d): done %d failed %d pending %d; dns answered %d/%d\n", nflows, v6, done, failed, pending, dns_ok, nflows);
  printf("stats: in v4 %u v6 %u, syn v4 %u v6 %u, listen fail %u, udp fail %u, not-ours v4 %u v6 %u, accepted %u, conn full %u, input err %u, out %u (syn-ack %u rst %u udp %u), bad csum %d\n",
         st.in_v4, st.in_v6, st.syn_v4, st.syn_v6, st.listen_fail, st.udp_session_fail, st.v4_not_ours, st.v6_not_ours, st.accepted, st.conn_full, st.input_err,
         st.out_pkts, st.out_synack, st.out_rst, st.out_udp, bad_csum);
  int active = count_list(tcp_active_pcbs), tw = count_list(tcp_tw_pcbs);
  printf("lwIP after drain: active %d time-wait %d (peak active %d, peak time-wait %d)\n", active, tw, peak_active, peak_tw);
  int ports = 0, v4d = 0, v6d = 0;
  { static uint8_t seenp[65536]; for (int i = 0; i < nflows; i++) if (!seenp[F[i].dport]++) ports++;
    for (int i = 0; i < nflows; i++) { int dup = 0; for (int j = 0; j < i && !dup; j++) dup = F[j].is6 == F[i].is6 && !memcmp(F[j].dst, F[i].dst, 16); if (!dup) { if (F[i].is6) v6d++; else v4d++; } } }
  printf("coverage: %d distinct dst ports, %d distinct v4 / %d distinct v6 destinations, %u simulated s\n", ports, v4d, v6d, END / 1000);
  /* PCB leak probe: the TCP PCB pool (128) must be (nearly) free once every flow ended and TIME_WAIT expired */
  struct tcp_pcb *probe[128]; int got = 0;
  for (; got < 120; got++) { probe[got] = tcp_new(); if (!probe[got]) break; }
  for (int i = 0; i < got; i++) tcp_abort(probe[i]);
  printf("pcb pool probe: %d/120 allocatable\n", got);
  int ok = 1;
  if (nflows < 500) { printf("FAIL: only %d flows\n", nflows); ok = 0; }
  if (failed || pending || done != nflows) { printf("FAIL: %d failed, %d pending\n", failed, pending); ok = 0; }
  if (dns_ok != nflows) { printf("FAIL: dns answered %d/%d\n", dns_ok, nflows); ok = 0; }
  if (st.accepted != st.syn_v4 + st.syn_v6) { printf("FAIL: accepted %u != syn %u (SYNs had to be retransmitted / were dropped)\n", st.accepted, st.syn_v4 + st.syn_v6); ok = 0; }
  if (st.accepted != (uint32_t)nflows) { printf("FAIL: accepted %u != flows %d\n", st.accepted, nflows); ok = 0; }
  if (st.v4_not_ours || st.v6_not_ours) { printf("FAIL: not-ours v4 %u v6 %u\n", st.v4_not_ours, st.v6_not_ours); ok = 0; }
  if (st.listen_fail || st.udp_session_fail || st.conn_full || st.input_err) { printf("FAIL: listen fail %u udp fail %u conn full %u input err %u\n", st.listen_fail, st.udp_session_fail, st.conn_full, st.input_err); ok = 0; }
  if (bad_csum) { printf("FAIL: %d emitted packets with a bad checksum\n", bad_csum); ok = 0; }
  if (active || tw) { printf("FAIL: lwIP still holds %d active / %d TIME_WAIT PCBs after drain\n", active, tw); ok = 0; }
  if (peak_tw < 10 || ports <= 24 || v4d < 100 || v6d < 50) { printf("FAIL: soak coverage too small (TIME_WAIT peak %d, ports %d, v4 %d, v6 %d)\n", peak_tw, ports, v4d, v6d); ok = 0; }
  if (got < 120) { printf("FAIL: TCP PCB pool leaked (%d/120 allocatable)\n", got); ok = 0; }
  printf(ok ? "SOAK PASS\n" : "SOAK FAIL\n");
  return ok ? 0 : 1;
}
