/* Bulk-download regression for the TUN bridge, run by Checks -> nc-stack-c.
   One flow; the engine pushes a 300 KB response through nc_tcp_write in 64 KB
   calls — exactly what NCDataPlane's drain does with a large relay read — and
   the simulated client ACKs (two flavors: per segment, and batched through
   the main-loop pump like a packet flow). Pins the wedge fixed in
   fix/nc-tcp-write-chunk: nc_tcp_write used to chunk by the u16 limit while
   lwIP's tcp_write is all-or-nothing against TCP_SND_BUF (23360 B), so any
   write over ~23 KB queued nothing and the flow stalled for good with the
   response stuck in the engine's outbox (device: content flows of XHS /
   YouTube / Ximalaya dying after the first burst). */
#include "nc_stack.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static uint16_t csum(const uint8_t *b, int n, uint32_t s) { for (int i = 0; i + 1 < n; i += 2) s += (b[i] << 8) | b[i + 1]; if (n & 1) s += b[n - 1] << 8; while (s >> 16) s = (s & 0xffff) + (s >> 16); return (uint16_t)~s; }
static uint32_t psum(const uint8_t *a, int alen, const uint8_t *b, int proto, int len) { uint32_t x = 0; for (int i = 0; i < alen; i += 2) x += (a[i] << 8 | a[i + 1]) + (b[i] << 8 | b[i + 1]); return x + proto + len; }
static uint32_t rd32(const uint8_t *b) { return (uint32_t)b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]; }

static const uint8_t S4[4] = {198, 18, 0, 1}, D4[4] = {93, 184, 216, 34};
static void *g_conn;
static uint32_t srv_seq;        /* stack's next seq (learned from SYN-ACK) */
static uint32_t cli_rcv;        /* client's next expected seq */
static long delivered;          /* payload bytes the client has received */
static int ack_pending; static int ack_due;         /* batched mode: segments since last ACK */
static int batch_mode;
static int got_request;

static void send4raw(uint8_t *t, int l4) {
  uint8_t p[2000]; memset(p, 0, 20); p[0] = 0x45; int tl = 20 + l4; p[2] = tl >> 8; p[3] = tl; p[8] = 64; p[9] = 6;
  memcpy(p + 12, S4, 4); memcpy(p + 16, D4, 4);
  uint16_t c = csum(p, 20, 0); p[10] = c >> 8; p[11] = c; memcpy(p + 20, t, l4);
  c = csum(p + 20, l4, psum(S4, 4, D4, 6, l4)); p[36] = c >> 8; p[37] = c; nc_input(p, tl);
}
static void cli_ack(void) {
  uint8_t t[20]; memset(t, 0, 20);
  t[0] = 50000 >> 8; t[1] = 50000 & 0xff; t[2] = 443 >> 8; t[3] = 443 & 0xff;
  uint32_t seq = 1001; t[4] = seq >> 24; t[5] = seq >> 16; t[6] = seq >> 8; t[7] = seq;
  t[8] = cli_rcv >> 24; t[9] = cli_rcv >> 16; t[10] = cli_rcv >> 8; t[11] = cli_rcv;
  t[12] = 5 << 4; t[13] = 0x10; t[14] = 0xff; t[15] = 0xff;
  send4raw(t, 20);
}
static void out(void *c, const uint8_t *p, uint32_t n) {
  if ((p[0] >> 4) != 4 || p[9] != 6) return;
  const uint8_t *t = p + 20; int l4 = (int)n - 20; int hl = (t[12] >> 4) * 4;
  uint32_t seq = rd32(t + 4); int pay = l4 - hl;
  if (t[13] & 0x02) { srv_seq = seq + 1; cli_rcv = srv_seq; return; } /* SYN-ACK */
  if (pay > 0 && seq == cli_rcv) { delivered += pay; cli_rcv += pay; }
  if (pay > 0) {
    if (!batch_mode) ack_due = 1;
    else if (++ack_pending >= 8) { ack_pending = 0; ack_due = 1; }
  }
}
static int acc(void *c, void *conn, const uint8_t d[16], uint16_t dp, const uint8_t s[16], uint16_t sp, int is6) { g_conn = conn; return 1; }
static void rcv(void *c, void *conn, const uint8_t *d, uint32_t n) { got_request = 1; nc_tcp_recved(conn, n); }
static void er(void *c, void *conn, int e) { printf("TCPERR %d\n", e); }
static void ud(void *c, uint32_t s, const uint8_t si[16], uint16_t sp, const uint8_t di[16], uint16_t dp, int is6, const uint8_t *d, uint32_t n) {}
static void sentcb(void *c, void *conn, uint32_t len) { (void)c; (void)conn; (void)len; }

static void seg(uint8_t *t, uint32_t seq, uint32_t ack, uint8_t flags, int syn_opts) {
  int hl = syn_opts ? 44 : 20; memset(t, 0, hl);
  t[0] = 50000 >> 8; t[1] = 50000 & 0xff; t[2] = 443 >> 8; t[3] = 443 & 0xff;
  t[4] = seq >> 24; t[5] = seq >> 16; t[6] = seq >> 8; t[7] = seq; t[8] = ack >> 24; t[9] = ack >> 16; t[10] = ack >> 8; t[11] = ack;
  t[12] = (hl / 4) << 4; t[13] = flags; t[14] = 0xff; t[15] = 0xff;
  if (syn_opts) { uint8_t o[24] = {2, 4, 0x0f, 0xb8, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 4, 2, 0, 0}; memcpy(t + 20, o, 24); }
}

static int run_case(int batch) {
  batch_mode = batch; delivered = 0; got_request = 0; ack_pending = 0; g_conn = 0; cli_rcv = 0;
  nc_callbacks cb = {0}; cb.output = out; cb.tcp_accept = acc; cb.tcp_recv = rcv; cb.tcp_err = er; cb.udp_recv = ud; cb.tcp_sent = sentcb;
  int irc = nc_init(&cb, 0, "198.18.0.1", "fdfe:dcba:9876::1", 4064); if (irc != 0) { printf("init fail rc=%d\n", irc); return 2; }
  uint8_t t[64];
  seg(t, 1000, 0, 0x02, 1); send4raw(t, 44);
  nc_poll();
  seg(t, 1001, cli_rcv, 0x10, 0); send4raw(t, 20);
  nc_poll();
  if (!g_conn) { printf("no accept\n"); return 2; }
  seg(t, 1001, cli_rcv, 0x18, 0);
  /* request: 4 payload bytes */
  uint8_t req[24]; memcpy(req, t, 20); memcpy(req + 20, "GET ", 4); send4raw(req, 24);
  if (!got_request) { printf("no request\n"); return 2; }
  const int TOTAL = 300000;
  static uint8_t body[300000]; memset(body, 'x', sizeof(body));
  int off = 0; long last_delivered = 0; int stall_rounds = 0;
  for (int round = 0; round < 200000; round++) {
    if (off < TOTAL) {
      int want = TOTAL - off; if (want > 65536) want = 65536;
      int w = nc_tcp_write(g_conn, body + off, want);
      if (w > 0) off += w;
    }
    nc_poll();
    if (ack_due) { ack_due = 0; cli_ack(); nc_poll(); }
    if (batch_mode && ack_pending > 0 && (round % 4 == 3)) { ack_pending = 0; cli_ack(); nc_poll(); }
    if (delivered != last_delivered) { last_delivered = delivered; stall_rounds = 0; }
    else if (++stall_rounds > 20000) break;
    if (delivered >= TOTAL) break;
  }
  printf("batch=%d: engine_wrote=%d client_delivered=%ld / %d  %s\n", batch, off, delivered, TOTAL,
         delivered >= TOTAL ? "COMPLETE" : "STALLED");
  return delivered >= TOTAL ? 0 : 1;
}

int main(void) {
  setvbuf(stdout, 0, _IONBF, 0);
  int r1 = run_case(0);
  int r2 = run_case(1);
  printf((r1 == 0 && r2 == 0) ? "BULK PASS\n" : "BULK FAIL\n");
  return (r1 == 0 && r2 == 0) ? 0 : 1;
}
