/* fix/nc-tcp0: host-side test of the TUN bridge (nc_stack.c + vendored lwIP), run by Checks → nc-stack-c.
   Full TCP handshake with iOS-like SYN options over IPv4 and IPv6 to real (non-netif) destinations, IPv6 UDP in,
   UDP replies (v4 + v6) out with their IP / UDP checksums verified byte-for-byte, and the nc_get_stats counters.
   build419 regressions it pins: v6 SYN / datagrams dropped as "not for us" (peek byte order + ip6_input_accept),
   and every hand-built UDP reply (all DNS answers) carrying a byte-swapped IPv4 header checksum and a UDP
   checksum that skipped the UDP header — XNU drops those, so apps never got a DNS answer. */
#include "nc_stack.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static int outs = 0, accepts = 0, udps = 0; static void *lastconn; static uint32_t lastsess;
static uint8_t last[4096]; static uint32_t lastn;
static uint16_t csum(const uint8_t *b, int n, uint32_t s) { for (int i = 0; i + 1 < n; i += 2) s += (b[i] << 8) | b[i + 1]; if (n & 1) s += b[n - 1] << 8; while (s >> 16) s = (s & 0xffff) + (s >> 16); return (uint16_t)~s; }
static uint32_t psum(const uint8_t *a, int alen, const uint8_t *b, int proto, int len) { uint32_t x = 0; for (int i = 0; i < alen; i += 2) x += (a[i] << 8 | a[i + 1]) + (b[i] << 8 | b[i + 1]); return x + proto + len; }
static void out(void *c, const uint8_t *p, uint32_t n) {
  outs++; memcpy(last, p, n); lastn = n;
  int v = p[0] >> 4;
  if (v == 4) { const uint8_t *t = p + (p[0] & 15) * 4; int l4 = n - (p[0] & 15) * 4;
    printf("OUT v4 len=%u proto=%u flags=%02x l4csum_ok=%d\n", n, p[9], p[9] == 6 ? t[13] : 0, csum(t, l4, psum(p + 12, 4, p + 16, p[9], l4)) == 0); }
  else { const uint8_t *t = p + 40; int l4 = n - 40;
    printf("OUT v6 len=%u nh=%u flags=%02x l4csum_ok=%d\n", n, p[6], p[6] == 6 ? t[13] : 0, csum(t, l4, psum(p + 8, 16, p + 24, p[6], l4)) == 0); }
}
static int acc(void *c, void *conn, const uint8_t d[16], uint16_t dp, const uint8_t s[16], uint16_t sp, int is6) { accepts++; lastconn = conn; printf("ACCEPT v%d port %u\n", is6 ? 6 : 4, dp); return 1; }
static void rcv(void *c, void *conn, const uint8_t *d, uint32_t n) { printf("TCPRECV %u\n", n); }
static void er(void *c, void *conn, int e) { printf("TCPERR %d\n", e); }
static void ud(void *c, uint32_t s, const uint8_t si[16], uint16_t sp, const uint8_t di[16], uint16_t dp, int is6, const uint8_t *d, uint32_t n) { udps++; lastsess = s; printf("UDP v%d sess=%u dport %u len=%u\n", is6 ? 6 : 4, s, dp, n); }

static int tcpseg(uint8_t *t, uint16_t sp, uint16_t dp, uint32_t seq, uint32_t ack, uint8_t flags, int syn_opts) {
  int hl = syn_opts ? 44 : 20; memset(t, 0, hl);
  t[0] = sp >> 8; t[1] = sp; t[2] = dp >> 8; t[3] = dp;
  t[4] = seq >> 24; t[5] = seq >> 16; t[6] = seq >> 8; t[7] = seq; t[8] = ack >> 24; t[9] = ack >> 16; t[10] = ack >> 8; t[11] = ack;
  t[12] = (hl / 4) << 4; t[13] = flags; t[14] = 0xff; t[15] = 0xff;
  if (syn_opts) { uint8_t o[24] = {2, 4, 0x0f, 0xb8, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 4, 2, 0, 0}; memcpy(t + 20, o, 24); }
  return hl;
}
static void send4(const uint8_t s[4], const uint8_t d[4], uint8_t *t, int l4) {
  uint8_t p[2000]; memset(p, 0, 20); p[0] = 0x45; int tl = 20 + l4; p[2] = tl >> 8; p[3] = tl; p[8] = 64; p[9] = 6; memcpy(p + 12, s, 4); memcpy(p + 16, d, 4);
  uint16_t c = csum(p, 20, 0); p[10] = c >> 8; p[11] = c; memcpy(p + 20, t, l4);
  c = csum(p + 20, l4, psum(s, 4, d, 6, l4)); p[36] = c >> 8; p[37] = c; nc_input(p, tl);
}
static void send6(const uint8_t s[16], const uint8_t d[16], int nh, uint8_t *t, int l4) {
  uint8_t p[2000]; memset(p, 0, 40); p[0] = 0x60; p[4] = l4 >> 8; p[5] = l4; p[6] = nh; p[7] = 64; memcpy(p + 8, s, 16); memcpy(p + 24, d, 16); memcpy(p + 40, t, l4);
  uint16_t c = csum(p + 40, l4, psum(s, 16, d, nh, l4)); int off = nh == 6 ? 16 : 6; p[40 + off] = c >> 8; p[41 + off] = c; nc_input(p, 40 + l4);
}
static uint32_t rd32(const uint8_t *b) { return (uint32_t)b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]; }
int main(void) {
  setvbuf(stdout, 0, _IONBF, 0);
  nc_callbacks cb = {0}; cb.output = out; cb.tcp_accept = acc; cb.tcp_recv = rcv; cb.tcp_err = er; cb.udp_recv = ud;
  printf("init=%d\n", nc_init(&cb, 0, "198.18.0.1", "fdfe:dcba:9876::1", 4064));
  uint8_t t[100];
  // v4 handshake to a real address
  uint8_t s4[4] = {198, 18, 0, 1}, d4[4] = {93, 184, 216, 34};
  send4(s4, d4, t, tcpseg(t, 50000, 443, 1000, 0, 0x02, 1));
  if (lastn) { uint32_t sseq = rd32(last + 20 + 4); send4(s4, d4, t, tcpseg(t, 50000, 443, 1001, sseq + 1, 0x10, 0)); }
  printf("v4: outs=%d accepts=%d\n", outs, accepts);
  int a4 = accepts; outs = 0; lastn = 0;
  // v6 handshake to a real global address (what redir-host / ipv6 on sends)
  uint8_t s6[16] = {0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  uint8_t d6[16] = {0x24, 0x04, 0x68, 0x00, 0x40, 0x05, 0x08, 0x0f, 0, 0, 0, 0, 0, 0, 0x20, 0x04};
  send6(s6, d6, 6, t, tcpseg(t, 50001, 443, 5000, 0, 0x02, 1));
  if (lastn) { uint32_t sseq = rd32(last + 40 + 4); send6(s6, d6, 6, t, tcpseg(t, 50001, 443, 5001, sseq + 1, 0x10, 0)); }
  printf("v6: outs=%d accepts=%d\n", outs, accepts - a4);
  // v6 UDP (QUIC / v6 DNS)
  uint8_t u[40]; memset(u, 0, 40); u[0] = 0xc3; u[1] = 0x51; u[2] = 1; u[3] = 0xbb; u[5] = 40; memset(u + 8, 0xab, 32);
  send6(s6, d6, 17, u, 40);
  printf("v6 udp: udps=%d\n", udps);
  outs = 0; int urc = nc_udp_send(lastsess, (const uint8_t *)"hello-v6", 8); printf("v6 udp reply rc=%d outs=%d\n", urc, outs);
  int ureply = outs == 1 && last[0] >> 4 == 6 && csum(last + 40, lastn - 40, psum(last + 8, 16, last + 24, 17, lastn - 40)) == 0;
  outs = 0; int w = nc_tcp_write(lastconn, (const uint8_t *)"0123456789", 10); nc_tcp_output(lastconn); printf("v6 tcp write=%d outs=%d\n", w, outs);
  int tw = outs >= 1;
  if (!ureply || !tw) return 2;
  nc_stats st; nc_get_stats(&st);
  printf("stats: in4=%u in6=%u syn4=%u syn6=%u listen_fail=%u v6_not_ours=%u v4_not_ours=%u out=%u synack=%u rst=%u conn_full=%u\n", st.in_v4, st.in_v6, st.syn_v4, st.syn_v6, st.listen_fail, st.v6_not_ours, st.v4_not_ours, st.out_pkts, st.out_synack, st.out_rst, st.conn_full);
  // v4 DNS-style round trip: query in, reply out, both checksums verified
  {
    uint8_t p[100] = {0x45, 0, 0, 37, 0, 0, 0x40, 0, 64, 17, 0, 0, 198, 18, 0, 1, 198, 18, 0, 2};
    uint8_t *uu = p + 20; uu[0] = 0x14; uu[1] = 0xe9; uu[3] = 53; uu[5] = 17; memset(uu + 8, 0x41, 9);
    uint16_t c = csum(p, 20, 0); p[10] = c >> 8; p[11] = c;
    c = csum(uu, 17, psum(p + 12, 4, p + 16, 17, 17)); uu[6] = c >> 8; uu[7] = c;
    int before = udps; nc_input(p, 37);
    if (udps != before + 1) { printf("FAIL: v4 udp not delivered\n"); return 3; }
    outs = 0; lastn = 0;
    nc_udp_send(lastsess, (const uint8_t *)"abcdefghi", 9);
    int iphdr_ok = lastn >= 20 && csum(last, 20, 0) == 0;
    int udp_ok = lastn == 37 && csum(last + 20, 17, psum(last + 12, 4, last + 16, 17, 17)) == 0;
    printf("v4 udp reply: len=%u iphdr_ok=%d udp_ok=%d\n", lastn, iphdr_ok, udp_ok);
    if (!iphdr_ok || !udp_ok) { printf("FAIL: v4 udp reply checksums\n"); return 4; }
    if (!(last[0] == 0x45 && last[12] == 198 && last[15] == 2 && last[19] == 1 && last[20] == 0 && last[21] == 53)) { printf("FAIL: v4 reply addressing\n"); return 5; }
  }
  if (!(a4 == 1 && accepts == 2 && udps >= 2)) { printf("FAIL: accepts=%d udps=%d\n", accepts, udps); return 1; }
  if (st.v6_not_ours != 0 || st.syn_v6 != 1 || st.accepted != 2) { printf("FAIL: stats\n"); return 6; }
  printf("PASS\n");
  return 0;
}
