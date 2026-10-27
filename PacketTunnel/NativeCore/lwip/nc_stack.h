/* nc_stack: a small C bridge over vendored lwIP (raw API, NO_SYS) for the
   native core's TUN data plane — docs/native-core-design.md.
 *
 * Model: the engine owns one queue. It feeds raw IP packets from the packet
   flow into nc_input(), and stack output comes back through the output
   callback. Incoming TCP connections are terminated by lwIP: because apps
   dial arbitrary destinations, the shim peeks at SYNs and installs a
   dedicated listening PCB bound to that destination before feeding the
   packet (the "listener per destination" trick used by lwIP tun2socks
   stacks). UDP works the same way with per-(src,dst) session PCBs.
 *
 * All callbacks fire synchronously from nc_input()/nc_poll(); byte buffers
 * passed to them are valid only for the duration of the call.
 */
#ifndef NC_STACK_H
#define NC_STACK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  /* Stack wants to emit an IP packet toward the apps. */
  void (*output)(void *ctx, const uint8_t *pkt, uint32_t len);
  /* A TCP connection was accepted. dst is the original destination the app
     dialed (often a fake IP). Return 0 to refuse (connection is aborted). */
  int (*tcp_accept)(void *ctx, void *conn, const uint8_t dst_ip[16], uint16_t dst_port,
                    const uint8_t src_ip[16], uint16_t src_port, int is6);
  /* Data arrived on a TCP connection. data == NULL means the peer sent FIN. */
  void (*tcp_recv)(void *ctx, void *conn, const uint8_t *data, uint32_t len);
  /* The connection died (RST, timeout...). conn is invalid after this call. */
  void (*tcp_err)(void *ctx, void *conn, int err);
  /* A UDP datagram arrived on a session. src is the app-side endpoint, dst the
     destination it was sent to. */
  void (*udp_recv)(void *ctx, uint32_t session, const uint8_t src_ip[16], uint16_t src_port,
                   const uint8_t dst_ip[16], uint16_t dst_port, int is6,
                   const uint8_t *data, uint32_t len);
  /* rv2-life: the peer ACKed `len` bytes of what nc_tcp_write queued (send window opened again): the engine drains
     its outbox and resumes reading the relay. May be NULL. */
  void (*tcp_sent)(void *ctx, void *conn, uint32_t len);
  /* rv2-life: a UDP session ended on the C side — idle expiry (120 s) or evicted to make room for a new flow — so
     the engine drops its relay for that id (replies to it would be dropped anyway). Not called for nc_udp_close
     or nc_shutdown. May be NULL. */
  void (*udp_closed)(void *ctx, uint32_t session);
} nc_callbacks;

/* ip4: dotted quad of the tunnel interface (e.g. "198.18.0.1"); ip6 may be NULL.
   Returns 0 on success. */
int nc_init(const nc_callbacks *cbs, void *ctx, const char *ip4, const char *ip6, uint16_t mtu);
void nc_shutdown(void);
void nc_input(const uint8_t *pkt, uint32_t len);
/* Drive lwIP timers and idle sweeps. Call at least every 250 ms. */
void nc_poll(void);

/* TCP, called by the engine on its queue. conn is the handle from tcp_accept.
   nc_tcp_write returns the number of bytes queued (>= 0), or -1 if the
   connection is gone; callers keep the remainder and retry later. */
int nc_tcp_write(void *conn, const uint8_t *data, uint32_t len);
/* rv2-life: received bytes are no longer acknowledged to lwIP automatically: the engine calls this once it has
   handed `len` bytes to the relay (or buffered them within its cap), which reopens the receive window toward the
   app. This is the upstream back-pressure: an app cannot push more than TCP_WND ahead of the relay. */
void nc_tcp_recved(void *conn, uint32_t len);
void nc_tcp_output(void *conn);
void nc_tcp_close(void *conn);
void nc_tcp_abort(void *conn);

/* UDP: send a reply datagram on a session (it will appear to come from the
   original destination). Sessions close after 120 s idle or via nc_udp_close. */
int nc_udp_send(uint32_t session, const uint8_t *data, uint32_t len);
void nc_udp_close(uint32_t session);

/* fix/nc-tcp0: what the C side did with the packets it was given (诊断 "tcp accepted 0" root-causing). Counters
   since nc_init; read on the engine queue. */
typedef struct {
  uint32_t in_v4, in_v6;          /* packets handed to nc_input */
  uint32_t in_other;              /* not v4 / v6, or too short */
  uint32_t syn_v4, syn_v6;        /* TCP SYN (no ACK) seen by the peek */
  uint32_t listen_fail;           /* no listener could be installed (table full / bind / listen failed) */
  uint32_t udp_session_fail;      /* no UDP session could be installed */
  uint32_t v4_not_ours, v6_not_ours; /* lwIP dropped the packet: destination not terminated here */
  uint32_t accepted;              /* handshake completed, accept callback ran */
  uint32_t accept_refused;        /* engine returned 0 from tcp_accept */
  uint32_t conn_full;             /* NC_MAX_TCP_CONNS exhausted: aborted */
  uint32_t input_err;             /* netif input returned an error / pbuf alloc failed */
  uint32_t out_pkts, out_synack, out_rst; /* packets emitted toward the apps (SYN-ACK / RST counted apart) */
  uint32_t out_udp;               /* hand-built UDP replies (DNS answers included) */
} nc_stats;
void nc_get_stats(nc_stats *out);

#ifdef __cplusplus
}
#endif

#endif
