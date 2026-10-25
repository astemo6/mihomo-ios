/* nc_wg: WireGuard interfaces as extra lwIP netifs (feat/nc-wg, based on astemo6/Muse NativeCore).
 *
 * The TUN netif (nc_stack) terminates app connections; a WireGuard device is a
 * second (third, ...) netif in the same lwIP instance whose packets are carried
 * by the WireGuard peer (Swift: NCWireGuard.swift). NativeCore originates TCP
 * and UDP flows *from* that netif: client PCBs are bound to it with
 * tcp_bind_netif / udp_bind_netif, so routing never mixes them with the TUN.
 *
 * Same contract as nc_stack: single-threaded, every call on the lwIP queue
 * (NCLwIP.queue in Swift), callbacks fire synchronously from these calls,
 * buffers are only valid during the callback. Handles are small integers
 * (never pointers), 0 = none / failure.
 */
#ifndef NC_WG_H
#define NC_WG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  /* The netif `dev` wants to send an IP packet to the WireGuard peer(s). */
  void (*output)(void *ctx, int32_t dev, const uint8_t *pkt, uint32_t len);
  /* tcp_connect finished (err == 0) — a failure before this arrives as tcp_err. */
  void (*tcp_connected)(void *ctx, uint32_t conn, int32_t err);
  /* Data from the remote; data == NULL means FIN. The stack does NOT open the
     window by itself: call nc_wg_tcp_recved once the bytes were consumed. */
  void (*tcp_recv)(void *ctx, uint32_t conn, const uint8_t *data, uint32_t len);
  /* `len` bytes were acknowledged: send-buffer room for nc_wg_tcp_write. */
  void (*tcp_sent)(void *ctx, uint32_t conn, uint32_t len);
  /* The connection died (RST / timeout / abort); conn is invalid afterwards. */
  void (*tcp_err)(void *ctx, uint32_t conn, int32_t err);
  /* A datagram arrived on a UDP socket. */
  void (*udp_recv)(void *ctx, uint32_t sock, const uint8_t src_ip[16], uint16_t src_port, int32_t is6,
                   const uint8_t *data, uint32_t len);
} nc_wg_callbacks;

void nc_wg_set_callbacks(const nc_wg_callbacks *cbs, void *ctx);

/* Adds a WireGuard netif. ip4 / ip6 (either may be NULL, not both) are the
   interface addresses from the node's `ip` / `ipv6`. Returns the device id
   (>= 1) or 0 on failure. Initialises lwIP when the TUN is not up yet. */
int32_t nc_wg_dev_add(const char *ip4, const char *ip6, uint16_t mtu);
/* Aborts every connection / socket of the device and removes its netif. */
void nc_wg_dev_remove(int32_t dev);
/* A decrypted IP packet from the peer. */
void nc_wg_input(int32_t dev, const uint8_t *pkt, uint32_t len);
/* lwIP timers (the TUN's nc_poll also drives them; calling both is harmless). */
void nc_wg_poll(void);

uint32_t nc_wg_tcp_connect(int32_t dev, const uint8_t ip[16], int32_t is6, uint16_t port);
/* Returns bytes queued (>= 0) or -1 when the connection is gone. */
int32_t nc_wg_tcp_write(uint32_t conn, const uint8_t *data, uint32_t len);
void nc_wg_tcp_recved(uint32_t conn, uint32_t len);
void nc_wg_tcp_close(uint32_t conn);
void nc_wg_tcp_abort(uint32_t conn);

uint32_t nc_wg_udp_open(int32_t dev, int32_t is6);
int32_t nc_wg_udp_send(uint32_t sock, const uint8_t ip[16], int32_t is6, uint16_t port,
                       const uint8_t *data, uint32_t len);
void nc_wg_udp_close(uint32_t sock);

#ifdef __cplusplus
}
#endif

#endif
