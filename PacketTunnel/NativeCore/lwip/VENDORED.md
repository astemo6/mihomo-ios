# Vendored lwIP

- Upstream: lwIP STABLE-2_2_0_RELEASE (BSD-3, see COPYING), core + ipv4 + ipv6
  subsets under core/, headers under include/.
- Port: port/lwipopts.h + port/arch/{cc.h,sys_arch.h} — raw API, NO_SYS,
  single-threaded, sized for the Network Extension memory budget.
- Local patch (marked "NC PATCH"): core/ip4.c `ip4_input_accept()` also accepts
  a destination when nc_stack has a listener/UDP session/connection for it
  (nc_lwip_dest_ours), which is what lets the stock stack terminate arbitrary
  TUN destinations.
- nc_stack.{h,c}: the C bridge (listener-per-destination TCP termination,
  per-flow UDP sessions, hand-built UDP replies — lwIP refuses udp_send from
  a PCB bound to a non-netif address). Verified on Linux with a packet-level
  smoke test (TCP handshake + data both ways, UDP round trip).
