// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_lookup_inlines_h
#define included_lookup_inlines_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4.h>
#include <vcdp/vcdp.h>
#include <vcdp/common.h>
#include <arpa/inet.h>
#include <vnet/udp/udp_packet.h>

// TODO: Remove lookup_val
static_always_inline void
vcdp_calc_key_v4(vlib_buffer_t *b, u32 context_id, vcdp_session_ip4_key_t *skey, u64 *lookup_val, u64 *h)
{
  ip4_header_t *ip = vlib_buffer_get_current(b);
  udp_header_t *udp = (udp_header_t *) (ip+1);
  u32 ip_addr_lo, ip_addr_hi;
  u16 port_lo, port_hi;
  u16 sport = udp->src_port;
  u16 dport = udp->dst_port;
  u32 src = ntohl(ip->src_address.as_u32);
  u32 dst = ntohl(ip->dst_address.as_u32);

  lookup_val[0] = 0;

  if (src < dst) {
    ip_addr_lo = src;
    port_lo = sport;
    ip_addr_hi = dst;
    port_hi = dport;
  } else {
    /* Normalize */
    ip_addr_lo = dst;
    port_lo = dport;
    ip_addr_hi = src;
    port_hi = sport;
    lookup_val[0] |= 0x1;
  }


  *skey = (vcdp_session_ip4_key_t){0};
  skey->context_id = context_id;
  skey->ip_addr_lo = htonl(ip_addr_lo);
  skey->port_lo = port_lo;
  skey->port_hi = port_hi;
  skey->ip_addr_hi = htonl(ip_addr_hi);
  skey->proto = ip->protocol;

  // figure out who uses this:
  // void *next_header = ip4_next_header(ip);
  // l4_hdr_offset[0] = (u8 *) next_header - b->data;

  /* calculate hash */
  h[0] = clib_bihash_hash_16_8((clib_bihash_kv_16_8_t *) (skey));
}

#endif
