// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_lookup_inlines_h
#define included_lookup_inlines_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4.h>
#include <vcdp/vcdp.h>
#include <vcdp/common.h>
#include <arpa/inet.h> // TODO: remove
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>

// TODO: Move this to icmp46_packet.h
typedef struct
{
  u16 identifier;
  u16 sequence;
} nat_icmp_echo_header_t;

// TODO: Remove lookup_val
static_always_inline void
vcdp_calc_key_v4(vlib_buffer_t *b, u32 context_id, vcdp_session_ip4_key_t *skey, u64 *h)
{
  ip4_header_t *ip = vlib_buffer_get_current(b);
  u16 sport = 0, dport = 0;

  if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = (udp_header_t *) ip4_next_header(ip);
    sport = udp->src_port;
    dport = udp->dst_port;
  } else if (ip->protocol == IP_PROTOCOL_ICMP) {
    icmp46_header_t *icmp = (icmp46_header_t *) ip4_next_header(ip);
    // Only support ICMP query types here
    // TODO: ICMP error
    if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
      nat_icmp_echo_header_t *echo = (nat_icmp_echo_header_t *) (icmp + 1);
      sport = dport = echo->identifier;
    }
  }

  *skey = (vcdp_session_ip4_key_t){0};
  skey->context_id = context_id;
  skey->src = ip->src_address.as_u32;
  skey->dst = ip->dst_address.as_u32;
  skey->sport = sport;
  skey->dport = dport;
  skey->proto = ip->protocol;

  // figure out who uses this:
  // void *next_header = ip4_next_header(ip);
  // l4_hdr_offset[0] = (u8 *) next_header - b->data;

  /* calculate hash */
  h[0] = clib_bihash_hash_16_8((clib_bihash_kv_16_8_t *) (skey));
}

#endif
