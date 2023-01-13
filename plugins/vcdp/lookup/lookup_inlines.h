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

// select service chain
// TCP
// ICMP error
// default
// drop
typedef enum {
  VCDP_SERVICE_CHAIN_DEFAULT = 0,
  VCDP_SERVICE_CHAIN_TCP,
  VCDP_SERVICE_CHAIN_ICMP_ERROR,
  VCDP_SERVICE_CHAIN_DROP,
  VCDP_SERVICE_CHAIN_DROP_NO_KEY,
} vcdp_service_chain_selector_t;

static inline int
vcdp_header_offset(void *start, void *end, int header_size)
{
  return (end - start) + header_size;
}
static inline void
vcdp_calc_key_v4(vlib_buffer_t *b, u32 context_id, vcdp_session_ip4_key_t *skey, u64 *h, int *sc)
{
  ip4_header_t *ip = vlib_buffer_get_current(b);
  int offset = 0;
  u16 sport = 0, dport = 0;
  udp_header_t *udp;
  icmp46_header_t *icmp;
  nat_icmp_echo_header_t *echo;
  sc[0] = VCDP_SERVICE_CHAIN_DEFAULT;

  switch (ip->protocol) {
  case IP_PROTOCOL_TCP:
    udp = (udp_header_t *) ip4_next_header(ip);
    offset = vcdp_header_offset(ip, udp, sizeof(*udp));
    sport = udp->src_port;
    dport = udp->dst_port;
    sc[0] = VCDP_SERVICE_CHAIN_TCP;
    break;
  case IP_PROTOCOL_UDP:
    udp = (udp_header_t *) ip4_next_header(ip);
    offset = vcdp_header_offset(ip, udp, sizeof(*udp));
    sport = udp->src_port;
    dport = udp->dst_port;
    break;
  case IP_PROTOCOL_ICMP:
    icmp = (icmp46_header_t *) ip4_next_header(ip);
    echo = (nat_icmp_echo_header_t *) (icmp + 1);
    offset = vcdp_header_offset(ip, echo, sizeof(*echo));

    if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
      sport = dport = echo->identifier;
    } else {
      /* Do the same thing for the inner packet */
      ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);
      offset = vcdp_header_offset(ip, inner_ip, sizeof(*inner_ip));
      sc[0] = VCDP_SERVICE_CHAIN_ICMP_ERROR;
      switch (inner_ip->protocol) {
      case IP_PROTOCOL_TCP:
        udp = (udp_header_t *) ip4_next_header(inner_ip);
        offset = vcdp_header_offset(ip, udp, sizeof(*udp));
        sport = udp->src_port;
        dport = udp->dst_port;
        break;
      case IP_PROTOCOL_UDP:
        udp = (udp_header_t *) ip4_next_header(inner_ip);
        offset = vcdp_header_offset(ip, udp, sizeof(*udp));
        sport = udp->src_port;
        dport = udp->dst_port;
        break;
      case IP_PROTOCOL_ICMP:
        icmp = (icmp46_header_t *) ip4_next_header(inner_ip);
        echo = (nat_icmp_echo_header_t *) (icmp + 1);
        offset = vcdp_header_offset(ip, echo, sizeof(*echo));
        if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
          sport = dport = echo->identifier;
        } else {
          sc[0] = VCDP_SERVICE_CHAIN_DROP;
        }
        break;
      }
      break;
    }
  }

  if (offset > b->current_length)
    sc[0] = VCDP_SERVICE_CHAIN_DROP_NO_KEY;

  // *skey = (vcdp_session_ip4_key_t){0};
  skey->context_id = context_id;
  skey->src = ip->src_address.as_u32;
  skey->dst = ip->dst_address.as_u32;
  skey->sport = sport;
  skey->dport = dport;
  skey->proto = ip->protocol;

  /* calculate hash */
  h[0] = clib_bihash_hash_16_8((clib_bihash_kv_16_8_t *) (skey));
}

#endif
