// SPDX-License-Identifier: Apache-2.0
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
#include <vcdp/vcdp_funcs.h>

static inline int
vcdp_header_offset(void *start, void *end, int header_size)
{
  return (end - start) + header_size;
}

static inline void
vcdp_calc_key_v4(vlib_buffer_t *b, u32 context_id, bool is_3tuple, vcdp_session_ip4_key_t *skey, u64 *h)
{
  ip4_header_t *ip = vcdp_get_ip4_header(b);
  skey->proto = ip->protocol;
  skey->context_id = context_id;
  skey->src = ip->src_address.as_u32;
  skey->dst = ip->dst_address.as_u32;

  if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = (udp_header_t *) (ip+1);
    skey->sport = udp->src_port;
    skey->dport = udp->dst_port;
    vnet_buffer(b)->l4_hdr_offset = b->current_data + (void *)udp - (void *)ip;
  } else if (ip->protocol == IP_PROTOCOL_ICMP) {
    icmp46_header_t *icmp = (icmp46_header_t *) ip4_next_header(ip);
    icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
    skey->sport = skey->dport = echo->identifier;
    vnet_buffer(b)->l4_hdr_offset = b->current_data + (void *)icmp - (void *)ip;
  } else {
    skey->sport = skey->dport = 0;
  }
  if (is_3tuple) {
    skey->sport = 0;
    skey->src = 0;
  }
  /* calculate hash */
  h[0] = clib_bihash_hash_16_8((clib_bihash_kv_16_8_t *) (skey));
}

static inline void
vcdp_calc_key_v6(vlib_buffer_t *b, u32 context_id, bool is_3tuple, vcdp_session_ip6_key_t *skey, u64 *h)
{
  ip6_header_t *ip = vcdp_get_ip6_header(b);
  skey->proto = ip->protocol;
  skey->context_id = context_id;
  skey->src = ip->src_address;
  skey->dst = ip->dst_address;

  if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = (udp_header_t *) (ip+1);
    skey->sport = udp->src_port;
    skey->dport = udp->dst_port;
    vnet_buffer(b)->l4_hdr_offset = b->current_data + (void *)udp - (void *)ip;
  } else if (ip->protocol == IP_PROTOCOL_ICMP6) {
    icmp46_header_t *icmp = (icmp46_header_t *) ip6_next_header(ip);
    icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
    skey->sport = skey->dport = echo->identifier;
    vnet_buffer(b)->l4_hdr_offset = b->current_data + (void *)icmp - (void *)ip;
  } else {
    skey->sport = skey->dport = 0;
  }
  if (is_3tuple) {
    skey->sport = 0;
    skey->src.as_u64[0] = 0;
    skey->src.as_u64[1] = 0;
  }

  /* calculate hash */
  h[0] = clib_bihash_hash_40_8((clib_bihash_kv_40_8_t *) (skey));
}

static inline void
vcdp_calc_key(vlib_buffer_t *b, u32 context_id, vcdp_session_key_t *skey, u64 *h, bool is_ip6, bool is_3tuple)
{
  if (is_ip6) {
    skey->is_ip6 = true;
    return vcdp_calc_key_v6(b, context_id, is_3tuple, &skey->ip6, h);
  } else {
    skey->is_ip6 = false;
    return vcdp_calc_key_v4(b, context_id, is_3tuple, &skey->ip4, h);
  }
}

/*
 * Find the 5-tuple key. In case of an ICMP error use the inner IP packet.
 */
static inline int
vcdp_calc_key_slow(vlib_buffer_t *b, u32 context_id, vcdp_session_key_t *skey, u64 *h, bool is_ip6)
{
  int offset = 0;
  udp_header_t *udp;
  icmp46_header_t *icmp;
  icmp_echo_header_t *echo;

  if (is_ip6) {
    ip6_header_t *ip = vcdp_get_ip6_header(b);
    // if (ip6_is_fragment(ip)) {
    //   return -1;
    // }

    vcdp_session_ip6_key_t *k = &skey->ip6;
    k->src = ip->src_address;
    k->dst = ip->dst_address;
    k->proto = ip->protocol;
    k->context_id = context_id;
    skey->is_ip6 = true;

    if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) {
      udp = (udp_header_t *) (ip + 1);
      offset = vcdp_header_offset(ip, udp, sizeof(*udp));
      k->sport = udp->src_port;
      k->dport = udp->dst_port;
    } else if (ip->protocol == IP_PROTOCOL_ICMP6) {
      icmp = (icmp46_header_t *) ip6_next_header(ip);
      echo = (icmp_echo_header_t *) (icmp + 1);
      offset = vcdp_header_offset(ip, echo, sizeof(*echo));
      k->sport = k->dport = 0; // default
      if (icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply) {
        k->sport = k->dport = echo->identifier;
      } else if (icmp->type < 128) {
        /* Do the same thing for the inner packet */
        ip6_header_t *inner_ip = (ip6_header_t *) (echo + 1);
        offset = vcdp_header_offset(ip, inner_ip, sizeof(*inner_ip));
        // Swap lookup key for ICMP error
        k->dst = inner_ip->dst_address;
        k->src = inner_ip->src_address;
        k->proto = inner_ip->protocol;
        if (inner_ip->protocol == IP_PROTOCOL_TCP || inner_ip->protocol == IP_PROTOCOL_UDP) {
          udp = (udp_header_t *) ip6_next_header(inner_ip);
          offset = vcdp_header_offset(ip, udp, sizeof(*udp));
          k->dport = udp->dst_port;
          k->sport = udp->src_port;
        } else if (inner_ip->protocol == IP_PROTOCOL_ICMP) {
          icmp = (icmp46_header_t *) ip6_next_header(inner_ip);
          echo = (icmp_echo_header_t *) (icmp + 1);
          offset = vcdp_header_offset(ip, echo, sizeof(*echo));
          if (icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply) {
            k->sport = k->dport = echo->identifier;
          } else {
            VCDP_DBG(3, "Failed dealing with ICMP error");
            return -1;
          }
        }
      }
    } else {
      k->sport = k->dport = 0;
    }
    /* calculate hash */
    h[0] = clib_bihash_hash_40_8((clib_bihash_kv_40_8_t *) (k));
  } else {
    ip4_header_t *ip = vcdp_get_ip4_header(b);

    /* Do not support fragmentation for now */
    if (ip4_get_fragment_offset(ip) > 0) {
      return -2;
    }
    vcdp_session_ip4_key_t *k = &skey->ip4;
    k->src = ip->src_address.as_u32;
    k->dst = ip->dst_address.as_u32;
    k->proto = ip->protocol;
    k->context_id = context_id;
    skey->is_ip6 = false;

    if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) {
      udp = (udp_header_t *) (ip + 1);
      offset = vcdp_header_offset(ip, udp, sizeof(*udp));
      k->sport = udp->src_port;
      k->dport = udp->dst_port;
    } else if (ip->protocol == IP_PROTOCOL_ICMP) {
      icmp = (icmp46_header_t *) ip4_next_header(ip);
      echo = (icmp_echo_header_t *) (icmp + 1);
      offset = vcdp_header_offset(ip, echo, sizeof(*echo));
      k->sport = k->dport = 0; // default

      if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
        k->sport = k->dport = echo->identifier;
      } else {
        /* Do the same thing for the inner packet */
        ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);
        offset = vcdp_header_offset(ip, inner_ip, sizeof(*inner_ip));
        // Swap lookup key for ICMP error
        k->dst = inner_ip->src_address.as_u32;
        k->src = inner_ip->dst_address.as_u32;
        k->proto = inner_ip->protocol;
        if (inner_ip->protocol == IP_PROTOCOL_TCP || inner_ip->protocol == IP_PROTOCOL_UDP) {
          udp = (udp_header_t *) ip4_next_header(inner_ip);
          offset = vcdp_header_offset(ip, udp, sizeof(*udp));
          k->dport = udp->src_port;
          k->sport = udp->dst_port;
        } else if (inner_ip->protocol == IP_PROTOCOL_ICMP) {
          icmp = (icmp46_header_t *) ip4_next_header(inner_ip);
          echo = (icmp_echo_header_t *) (icmp + 1);
          offset = vcdp_header_offset(ip, echo, sizeof(*echo));
          if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
            k->sport = k->dport = echo->identifier;
          } else {
            VCDP_DBG(3, "Failed dealing with ICMP error");
            return -1;
          }
        }
      }
    } else {
      k->sport = k->dport = 0;
    }
    /* calculate hash */
    h[0] = clib_bihash_hash_16_8((clib_bihash_kv_16_8_t *) (k));
  }
  if (offset > b->current_length) {
    return -3;
  }
  return 0;
}

#if 0
/*
 * Find the 5-tuple key for the inner packet of an ICMP error
 */
static inline int
vcdp_calc_key_v4_icmp(vlib_buffer_t *b, u32 context_id, vcdp_session_ip4_key_t *skey, u64 *h)
{
  ip4_header_t *ip = vcdp_get_ip4_header(b);
  int offset = 0;
  udp_header_t *udp;
  icmp46_header_t *icmp = (icmp46_header_t *) ip4_next_header(ip);
  icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
  int rv = 0;

  /* Do the same thing for the inner packet */
  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);

  offset = vcdp_header_offset(ip, inner_ip, sizeof(*inner_ip));

  // Swap lookup key for ICMP error
  skey->dst = inner_ip->src_address.as_u32;
  skey->src = inner_ip->dst_address.as_u32;
  skey->proto = inner_ip->protocol;
  switch (inner_ip->protocol) {
  case IP_PROTOCOL_TCP:
    udp = (udp_header_t *) ip4_next_header(inner_ip);
    offset = vcdp_header_offset(ip, udp, sizeof(*udp));
    skey->dport = udp->src_port;
    skey->sport = udp->dst_port;
    break;
  case IP_PROTOCOL_UDP:
    udp = (udp_header_t *) ip4_next_header(inner_ip);
    offset = vcdp_header_offset(ip, udp, sizeof(*udp));
    skey->dport = udp->src_port;
    skey->sport = udp->dst_port;
    break;
  case IP_PROTOCOL_ICMP:
    icmp = (icmp46_header_t *) ip4_next_header(inner_ip);
    echo = (icmp_echo_header_t *) (icmp + 1);
    offset = vcdp_header_offset(ip, echo, sizeof(*echo));
    if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
      skey->sport = skey->dport = echo->identifier;
    } else {
      VCDP_DBG(3, "Failed dealing with ICMP error");
      rv = -1;
    }
    break;
  default:
    skey->sport = skey->dport = 0;
    break;
  }

  if (offset > b->current_length) {
    rv = -1;
  }
  skey->context_id = context_id;

  /* calculate hash */
  h[0] = clib_bihash_hash_16_8((clib_bihash_kv_16_8_t *) (skey));
  return rv;
}
#endif
#endif