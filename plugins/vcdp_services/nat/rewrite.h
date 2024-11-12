// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef nat_rewrite_h
#define nat_rewrite_h

#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include "nat.h"
#include <vnet/ip/ip4_to_ip6.h>
#include <vnet/ip/ip6_to_ip4.h>

static inline void
nat_rewrite(ip4_header_t *ip4, nat_rewrite_data_t *rewrite)
{
  ip_csum_t ip_sum = 0, tcp_sum = 0, udp_sum = 0, icmp_sum = 0;
//   u8 proto = rewrite->rewrite.proto;
  u8 proto = ip4->protocol;
  tcp_header_t *tcp;
  udp_header_t *udp;
  icmp46_header_t *icmp;
  u16 *icmp_id;
  u32 ops = rewrite->ops;

#if VCDP_DEBUG > 0
  bool checksum_valid = true;
  if (ip4->checksum != ip4_header_checksum(ip4)) {
    clib_warning("Checksum generation error in PRE NAT %U", format_ip4_header, ip4, 32);
    checksum_valid = false;
  }
#endif

  ip_sum = ip4->checksum;
  ip_sum = ip_csum_sub_even(ip_sum, rewrite->l3_csum_delta);
  ip_sum = ip_csum_fold(ip_sum);
  ip4->checksum = ip_sum;
  if (ip4->checksum == 0xffff)
    ip4->checksum = 0;

  if (ops & NAT_REWRITE_OP_SADDR)
    ip4->src_address = rewrite->rewrite.saddr;

  if (ops & NAT_REWRITE_OP_DADDR)
    ip4->dst_address = rewrite->rewrite.daddr;

  if (proto == IP_PROTOCOL_TCP) {
    tcp = (tcp_header_t *)ip4_next_header(ip4);
    tcp_sum = tcp->checksum;
    tcp_sum = ip_csum_sub_even(tcp_sum, rewrite->l3_csum_delta);
    tcp_sum = ip_csum_sub_even(tcp_sum, rewrite->l4_csum_delta);
    tcp_sum = ip_csum_fold(tcp_sum);
    tcp->checksum = tcp_sum;
    if (tcp->checksum == 0xffff)
      tcp->checksum = 0;

    if (ops & NAT_REWRITE_OP_SPORT)
      tcp->src_port = rewrite->rewrite.sport;

    if (ops & NAT_REWRITE_OP_DPORT)
      tcp->dst_port = rewrite->rewrite.dport;
  } else if (proto == IP_PROTOCOL_UDP) {
    udp = (udp_header_t *)ip4_next_header(ip4);
    udp_sum = udp->checksum;
    udp_sum = ip_csum_sub_even(udp_sum, rewrite->l3_csum_delta);
    udp_sum = ip_csum_sub_even(udp_sum, rewrite->l4_csum_delta);
    udp_sum = ip_csum_fold(udp_sum);
    udp->checksum = udp_sum;
    if (udp->checksum == 0xffff)
      udp->checksum = 0;

    if (ops & NAT_REWRITE_OP_SPORT)
      udp->src_port = rewrite->rewrite.sport;

    if (ops & NAT_REWRITE_OP_DPORT)
      udp->dst_port = rewrite->rewrite.dport;
  } else if (proto == IP_PROTOCOL_ICMP) {
    icmp = ip4_next_header(ip4);
    if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply) {
      icmp_sum = icmp->checksum;
      icmp_id = (u16 *) (icmp + 1);
      icmp_sum = ip_csum_sub_even(icmp_sum, rewrite->l4_csum_delta);
      icmp_sum = ip_csum_fold(icmp_sum);
      icmp->checksum = icmp_sum;
      if (ops & NAT_REWRITE_OP_ICMP_ID)
        *icmp_id = rewrite->rewrite.icmp_id;
    }
  } else {
    /*FIXME:, must be done at the beginning!*/
    // vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
    // b[0]->error = node->errors[UNSUPPORTED_PROTOCOL]
    // goto end_of_packet;
  }
#if VCDP_DEBUG > 0
  if (checksum_valid && (ip4->checksum != ip4_header_checksum(ip4))) {
    clib_warning("Checksum generation error in NAT %U", format_ip4_header, ip4, sizeof(*ip4));
  }
#endif
}

static inline void
nat_rewrite_outer(ip4_header_t *ip4, nat_rewrite_data_t *rewrite)
{
  u32 ops = rewrite->ops;
  if (ops & NAT_REWRITE_OP_SADDR)
    ip4->src_address = rewrite->rewrite.saddr;
  if (ops & NAT_REWRITE_OP_DADDR)
    ip4->dst_address = rewrite->rewrite.daddr;
  ip4->checksum = ip4_header_checksum(ip4);
}

static inline void
nat64_rewrite_outer(ip4_header_t *ip4, nat64_rewrite_data_t *rewrite)
{
#if 0
  u32 ops = rewrite->ops;
  if (ops & NAT_REWRITE_OP_SADDR)
    ip4->src_address = rewrite->rewrite.saddr;
  if (ops & NAT_REWRITE_OP_DADDR)
    ip4->dst_address = rewrite->rewrite.daddr;
  ip4->checksum = ip4_header_checksum(ip4);
#endif
}

#if 0
static int
nat64_inner_icmp_set_cb(ip6_header_t *ip6, ip4_header_t *ip4, void *arg)
{
  return 0;
}
static int
nat64_icmp_set_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
  return 0;
}
#endif

/*
 * Rewrite an IPv4 packet to an IPv6 packet and vice versa
 */
static inline void
nat64_rewrite(vlib_buffer_t *b, nat64_rewrite_data_t *rewrite)
{
  u8 protocol;
  void *ulp;
  ip6_header_t *ip6;
  ip4_header_t *ip4;
  vlib_main_t *vm = vlib_get_main();

  if (rewrite->ops & NAT64_REWRITE_OP_HDR_64) {
    // Copy out the pieces I need from the IPv6 header
    ip6 = vlib_buffer_get_current(b);
    protocol = ip6->protocol;
    u16 payload_length = clib_net_to_host_u16(ip6->payload_length);
    u8 ttl = ip6->hop_limit;
    // Set IPv4 header
    vlib_buffer_advance(b, 20);
    ip4 = vlib_buffer_get_current(b);
    ASSERT((u8 *)ip4 - (u8 *)ip6 == 20);
    clib_memcpy(ip4, &rewrite->ip4, sizeof(ip4_header_t));
    ip4->ttl = ttl;
    ip4->length = clib_host_to_net_u16(payload_length + sizeof(ip4_header_t));
    ip4->checksum = ip4_header_checksum(ip4);
    ulp = ip4 + 1;
    ASSERT((u8 *) ulp - (u8 *) ip6 == 40);
  } else if (rewrite->ops & NAT64_REWRITE_OP_HDR_46) {
    ip4 = vlib_buffer_get_current(b);
    protocol = ip4->protocol;
    ASSERT(protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP || protocol == IP_PROTOCOL_ICMP);

    u8 ttl = ip4->ttl;
    u16 payload_length = clib_net_to_host_u16(ip4->length) - sizeof(ip4_header_t);

    // Set IPv6 header
    vlib_buffer_advance(b, -20);
    ip6 = vlib_buffer_get_current(b);
    clib_memcpy(ip6, &rewrite->ip6, sizeof(ip6_header_t));
    ip6->hop_limit = ttl;
    ip6->payload_length = clib_host_to_net_u16(payload_length);
    ulp = ip6 + 1;
  } else {
    ASSERT(0);
  }

  // TCP checksum (and port)
  if (protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = ulp;
    tcp->checksum = 0;
    if (rewrite->ops & NAT64_REWRITE_OP_SPORT)
      tcp->src_port = rewrite->sport;
    if (rewrite->ops & NAT64_REWRITE_OP_DPORT)
      tcp->dst_port = rewrite->dport;
    if (rewrite->ops & NAT64_REWRITE_OP_HDR_64)
      tcp->checksum = ip4_tcp_udp_compute_checksum(vm, b, ip4);
    else {
      int length;
      tcp->checksum = ip6_tcp_udp_icmp_compute_checksum(vm, b, ip6, &length);
    }
  } else if (protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = ulp;
    udp->checksum = 0;
    if (rewrite->ops & NAT64_REWRITE_OP_SPORT)
      udp->src_port = rewrite->sport;
    if (rewrite->ops & NAT64_REWRITE_OP_DPORT)
      udp->dst_port = rewrite->dport;
    if (rewrite->ops & NAT64_REWRITE_OP_HDR_64)
      udp->checksum = ip4_tcp_udp_compute_checksum(vm, b, ip4);
    else {
      int length;
      udp->checksum = ip6_tcp_udp_icmp_compute_checksum(vm, b, ip6, &length);
    }
  } else if (protocol == IP_PROTOCOL_ICMP6) {
    // if (icmp6_to_icmp(vm, b, nat64_in2out_icmp_set_cb, &ctx0, nat64_in2out_inner_icmp_set_cb, &ctx0))
    icmp46_header_t *icmp = ulp;
    ip6_header_t *inner_ip6;
    if (icmp6_to_icmp_header(icmp, &inner_ip6)) {
      vcdp_log_info("icmp6_to_icmp_header failed %U", format_ip6_header, ip6, 40);
      return;
    }
    if (rewrite->ops & NAT64_REWRITE_OP_SPORT) {
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      echo->identifier = rewrite->sport;
    }

    // int rv = icmp6_to_icmp(vm, b, nat64_icmp_set_cb, 0, nat64_inner_icmp_set_cb, 0);
    // clib_warning("translate icmp6 to icmp %d", rv);
    // icmp46_header_t *icmp = ulp;
    // icmp->type = ICMP4_echo_request;
    icmp->checksum = 0;
    ip_csum_t sum = ip_incremental_checksum(0, icmp, b->current_length - sizeof(ip4_header_t));
    icmp->checksum = ~ip_csum_fold(sum);
  } else if (protocol == IP_PROTOCOL_ICMP) {
    icmp46_header_t *icmp = ulp;
    ip4_header_t *inner_ip4;
    if (icmp_to_icmp6_header(icmp, &inner_ip4)) {
      vcdp_log_info("icmp_to_icmp6_header failed %U", format_ip4_header, ip4, 20);
      return;
    }
    if (rewrite->ops & NAT64_REWRITE_OP_DPORT) {
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      echo->identifier = rewrite->sport;
    }
    int length;
    icmp->checksum = 0;
    icmp->checksum = ip6_tcp_udp_icmp_compute_checksum(vm, b, ip6, &length);
  } else {
    // Pass any other protocol unharmed.
    ;
  }
}

#endif