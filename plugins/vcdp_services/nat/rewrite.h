// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef nat_rewrite_h
#define nat_rewrite_h

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
    tcp = ip4_next_header(ip4);
    tcp_sum = tcp->checksum;
    tcp_sum = ip_csum_sub_even(tcp_sum, rewrite->l3_csum_delta);
    tcp_sum = ip_csum_sub_even(tcp_sum, rewrite->l4_csum_delta);
    tcp_sum = ip_csum_fold(tcp_sum);
    tcp->checksum = tcp_sum;

    if (ops & NAT_REWRITE_OP_SPORT)
      tcp->src_port = rewrite->rewrite.sport;

    if (ops & NAT_REWRITE_OP_DPORT)
      tcp->dst_port = rewrite->rewrite.dport;
  } else if (proto == IP_PROTOCOL_UDP) {
    udp = ip4_next_header(ip4);
    udp_sum = udp->checksum;
    udp_sum = ip_csum_sub_even(udp_sum, rewrite->l3_csum_delta);
    udp_sum = ip_csum_sub_even(udp_sum, rewrite->l4_csum_delta);
    udp_sum = ip_csum_fold(udp_sum);
    udp->checksum = udp_sum;

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
  // ASSERT(ip4->checksum == ip4_header_checksum(ip4));
}

#endif