// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_tcp_mss_h
#define included_vcdp_tcp_mss_h

#include <stdbool.h> /* for bool in .api */
#include <vnet/vnet.h>
#include <vcdp/vcdp.h>

int vcdp_tcp_mss_enable_disable(u32 tenant_idx, u16 mss4_forward, u16 mss4_reverse, bool is_enable);

typedef struct {
  /* Maximum segment size per tenant for IPv4/IPv6 */
  u16 *max_mss4_forward;
  u16 *max_mss4_reverse;

  /* API message ID base */
  u16 msg_id_base;
} vcdp_tcp_mss_main_t;

extern vcdp_tcp_mss_main_t vcdp_tcp_mss_main;

#define MSS_CLAMP_UNSET 0xffff

#endif
