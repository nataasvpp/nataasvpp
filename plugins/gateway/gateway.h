// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_gateway_h
#define included_gateway_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vcdp/vcdp.h>

typedef struct {
  u16 msg_id_base;

  u16 *tenant_idx_by_sw_if_idx; /* vec */
} gw_main_t;

extern gw_main_t gateway_main;

int gw_interface_input_enable_disable(u32 sw_if_index, u32 tenant_id, bool output_arc, bool is_enable);
int gw_prefix_input_enable_disable(u32 fib_prefix, ip_prefix_t *prefix, u32 tenant_id, bool is_forward, bool is_enable);

#endif /* included_gateway_h */
