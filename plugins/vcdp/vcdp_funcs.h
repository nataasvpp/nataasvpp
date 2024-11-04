// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_funcs_h
#define included_vcdp_funcs_h
#include <vcdp/vcdp.h>


static inline ip4_header_t *
vcdp_get_ip4_header(vlib_buffer_t *b)
{
  return vlib_buffer_get_current(b) + vnet_buffer(b)->ip.save_rewrite_length;
}

static inline ip6_header_t *
vcdp_get_ip6_header(vlib_buffer_t *b)
{
  return vlib_buffer_get_current(b) + vnet_buffer(b)->ip.save_rewrite_length;
}

/* TODO: Fix this so it works in all cases */
static inline u16
vcdp_get_l3_length (vlib_main_t *vm, vlib_buffer_t *b)
{
  // int l3_offset = (void *)b->data - vlib_buffer_get_current(b) + vnet_buffer(b)->ip.save_rewrite_length;
  // return vlib_buffer_length_in_chain(vm, b) - l3_offset;
  // return vlib_buffer_length_in_chain(vm, b) - (vnet_buffer(b)->l3_hdr_offset - b->current_data);
  return vlib_buffer_length_in_chain(vm, b);
}

#endif
