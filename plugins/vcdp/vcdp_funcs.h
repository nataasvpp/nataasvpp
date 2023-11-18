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

#endif
