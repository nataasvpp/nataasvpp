// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp_services/tcp-check-lite/tcp_check_lite.h>

vcdp_tcp_check_lite_main_t vcdp_tcp_lite;

clib_error_t *
vcdp_tcp_check_lite_init(vlib_main_t *vm)
{
  vcdp_tcp_check_lite_main_t *vtcm = &vcdp_tcp_lite;
  vec_validate(vtcm->state, vcdp_cfg_main.no_sessions);
  return 0;
};
VLIB_INIT_FUNCTION(vcdp_tcp_check_lite_init);
