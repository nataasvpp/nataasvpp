// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp_services/tcp-check-lite/tcp_check_lite.h>

vcdp_tcp_check_lite_main_t vcdp_tcp_lite;

clib_error_t *
vcdp_tcp_check_lite_init(vlib_main_t *vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main();
  vcdp_tcp_check_lite_main_t *vtcm = &vcdp_tcp_lite;
  vcdp_tcp_check_lite_per_thread_data_t *ptd;
  vec_validate(vtcm->ptd, tm->n_vlib_mains - 1);
  vec_foreach (ptd, vtcm->ptd)
    vec_validate(ptd->state, vcdp_cfg_main.no_sessions_per_thread);
  return 0;
};
VLIB_INIT_FUNCTION(vcdp_tcp_check_lite_init);
