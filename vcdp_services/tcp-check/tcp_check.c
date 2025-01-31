// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp_services/tcp-check/tcp_check.h>

vcdp_tcp_check_main_t vcdp_tcp;

static clib_error_t *
vcdp_tcp_check_init(vlib_main_t *vm)
{
  vcdp_tcp_check_main_t *vtcm = &vcdp_tcp;
  vcdp_tcp_check_per_thread_data_t *ptd;
  vec_validate(vtcm->ptd, vlib_num_workers());
  vec_foreach (ptd, vtcm->ptd)
    vec_validate(ptd->state, vcdp_cfg_main.no_sessions);
  return 0;
};

// TODO: Only initialise these data structures when service is enabled
// Consider moving to a sub-block?
VLIB_INIT_FUNCTION(vcdp_tcp_check_init);
