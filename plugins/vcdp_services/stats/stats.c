// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include "stats.h"

vcdp_stats_main_t vcdp_stats_main;

// packet size to histogram bin
static inline u32
vcdp_stats_packet_size_to_bin(u32 packet_size)
{
  u32 bin = 0;
  while (packet_size > 0) {
    packet_size >>= 1;
    bin++;
  }
  return bin;
}


clib_error_t *
vcdp_stats_init(vlib_main_t *vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main();
  vcdp_stats_main_t *vsm = &vcdp_stats_main;
  vcdp_stats_per_thread_data_t *ptd;
  vec_validate(vsm->ptd, tm->n_vlib_mains - 1);
  vec_foreach (ptd, vsm->ptd)
    vec_validate(ptd->state, vcdp_cfg_main.no_sessions_per_thread);
  return 0;
};
VLIB_INIT_FUNCTION(vcdp_stats_init);
