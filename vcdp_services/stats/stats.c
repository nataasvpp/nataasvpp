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
  vcdp_stats_main_t *vsm = &vcdp_stats_main;
  vcdp_stats_per_thread_data_t *ptd;
  vec_validate(vsm->ptd, vlib_num_workers());
  vec_foreach (ptd, vsm->ptd)
    vec_validate(ptd->state, vcdp_cfg_main.no_sessions);
  return 0;
};
VLIB_INIT_FUNCTION(vcdp_stats_init);
