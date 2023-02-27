// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_stats_h
#define included_vcdp_stats_h

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>

// Histogram
typedef struct {
    u32 *bins;
    u32 n_bins;
    u32 n_samples;
    u32 min;
    u32 max;
} histogram_t;

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  session_version_t version;
  f64 start_time;
  f64 last_update;
  histogram_t *packet_sizes;
  histogram_t *session_lifetimes;
} vcdp_stats_session_state_t;

typedef struct {
  vcdp_stats_session_state_t *state; /* vec indexed by session-index */
} vcdp_stats_per_thread_data_t;

typedef struct {
  vcdp_stats_per_thread_data_t *ptd;
} vcdp_stats_main_t;

extern vcdp_stats_main_t vcdp_stats_main;

#endif