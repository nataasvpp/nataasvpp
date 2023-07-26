// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_tcp_check_lite_h
#define included_vcdp_tcp_check_lite_h

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>

/* TCP session state */
typedef enum {
  VCDP_TCP_CHECK_LITE_STATE_CLOSED = 0,
  VCDP_TCP_CHECK_LITE_STATE_ESTABLISHED,
  VCDP_TCP_CHECK_LITE_STATE_CLOSING,
} vcdp_tcp_check_lite_tcp_state_t;

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  u8 flags[VCDP_FLOW_F_B_N];
  vcdp_tcp_check_lite_tcp_state_t state;
  session_version_t version;
} vcdp_tcp_check_lite_session_state_t;

typedef struct {
  vcdp_tcp_check_lite_session_state_t *state; /* vec indexed by session-index */
} vcdp_tcp_check_lite_per_thread_data_t;

typedef struct {
  vcdp_tcp_check_lite_per_thread_data_t *ptd;
} vcdp_tcp_check_lite_main_t;

extern vcdp_tcp_check_lite_main_t vcdp_tcp_lite;

format_function_t format_vcdp_tcp_lite_service_session;

#endif