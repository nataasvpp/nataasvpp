// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp_services/tcp-check-lite/tcp_check_lite.h>
#include <vcdp/service.h>
#include <vcdp_services/tcp-check-lite/tcp_check_lite.api_enum.h>
#include "node.h"

VLIB_NODE_FN(vcdp_tcp_check_lite_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_tcp_check_lite_node_inline(vm, node, frame);
}

VLIB_REGISTER_NODE(vcdp_tcp_check_lite_node) = {
  .name = "vcdp-tcp-check-lite",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_tcp_check_lite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_TCP_CHECK_LITE_N_ERROR,
  .error_counters = vcdp_tcp_check_lite_error_counters,
  .sibling_of = "vcdp-lookup-ip4"

};

static u8 *
format_vcdp_tcp_check_lite_state (u8 *s, va_list *args)
{
  u32 state = va_arg(*args, u32);
  switch (state) {
    case VCDP_TCP_CHECK_LITE_STATE_CLOSED:
      return format(s, "CLOSED");
    case VCDP_TCP_CHECK_LITE_STATE_ESTABLISHED:
      return format(s, "ESTABLISHED");
    case VCDP_TCP_CHECK_LITE_STATE_CLOSING:
      return format(s, "CLOSING");
      default:
        break;
  }
  return format(s, "unknown");
}

static u8 *
format_vcdp_tcp_check_lite_service(u8 *s, u32 thread_index, u32 session_index)
{
  vcdp_tcp_check_lite_main_t *vtcm = &vcdp_tcp_lite;
  vcdp_tcp_check_lite_per_thread_data_t *tptd = vec_elt_at_index(vtcm->ptd, thread_index);
  vcdp_tcp_check_lite_session_state_t *tcp_session = vec_elt_at_index(tptd->state, session_index);

  s = format(s, "tcp-check-lite: flags: %U/%U\n%16sstate: %U\n", format_tcp_flags, tcp_session->flags[VCDP_FLOW_FORWARD],
             format_tcp_flags, tcp_session->flags[VCDP_FLOW_REVERSE], "", format_vcdp_tcp_check_lite_state, tcp_session->state);
  return s;
}

VCDP_SERVICE_DEFINE(tcp_check_lite) = {
  .node_name = "vcdp-tcp-check-lite",
  .runs_before = VCDP_SERVICES(0),
  .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle"),
  .is_terminal = 0,
  .is_tcp_specific = 1,
  .format_service = format_vcdp_tcp_check_lite_service,
};