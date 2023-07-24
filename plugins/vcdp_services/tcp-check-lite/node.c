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

VCDP_SERVICE_DEFINE(tcp_check_lite) = {
  .node_name = "vcdp-tcp-check-lite",
  .runs_before = VCDP_SERVICES(0),
  .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle"),
  .is_terminal = 0,
  .format_session = format_vcdp_tcp_lite_service_session,
};