// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp_services/tcp-check-lite/tcp_check_lite.h>
#include <vcdp/service.h>

#include "node.h"

#define foreach_vcdp_tcp_check_lite_error _(DROP, "drop")

typedef enum {
#define _(sym, str) VCDP_TCP_CHECK_ERROR_##sym,
  foreach_vcdp_tcp_check_lite_error
#undef _
    VCDP_TCP_CHECK_N_ERROR,
} vcdp_tcp_check_lite_error_t;

static char *vcdp_tcp_check_lite_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_tcp_check_lite_error
#undef _
};

VLIB_NODE_FN(vcdp_tcp_check_lite_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_tcp_check_lite_node_inline(vm, node, frame);
}

VLIB_REGISTER_NODE(vcdp_tcp_check_lite_node) = {.name = "vcdp-tcp-check-lite",
                                           .vector_size = sizeof(u32),
                                           .format_trace = format_vcdp_tcp_check_lite_trace,
                                           .type = VLIB_NODE_TYPE_INTERNAL,

                                           .n_errors = ARRAY_LEN(vcdp_tcp_check_lite_error_strings),
                                           .error_strings = vcdp_tcp_check_lite_error_strings,
                                           .sibling_of = "vcdp-lookup-ip4"

};

VCDP_SERVICE_DEFINE(tcp_check_lite) = {.node_name = "vcdp-tcp-check-lite",
                                  .runs_before = VCDP_SERVICES(0),
                                  .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle"),
                                  .is_terminal = 0};