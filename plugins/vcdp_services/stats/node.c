// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include "stats.h"
#include <vcdp/service.h>
#include <vcdp_services/stats/stats.api_enum.h>

uword
vcdp_stats_node_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_stats_main_t *vsm = &vcdp_stats_main;
  u32 thread_index = vlib_get_thread_index();
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vcdp_stats_per_thread_data_t *sptd = vec_elt_at_index(vsm->ptd, thread_index);
  vcdp_session_t *session;
  u32 session_idx;
  vcdp_stats_session_state_t *stats_session;

  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  //   f64 current_time = ptd->current_time;

  vlib_get_buffers(vm, from, bufs, n_left);
  while (n_left > 0) {
    session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    session = vcdp_session_at_index(ptd, session_idx);
    stats_session = vec_elt_at_index(sptd->state, session_idx);

    if (stats_session->version != session->session_version) {
      clib_warning("Change in session version");
    }

    vcdp_next(b[0], to_next);

    n_left -= 1;
    b += 1;
    to_next += 1;
  }
  return frame->n_vectors;
}

VLIB_NODE_FN(vcdp_stats_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
     return vcdp_stats_node_inline(vm, node, frame);
}

VLIB_REGISTER_NODE(vcdp_stats_node) = {
  .name = "vcdp-stats",
  .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_STATS_N_ERROR,
  .error_counters = vcdp_stats_error_counters
};

VCDP_SERVICE_DEFINE(vcdp_stats) = {
  .node_name = "vcdp-stats",
  .runs_before = VCDP_SERVICES("vcdp-l4-lifecycle"),
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 0
};