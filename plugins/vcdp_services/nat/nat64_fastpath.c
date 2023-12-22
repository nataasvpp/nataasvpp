// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp_services/nat/nat.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include "rewrite.h"
#include <vcdp_services/nat/nat.api_enum.h>

typedef struct {
  u32 thread_index;
  u32 flow_id;
} vcdp_nat64_fastpath_trace_t;

static u8 *
format_vcdp_nat64_fastpath_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_nat64_fastpath_trace_t *t = va_arg(*args, vcdp_nat64_fastpath_trace_t *);
  nat_main_t *nm = &nat_main;
  nat_per_thread_data_t *ptd = vec_elt_at_index(nm->ptd, t->thread_index);
  nat_rewrite_data_t *rewrite = vec_elt_at_index(ptd->flows, t->flow_id);
  s = format(s, "vcdp-nat64-fastpath: flow-id %u (session %u, %s) rewrite: %U\n", t->flow_id, t->flow_id >> 1,
             t->flow_id & 0x1 ? "reverse" : "forward", format_vcdp_nat64_rewrite, rewrite);

  return s;
}

VCDP_SERVICE_DECLARE(drop)

static_always_inline u16
vcdp_nat64_fastpath_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, bool is_6to4)
{

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;
  nat_main_t *nat = &nat_main;
  u32 thread_index = vlib_get_thread_index();
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  nat_per_thread_data_t *nptd = vec_elt_at_index(nat->ptd, thread_index);
  vcdp_session_t *session;
  u32 session_idx;
  nat64_rewrite_data_t *nat_rewrite;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  vlib_get_buffers(vm, from, bufs, n_left);
  while (n_left > 0) {
    session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    session = vcdp_session_at_index(ptd, session_idx);
    nat_rewrite = vec_elt_at_index(nptd->flows64, b[0]->flow_id); // broken

    if (session->session_version != nat_rewrite->version) {
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      goto end_of_packet;
    }
    nat64_rewrite(b[0], nat_rewrite);

    int dir = vcdp_direction_from_flow_index(b[0]->flow_id);
    vlib_increment_combined_counter(nat->combined_counters + dir, thread_index,
                                    nat_rewrite->nat_idx, 1, vlib_buffer_length_in_chain(vm, b[0]));

  end_of_packet:
    vcdp_next(b[0], to_next);

    n_left -= 1;
    b += 1;
    to_next += 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    n_left = frame->n_vectors;
    for (i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_nat64_fastpath_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->thread_index = thread_index;
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_NODE_FN(vcdp_nat64_early_rewrite_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_nat64_fastpath_inline(vm, node, frame, false);
}

VLIB_NODE_FN(vcdp_nat64_late_rewrite_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_nat64_fastpath_inline(vm, node, frame, true);
}

VLIB_REGISTER_NODE(vcdp_nat64_early_rewrite_node) = {
  .name = "vcdp-nat64-early-rewrite",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_nat64_fastpath_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_NAT64_FASTPATH_N_ERROR,
  .error_counters = vcdp_nat64_fastpath_error_counters,
};

VLIB_REGISTER_NODE(vcdp_nat64_late_rewrite_node) = {
  .name = "vcdp-nat64-late-rewrite",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_nat64_fastpath_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_NAT64_FASTPATH_N_ERROR,
  .error_counters = vcdp_nat64_fastpath_error_counters,
};

VCDP_SERVICE_DEFINE(nat64_late_rewrite) = {
  .node_name = "vcdp-nat64-late-rewrite",
  // .icmp_error = "vcdp-nat64-icmp-error",
  .runs_before = VCDP_SERVICES(0),
  .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle", "vcdp-tcp-check"),
  .is_terminal = 0,
  .format_service = format_vcdp_nat64_service,
};

VCDP_SERVICE_DEFINE(nat64_early_rewrite) = {
  .node_name = "vcdp-nat64-early-rewrite",
  // .icmp_error = "vcdp-nat64-icmp-error",
  .runs_before = VCDP_SERVICES("vcdp-tunnel-output"),
  .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle", "vcdp-tcp-check"),
  .is_terminal = 0,
  .format_service = format_vcdp_nat64_service,
};
