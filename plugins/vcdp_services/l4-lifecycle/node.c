// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vcdp/service.h>
#include <vcdp_services/l4-lifecycle/l4_lifecycle.api_enum.h>

typedef struct {
  u32 flow_id;
  u8 new_state;
} vcdp_l4_lifecycle_trace_t;

static u8 *
format_vcdp_l4_lifecycle_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_l4_lifecycle_trace_t *t = va_arg(*args, vcdp_l4_lifecycle_trace_t *);

  s = format(s, "vcdp-l4-lifecycle: flow-id %u (session %u, %s) new_state: %U", t->flow_id, t->flow_id >> 1,
             t->flow_id & 0x1 ? "reverse" : "forward", format_vcdp_session_state, t->new_state);
  return s;
}

VLIB_NODE_FN(vcdp_l4_lifecycle_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;

  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);

  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers(vm, from, bufs, n_left);
  f64 time_now = vlib_time_now(vm);

  while (n_left) {
    u32 session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    u16 tenant_idx = vcdp_buffer(b[0])->tenant_index;
    vcdp_session_t *session = vcdp_session_at_index(ptd, session_idx);
    vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
    u8 direction = vcdp_direction_from_flow_index(b[0]->flow_id);
    /* TODO: prefetch, 4-loop, remove ifs and do state-transition-timer LUT?
     */
    if (session->state == VCDP_SESSION_STATE_FSOL && direction == VCDP_FLOW_REVERSE)
      /*Establish the session*/
      session->state = VCDP_SESSION_STATE_ESTABLISHED;

    if (session->state == VCDP_SESSION_STATE_ESTABLISHED) {
      vcdp_session_timer_update(&ptd->wheel, &session->timer, time_now,
                                tenant->timeouts[VCDP_TIMEOUT_ESTABLISHED]);
    }

    vcdp_next(b[0], to_next);

    b++;
    to_next++;
    n_left--;
  }

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    n_left = frame->n_vectors;
    b = bufs;
    for (int i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_l4_lifecycle_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        u32 session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
        vcdp_session_t *session = vcdp_session_at_index(ptd, session_idx);
        u16 state = session->state;
        t->flow_id = b[0]->flow_id;
        t->new_state = state;
        b++;
      } else
        break;
    }
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_l4_lifecycle_node) = {
  .name = "vcdp-l4-lifecycle",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_l4_lifecycle_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_L4_LIFECYCLE_N_ERROR,
  .error_counters = vcdp_l4_lifecycle_error_counters,
  .sibling_of = "vcdp-lookup-ip4"

};

VCDP_SERVICE_DEFINE(l4_lifecycle) = {.node_name = "vcdp-l4-lifecycle",
                                     .runs_before = VCDP_SERVICES(0),
                                     .runs_after = VCDP_SERVICES("vcdp-drop"),
                                     .is_terminal = 0};