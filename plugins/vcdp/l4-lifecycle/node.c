/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vcdp/service.h>
#define foreach_vcdp_l4_lifecycle_error _ (DROP, "drop")

typedef enum
{
#define _(sym, str) VCDP_L4_LIFECYCLE_ERROR_##sym,
  foreach_vcdp_l4_lifecycle_error
#undef _
    VCDP_L4_LIFECYCLE_N_ERROR,
} vcdp_l4_lifecycle_error_t;

static char *vcdp_l4_lifecycle_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_l4_lifecycle_error
#undef _
};

typedef struct
{
  u32 flow_id;
  u8 new_state;
} vcdp_l4_lifecycle_trace_t;

static u8 *
format_vcdp_l4_lifecycle_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_l4_lifecycle_trace_t *t = va_arg (*args, vcdp_l4_lifecycle_trace_t *);

  s = format (
    s, "vcdp-l4-lifecycle: flow-id %u (session %u, %s) new_state: %U",
    t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward",
    format_vcdp_session_state, t->new_state);
  return s;
}

VLIB_NODE_FN (vcdp_l4_lifecycle_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;

  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd =
    vec_elt_at_index (vcdp->per_thread_data, thread_index);

  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left)
    {
      u32 session_idx = vcdp_session_from_flow_index (b[0]->flow_id);
      u16 tenant_idx = vcdp_buffer (b[0])->tenant_index;
      vcdp_session_t *session = vcdp_session_at_index (ptd, session_idx);
      vcdp_tenant_t *tenant = vcdp_tenant_at_index (vcdp, tenant_idx);
      u8 direction = vcdp_direction_from_flow_index (b[0]->flow_id);
      /* TODO: prefetch, 4-loop, remove ifs and do state-transition-timer LUT?
       */
      if (session->proto == IP_PROTOCOL_TCP)
	{
	  session->bitmaps[VCDP_FLOW_FORWARD] &=
	    ~(1 << VCDP_SERVICE_L4_LIFECYCLE);
	  session->bitmaps[VCDP_FLOW_REVERSE] &=
	    ~(1 << VCDP_SERVICE_L4_LIFECYCLE);
	  vcdp_buffer (b[0])->service_bitmap |= (1 << VCDP_SERVICE_TCP_CHECK);
	  session->bitmaps[VCDP_FLOW_FORWARD] |= (1 << VCDP_SERVICE_TCP_CHECK);
	  session->bitmaps[VCDP_FLOW_REVERSE] |= (1 << VCDP_SERVICE_TCP_CHECK);
	}
      else
	{
	  if (session->state == VCDP_SESSION_STATE_FSOL &&
	      direction == VCDP_FLOW_REVERSE)
	    /*Establish the session*/
	    session->state = VCDP_SESSION_STATE_ESTABLISHED;

	  if (session->state == VCDP_SESSION_STATE_ESTABLISHED)
	    {
	      /* TODO: must be configurable per tenant */
	      vcdp_session_timer_update (
		&ptd->wheel, &session->timer, ptd->current_time,
		tenant->timeouts[VCDP_TIMEOUT_ESTABLISHED]);
	    }
	}
      vcdp_next (b[0], to_next);

      b++;
      to_next++;
      n_left--;
    }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      n_left = frame->n_vectors;
      b = bufs;
      for (int i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vcdp_l4_lifecycle_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      u32 session_idx = vcdp_session_from_flow_index (b[0]->flow_id);
	      vcdp_session_t *session =
		vcdp_session_at_index (ptd, session_idx);
	      u16 state = session->state;
	      t->flow_id = b[0]->flow_id;
	      t->new_state = state;
	      b++;
	    }
	  else
	    break;
	}
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (vcdp_l4_lifecycle_node) = {
  .name = "vcdp-l4-lifecycle",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_l4_lifecycle_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_l4_lifecycle_error_strings),
  .error_strings = vcdp_l4_lifecycle_error_strings,

  .sibling_of = "vcdp-lookup"

};