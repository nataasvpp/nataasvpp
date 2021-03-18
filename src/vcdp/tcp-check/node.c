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

#define foreach_vcdp_tcp_check_error _ (DROP, "drop")

typedef enum
{
#define _(sym, str) VCDP_TCP_CHECK_ERROR_##sym,
  foreach_vcdp_tcp_check_error
#undef _
    VCDP_TCP_CHECK_N_ERROR,
} vcdp_tcp_check_error_t;

static char *vcdp_tcp_check_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_tcp_check_error
#undef _
};

#define foreach_vcdp_tcp_check_next _ (DROP, "error-drop")

typedef enum
{
#define _(n, x) VCDP_TCP_CHECK_NEXT_##n,
  foreach_vcdp_tcp_check_next
#undef _
    VCDP_TCP_CHECK_N_NEXT
} vcdp_tcp_check_next_t;

typedef struct
{
  u32 flow_id;
} vcdp_tcp_check_trace_t;

static u8 *
format_vcdp_tcp_check_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_tcp_check_trace_t *t = va_arg (*args, vcdp_tcp_check_trace_t *);

  s = format (s, "vcdp-tcp-check: flow-id %u (session %u, %s)", t->flow_id,
	      t->flow_id >> 1, t->flow_id & 0x1 ? "backward" : "forward");
  return s;
}

VLIB_NODE_FN (vcdp_tcp_check_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_buffer_enqueue_to_single_next (vm, node, from, VCDP_TCP_CHECK_NEXT_DROP,
				      n_left);
  vlib_node_increment_counter (vm, node->node_index, VCDP_TCP_CHECK_ERROR_DROP,
			       n_left);
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      vlib_get_buffers (vm, from, bufs, n_left);
      b = bufs;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vcdp_tcp_check_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      b++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (vcdp_tcp_check_node) = {
  .name = "vcdp-tcp-check",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_tcp_check_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_tcp_check_error_strings),
  .error_strings = vcdp_tcp_check_error_strings,

  .n_next_nodes = VCDP_TCP_CHECK_N_NEXT,
  .next_nodes = {
#define _(n, x) [VCDP_TCP_CHECK_NEXT_##n] = x,
          foreach_vcdp_tcp_check_next
#undef _
  }

};