// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/service.h>
#include <vnet/feature/feature.h>

#define foreach_vcdp_bypass_error _(BYPASS, "bypass")

typedef enum {
#define _(sym, str) VCDP_BYPASS_ERROR_##sym,
  foreach_vcdp_bypass_error
#undef _
    VCDP_BYPASS_N_ERROR,
} vcdp_bypass_error_t;

static char *vcdp_bypass_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_bypass_error
#undef _
};

typedef enum {
  VCDP_BYPASS_NEXT_LOOKUP,
  VCDP_BYPASS_N_NEXT
} vcdp_bypass_next_t;

typedef struct {
  u32 flow_id;
} vcdp_bypass_trace_t;

static u8 *
format_vcdp_bypass_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_bypass_trace_t *t = va_arg(*args, vcdp_bypass_trace_t *);

  s = format(s, "vcdp-bypass: flow-id %u (session %u, %s)", t->flow_id, t->flow_id >> 1,
             t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

VLIB_NODE_FN(vcdp_bypass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 n_left_from, *from;
  u32 n_left = frame->n_vectors;
  // u16 nexts[VLIB_FRAME_SIZE] = {0}, *next = nexts;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers(vm, from, b, n_left_from);
#if 0
  while (n_left_from > 0) {
    /* By default pass packet to next node in the feature chain */
    vnet_feature_next_u16(next, b[0]);
    b[0]->error = 0;
    next += 1;
    n_left_from -= 1;
    b += 1;
  }
#endif
  vlib_buffer_enqueue_to_single_next(vm, node, from, VCDP_BYPASS_NEXT_LOOKUP, n_left);

  // vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);
  vlib_node_increment_counter(vm, node->node_index, VCDP_BYPASS_ERROR_BYPASS, n_left);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    vlib_get_buffers(vm, from, bufs, n_left);
    b = bufs;
    for (i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_bypass_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_bypass_node) = {
  .name = "vcdp-bypass",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_bypass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_bypass_error_strings),
  .error_strings = vcdp_bypass_error_strings,
  .n_next_nodes = VCDP_BYPASS_N_NEXT,
  .next_nodes = { "ip4-lookup" }
};

VCDP_SERVICE_DEFINE(bypass) = {
  .node_name = "vcdp-bypass", 
  .runs_before = VCDP_SERVICES(0), 
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 1
};