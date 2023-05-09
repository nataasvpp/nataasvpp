// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/service.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/load_balance.h>

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
  VCDP_BYPASS_NEXT_DROP,
  VCDP_BYPASS_NEXT_LOOKUP,
  VCDP_BYPASS_NEXT_RECEIVE,
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

/*
 * Bypass the session layer.
 * If packet destination address matches the NAT pool address, drop the packet,
 * unless it's a local interface address. Then send it to the ip4-receive node.
 */

VLIB_NODE_FN(vcdp_bypass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *from;
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE] = {0}, *next = nexts;
  // const dpo_id_t *dpo;
  // load_balance_t *lb;
  // u32 lbi;

  from = vlib_frame_vector_args(frame);
  vlib_get_buffers(vm, from, b, n_left);

  while (n_left > 0) {
    // TODO: What if the packet does not come along a feature chain???
    // Send directly to lookup. Note this breaks the feature chain.
    // vnet_feature_next_u16(next, b[0]);
    next[0] = VCDP_BYPASS_NEXT_LOOKUP;

    // ip4_header_t *ip = vlib_buffer_get_current(b[0]);
    // u32 lbi = ip4_fib_forwarding_lookup(vnet_buffer(b)->ip.fib_index, &ip0->src_address);
    // TODO: Fix VRF
#if 0
    lbi = ip4_fib_forwarding_lookup(0, &ip->dst_address);
    lb = load_balance_get(lbi);
    dpo = load_balance_get_bucket_i(lb, 0);
    if (dpo->dpoi_type == vcdp_nat_dpo_type) { // matches pool
      // Drop packet
      next[0] = VCDP_BYPASS_NEXT_DROP;
      b[0]->error = node->errors[VCDP_BYPASS_ERROR_BYPASS];
     } else if (dpo->dpoi_type == vcdp_nat_if_dpo_type) { // matches interface pool
      next[0] = VCDP_BYPASS_NEXT_RECEIVE;
     }    
#endif

    b[0]->error = 0;
    next += 1;
    n_left -= 1;
    b += 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter(vm, node->node_index, VCDP_BYPASS_ERROR_BYPASS, n_left);
  n_left = frame->n_vectors;
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
  .next_nodes = { "error-drop", "ip4-lookup", "ip4-receive" }
};

VCDP_SERVICE_DEFINE(bypass) = {
  .node_name = "vcdp-bypass", 
  .runs_before = VCDP_SERVICES(0), 
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 1
};