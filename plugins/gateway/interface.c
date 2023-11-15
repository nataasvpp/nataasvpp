// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

// Get packets from the IP unicast input feature arc set tenant and pass them to
// VCDP.

#include <vlib/vlib.h>
#include <vnet/fib/fib_table.h>
#include <vnet/feature/feature.h>
#include <vcdp/vcdp.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vcdp/vcdp_funcs.h>
#include "gateway.h"

enum vcdp_input_next_e {
   VCDP_GW_NEXT_LOOKUP,
   VCDP_GW_NEXT_IP4_LOOKUP,
   VCDP_GW_NEXT_ICMP_ERROR,
   VCDP_GW_N_NEXT
};

typedef struct {
  u16 tenant_index;
} vcdp_input_trace_t;

static inline u8 *
format_vcdp_input_trace(u8 *s, va_list *args)
{
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  vcdp_input_trace_t *t = va_arg(*args, vcdp_input_trace_t *);

  s = format(s, "vcdp-input: tenant idx %d", t->tenant_index);
  return s;
}

static inline u8 *
format_vcdp_output_trace(u8 *s, va_list *args)
{
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  s = format(s, "vcdp-output: terminating VCDP chain");
  return s;
}


// This node assumes that the tenant has been configured for the given FIB table
// before being enabled.
VLIB_NODE_FN(vcdp_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{

  // use VRF ID as tenant ID
  vcdp_main_t *vcdp = &vcdp_main;
  gw_main_t *gw = &gateway_main;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 tenant_indicies[VLIB_FRAME_SIZE] = {0},
    *tenant_idx = tenant_indicies; // Used only for tracing

  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left) {

    u32 rx_sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
    tenant_idx[0] = gw->tenant_idx_by_sw_if_idx[rx_sw_if_index];
    if ((u32)tenant_idx[0] == ~0) {
      vnet_feature_next_u16(current_next, b[0]);
      goto next;
    }
    vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx[0]);
    vcdp_buffer(b[0])->context_id = tenant->context_id;
    vcdp_buffer(b[0])->tenant_index = tenant_idx[0];
    current_next[0] = VCDP_GW_NEXT_LOOKUP;

  next:
    b += 1;
    current_next += 1;
    n_left -= 1;
    tenant_idx += 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    tenant_idx = tenant_indicies;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_input_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->tenant_index = tenant_idx[0];
        b++;
        tenant_idx++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_input_node) = {
  .name = "vcdp-input",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = VCDP_GW_N_NEXT,
  .next_nodes =
    {
      [VCDP_GW_NEXT_LOOKUP] = "vcdp-lookup-ip4",
      [VCDP_GW_NEXT_IP4_LOOKUP] = "ip4-lookup",
      [VCDP_GW_NEXT_ICMP_ERROR] = "vcdp-icmp-error",
    },
};

VNET_FEATURE_INIT(vcdp_input_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "vcdp-input",
};

VNET_FEATURE_INIT(vcdp_output_feat, static) = {
  .arc_name = "ip4-output",
  .node_name = "vcdp-input",
};

VLIB_NODE_FN(vcdp_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;

  while (n_left > 0) {
    if (vnet_buffer(b[0])->ip.save_rewrite_length) {
      vnet_feature_next_u16(next, b[0]);
    } else {
      next[0] = VCDP_GW_NEXT_IP4_LOOKUP;
    }

    /*
     * If the ttl drops below 1 when forwarding, generate
     * an ICMP response.
     */
    ip4_header_t *ip = vcdp_get_ip4_header(b[0]);
    if (PREDICT_FALSE(ip->ttl <= 1)) {
      // b[0]->error = VCDP_TUNNEL_OUTPUT_ERROR_TIME_EXPIRED;
      vnet_buffer(b[0])->sw_if_index[VLIB_TX] = (u32) ~0;
      icmp4_error_set_vnet_buffer(b[0], ICMP4_time_exceeded, ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
      next[0] = VCDP_GW_NEXT_ICMP_ERROR;
    }

    b++;
    next++;
    n_left--;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vlib_add_trace(vm, node, b[0], 0);
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_output_node) = {
  .name = "vcdp-output",
  .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_vcdp_output_trace,
  .sibling_of = "vcdp-input",
};

VCDP_SERVICE_DEFINE(output) = {
  .node_name = "vcdp-output",
  .runs_before = VCDP_SERVICES(0),
  .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle", "vcdp-tcp-lite-check",
                              "vcdp-nat-late-rewrite", "vcdp-nat-early-rewrite"),
  .is_terminal = 1
};
