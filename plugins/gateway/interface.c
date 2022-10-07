// Copyright(c) 2022 Cisco Systems, Inc.

// Get packets from the IP unicast input feature arc set tenant and pass them to VCDP.

#include <vlib/vlib.h>
#include <vnet/fib/fib_table.h>
#include <vnet/feature/feature.h>
#include <vcdp/vcdp.h>
#include <vcdp/common.h>
#include "gateway.h"

enum vcdp_input_next_e {
    VCDP_INPUT_NEXT_LOOKUP,
    VCDP_INPUT_N_NEXT
};

// This node assumes that the tenant has been configured for the given FIB table before being enabled.
VLIB_NODE_FN(vcdp_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {

  // use VRF ID as tenant ID
  vcdp_main_t *vcdp = &vcdp_main;
  gw_main_t *gw = &gateway_main;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left) {

    u32 rx_sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
    u32 tenant_idx = gw->tenant_idx_by_sw_if_idx[rx_sw_if_index];
    if (tenant_idx == ~0) {
      vnet_feature_next_u16(current_next, b[0]);
      goto next;
    }
    vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
    b[0]->flow_id = tenant->context_id;
    vcdp_buffer(b[0])->tenant_index = tenant_idx;
    current_next[0] = VCDP_INPUT_NEXT_LOOKUP;

  next:
    b += 1;
    current_next += 1;
    n_left -= 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_input_node) = {
  .name = "vcdp-input",
  .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = VCDP_INPUT_N_NEXT,
  .next_nodes =
    {
      [VCDP_INPUT_NEXT_LOOKUP] = "vcdp-lookup-ip4",
    },
};

VNET_FEATURE_INIT(vcdp_input_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "vcdp-input",
};
