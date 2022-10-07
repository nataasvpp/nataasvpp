// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <gateway/gateway.h>
#include <vcdp/common.h>
#include <vnet/vxlan/vxlan_packet.h>
#include <vpp_plugins/geneve/geneve_packet.h>
#include "tunnel.h"

typedef struct {
  u32 next_index;
  u32 sw_if_index;
} vcdp_tunnel_input_trace_t;

static u8 *
format_vcdp_tunnel_input_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  vcdp_tunnel_input_trace_t *t = va_arg(*args, vcdp_tunnel_input_trace_t *);

  s = format(s, "tunnel-input: sw_if_index %d, next index %d\n", t->sw_if_index,
             t->next_index);
  return s;
}

// Next nodes
typedef enum {
  VCDP_TUNNEL_INPUT_NEXT_DROP,
  VCDP_TUNNEL_INPUT_NEXT_IP4_LOOKUP,
  VCDP_TUNNEL_INPUT_N_NEXT
} vcdp_tunnel_input_next_t;

#define foreach_vcdp_tunnel_input_error                                             \
  _ (BUFFER_ALLOC_FAIL, buffer_alloc, ERROR, "buffer allocation failed")      \
  _ (BAD_DESC, bad_desc, ERROR, "bad descriptor")                             \
  _ (NOT_IP, not_ip, INFO, "not ip packet")

// Error counters
typedef enum
{
#define _(f, n, s, d) VCDP_TUNNEL_INPUT_ERROR_##f,
  foreach_vcdp_tunnel_input_error
#undef _
    VCDP_TUNNEL_INPUT_N_ERROR,
} vcdp_tunnel_input_error_t;

static vlib_error_desc_t vcdp_tunnel_input_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
  foreach_vcdp_tunnel_input_error
#undef _
};


// Graph node for VXLAN and Geneve tunnel decap
VLIB_NODE_FN(vcdp_tunnel_vxlan_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
  u32 n_left_from, *from;
  u16 nexts[VLIB_FRAME_SIZE] = {0}, *next = nexts;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_tenant_t *tenant;
  u16 tenant_idx;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers(vm, from, b, n_left_from);

  while (n_left_from > 0) {

    /* By default pass packet to next node in the feature chain */
    vnet_feature_next_u16(next, b[0]);

    // Do we have enough bytes to do the lookup?
    // No support for reassembly so pass-through for non-first fragments
    ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current(b[0]);
    u16 min_lookup_bytes = ip4_header_bytes(ip) + sizeof(udp_header_t);
    if (vlib_buffer_has_space (b[0], min_lookup_bytes) == 0 || ip4_is_fragment(ip)) {
      goto next;
    }

    udp_header_t *udp = ip4_next_header(ip);
    u32 context_id = 0;
    u64 value;
    int rv = vcdp_session_static_lookup(context_id, ip->src_address, ip->dst_address,
                           ip->protocol, udp->src_port, udp->dst_port, &value);
    if (rv != 0) {
      goto next;
    }

    vcdp_tunnel_t *t = pool_elt_at_index(vcdp_tunnel_main.tunnels, value);
    u16 bytes_to_inner_ip;
    u32 vni;

    switch (t->method) {

    case VCDP_TUNNEL_GENEVE_L3:
      bytes_to_inner_ip = ip4_header_bytes(ip) + sizeof(udp_header_t) + sizeof(geneve_header_t);
      if (vlib_buffer_has_space (b[0], bytes_to_inner_ip + 28) == 0) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        goto next;
      }
      geneve_header_t *geneve = (geneve_header_t *)(udp + 1);
      if (vnet_get_geneve_options_len(geneve) != 0) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        goto next;
      }
      vni = vnet_get_geneve_vni(geneve);
      if (vnet_get_geneve_protocol(geneve) != ETHERNET_TYPE_IP4) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        goto next;
      }
      break;

    case VCDP_TUNNEL_VXLAN_DUMMY_L2:
      bytes_to_inner_ip = ip4_header_bytes(ip) + sizeof(udp_header_t) + sizeof(vxlan_header_t) \
                          + sizeof(ethernet_header_t);
      if (vlib_buffer_has_space (b[0], bytes_to_inner_ip + 28) == 0) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        goto next;
      }
      vxlan_header_t *vxlan = (vxlan_header_t *)(udp + 1);
      vni = vnet_get_vni(vxlan);
      ethernet_header_t *eth = (ethernet_header_t *)(vxlan + 1);
      if (clib_net_to_host_u16(eth->type) != ETHERNET_TYPE_IP4) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        goto next;
      }
      break;    

    default:
      // unknown tunnel type
      next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
      goto next;
    }

    // Two choices. Either a tunnel can be hardcoded with a tenant or the VNI is used as tenant id.
    // ignoring VNI for NATaaS / SWG integration
    clib_bihash_kv_8_8_t kv = {};
    vcdp_main_t *vcdp = &vcdp_main;
    kv.key = t->tenant_id == ~0 ? (u64) vni : t->tenant_id;
    if (clib_bihash_search_inline_8_8(&vcdp->tenant_idx_by_id, &kv)) {
      /* Not found */
      next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
      goto next;
    }
    tenant_idx = kv.value;

    /* Store tenant_id as flow_id (to simplify the future lookup) */
    tenant = vcdp_tenant_at_index(&vcdp_main, tenant_idx);
    b[0]->flow_id = tenant->context_id;

    vlib_buffer_advance(b[0], bytes_to_inner_ip);

    vcdp_buffer(b[0])->tenant_index = tenant_idx;
    vcdp_buffer(b[0])->rx_id = value; 

    next[0] = VCDP_TUNNEL_INPUT_NEXT_IP4_LOOKUP;

  next:
    next += 1;
    n_left_from -= 1;
    b += 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_tunnel_input_node) = {
  .name = "vcdp-tunnel-input",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_tunnel_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = VCDP_TUNNEL_INPUT_N_ERROR,
  .error_counters = vcdp_tunnel_input_error_counters,
  .n_next_nodes = VCDP_TUNNEL_INPUT_N_NEXT,
  .next_nodes =
    {
      [VCDP_TUNNEL_INPUT_NEXT_DROP] = "error-drop",
      [VCDP_TUNNEL_INPUT_NEXT_IP4_LOOKUP] = "vcdp-lookup-ip4",
    },
};

/* Hook up features */
VNET_FEATURE_INIT(vcdp_tunnel_input, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "vcdp-tunnel-input",
    .runs_after = VNET_FEATURES("ip4-sv-reassembly-feature"), // TODO: Needed?
};