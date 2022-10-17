// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_tunnel_node_h
#define included_vcdp_tunnel_node_h

#include <vlib/vlib.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
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

static inline u8 *
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

#define foreach_vcdp_tunnel_input_error                                        \
  _(BUFFER_ALLOC_FAIL, buffer_alloc, ERROR, "buffer allocation failed")        \
  _(BAD_DESC, bad_desc, ERROR, "bad descriptor")                               \
  _(NOT_IP, not_ip, INFO, "not ip packet")

// Error counters
typedef enum {
#define _(f, n, s, d) VCDP_TUNNEL_INPUT_ERROR_##f,
  foreach_vcdp_tunnel_input_error
#undef _
    VCDP_TUNNEL_INPUT_N_ERROR,
} vcdp_tunnel_input_error_t;

vlib_error_desc_t vcdp_tunnel_input_error_counters[] = {
#define _(f, n, s, d) {#n, d, VL_COUNTER_SEVERITY_##s},
  foreach_vcdp_tunnel_input_error
#undef _
};

// Graph node for VXLAN and Geneve tunnel decap
static inline uword vcdp_tunnel_input_node_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
  u32 n_left_from, *from;
  u16 nexts[VLIB_FRAME_SIZE] = {0}, *next = nexts;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_tenant_t *tenant;
  u16 tenant_idx;

  from = vlib_frame_vector_args(frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers(vm, from, b, n_left_from);

  while (n_left_from > 0) {
    clib_warning("OLE received packet %d", vlib_buffer_length_in_chain(vm, b[0]));
    /* By default pass packet to next node in the feature chain */
    vnet_feature_next_u16(next, b[0]);

    // Do we have enough bytes to do the lookup?
    // No support for reassembly so pass-through for non-first fragments
    ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current(b[0]);
    u16 min_lookup_bytes = ip4_header_bytes(ip) + sizeof(udp_header_t);
    if (vlib_buffer_has_space(b[0], min_lookup_bytes) == 0 ||
        ip4_is_fragment(ip)) {
      goto next;
    }

    udp_header_t *udp = ip4_next_header(ip);
    u32 context_id = 0;
    u64 value;
    int rv = vcdp_session_static_lookup(context_id, ip->src_address,
                                        ip->dst_address, ip->protocol,
                                        0, udp->dst_port, &value);
    if (rv != 0) {
        clib_warning("SESSION STATIC LOOKUP FAILED");
        goto next;
    }

    vcdp_tunnel_t *t = pool_elt_at_index(vcdp_tunnel_main.tunnels, value);
    u16 bytes_to_inner_ip;
    u32 vni;

    switch (t->method) {

    case VCDP_TUNNEL_GENEVE_L3:
      bytes_to_inner_ip =
        ip4_header_bytes(ip) + sizeof(udp_header_t) + sizeof(geneve_header_t);
      if (vlib_buffer_has_space(b[0], bytes_to_inner_ip + 28) == 0) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        goto next;
      }
      geneve_header_t *geneve = (geneve_header_t *) (udp + 1);
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
      bytes_to_inner_ip = ip4_header_bytes(ip) + sizeof(udp_header_t) +
                          sizeof(vxlan_header_t) + sizeof(ethernet_header_t);
      if (vlib_buffer_has_space(b[0], bytes_to_inner_ip + 28) == 0) {
        next[0] = VCDP_TUNNEL_INPUT_NEXT_DROP;
        goto next;
      }
      vxlan_header_t *vxlan = (vxlan_header_t *) (udp + 1);
      vni = vnet_get_vni(vxlan);
      ethernet_header_t *eth = (ethernet_header_t *) (vxlan + 1);
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

    // Two choices. Either a tunnel can be hardcoded with a tenant or the VNI is
    // used as tenant id. ignoring VNI for NATaaS / SWG integration
    clib_bihash_kv_8_8_t kv = {};
    vcdp_main_t *vcdp = &vcdp_main;
    kv.key = t->tenant_id == ~0 ? (u64) vni : t->tenant_id;
    ASSERT(vcdp->tenant_idx_by_id.buckets != 0);
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
    ip4_header_t *inner_ip = (ip4_header_t *) vlib_buffer_get_current(b[0]);
    clib_warning("INNER PACKET: %U", format_ip4_header, inner_ip);
    vcdp_buffer(b[0])->tenant_index = tenant_idx;
    // vcdp_buffer(b[0])->rx_id = value;

    next[0] = VCDP_TUNNEL_INPUT_NEXT_IP4_LOOKUP;

  next:
    next += 1;
    n_left_from -= 1;
    b += 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

// Encapsulation
typedef struct {
  u32 next_index;
  u32 sw_if_index;
} vcdp_tunnel_output_trace_t;

static inline u8 *
format_vcdp_tunnel_output_trace(u8 *s, va_list *args) {
  CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
  vcdp_tunnel_output_trace_t *t = va_arg(*args, vcdp_tunnel_output_trace_t *);

  s = format(s, "tunnel-output: sw_if_index %d, next index %d\n",
             t->sw_if_index, t->next_index);
  return s;
}

// Next nodes
typedef enum {
  VCDP_TUNNEL_OUTPUT_NEXT_DROP,
  VCDP_TUNNEL_OUTPUT_NEXT_IP4_LOOKUP,
  VCDP_TUNNEL_OUTPUT_N_NEXT
} vcdp_tunnel_output_next_t;

#define foreach_vcdp_tunnel_output_error                                       \
  _(BUFFER_ALLOC_FAIL, buffer_alloc, ERROR, "buffer allocation failed")        \
  _(BAD_DESC, bad_desc, ERROR, "bad descriptor")                               \
  _(NOT_IP, not_ip, INFO, "not ip packet")

// Error counters
typedef enum {
#define _(f, n, s, d) VCDP_TUNNEL_OUTPUT_ERROR_##f,
  foreach_vcdp_tunnel_output_error
#undef _
    VCDP_TUNNEL_OUTPUT_N_ERROR,
} vcdp_tunnel_output_error_t;

vlib_error_desc_t vcdp_tunnel_output_error_counters[] = {
#define _(f, n, s, d) {#n, d, VL_COUNTER_SEVERITY_##s},
  foreach_vcdp_tunnel_output_error
#undef _
};

static void
vcdp_vxlan_dummy_l2_fixup(vlib_main_t *vm, vlib_buffer_t *b) {
  ip4_header_t *ip;
  udp_header_t *udp;

  ip = vlib_buffer_get_current(b);

  ip->length = clib_host_to_net_u16(vlib_buffer_length_in_chain(vm, b));
  ip->checksum = ip4_header_checksum(ip);
  udp = (udp_header_t *) ip + 1;
  udp->length = ip->length - sizeof(ip4_header_t);
  // TODO: udp->src_port = ip4_compute_flow_hash (b);
}

static inline uword vcdp_tunnel_output_node_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  // gw_main_t *gm = &gateway_main;
  // vcdp_main_t *vcdp = &vcdp_main;
  // vcdp_tunnel_main_t *vcdp_tm = &vcdp_tunnel_main;
  // u32 thread_index = vm->thread_index;

  // vcdp_per_thread_data_t *vptd =
  //   vec_elt_at_index(vcdp->per_thread_data, thread_index);

  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers(vm, from, bufs, n_left);

  while (n_left > 0) {
    // u32 session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    // vcdp_session_t *session = vcdp_session_at_index(vptd, session_idx);
    vcdp_tunnel_t *t = vcdp_tunnel_get(vcdp_buffer(b[0])->tenant_index);
    if (t == 0) {
      to_next[0] = VCDP_TUNNEL_OUTPUT_NEXT_DROP;
      goto done;
    }
    u8 *data;
    // u16 orig_len = vlib_buffer_length_in_chain(vm, b[0]);
    b[0]->flags |= (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
                    VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
    vnet_buffer(b[0])->oflags |=
      VNET_BUFFER_OFFLOAD_F_UDP_CKSUM | VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
    vlib_buffer_advance(b[0], -t->encap_size);
    data = vlib_buffer_get_current(b[0]);
    vnet_buffer(b[0])->l3_hdr_offset = b[0]->current_data;
    vnet_buffer(b[0])->l4_hdr_offset = b[0]->current_data + sizeof(ip4_header_t);
    clib_memcpy_fast(data, t->rewrite, t->encap_size);
    vcdp_vxlan_dummy_l2_fixup(vm, b[0]);

    to_next[0] = VCDP_TUNNEL_OUTPUT_NEXT_IP4_LOOKUP;

  done:
    to_next++;
    b++;
    n_left--;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
#if 0
  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    n_left = frame->n_vectors;
    b = bufs;
    for (i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_tunnel_output_trace_t *t =
          vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->encap_size = gptd->output[b[0]->flow_id].encap_size;
        clib_memcpy_fast(t->encap_data, gptd->output[b[0]->flow_id].encap_data,
                         gptd->output[b[0]->flow_id].encap_size);
        b++;
      } else
        break;
    }
  }
#endif
  return frame->n_vectors;
}

#endif