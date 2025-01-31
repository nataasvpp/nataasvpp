// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2023 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp_services/nat/nat.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include "rewrite.h"
#include <vcdp_services/nat/nat.api_enum.h>
#include <vnet/ip/ip4_to_ip6.h>
#include <vnet/ip/ip6_to_ip4.h>

typedef struct {
  u32 thread_index;
  u32 flow_id;
} vcdp_nat64_icmp_error_trace_t;

static u8 *
format_vcdp_nat64_icmp_error_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_nat64_icmp_error_trace_t *t = va_arg(*args, vcdp_nat64_icmp_error_trace_t *);
  nat_main_t *nm = &nat_main;
  u32 session_idx = vcdp_session_from_flow_index(t->flow_id);
  nat64_rewrite_data_t *  rewrites = vec_elt_at_index(nm->flows64, session_idx << 1);

  s = format(s, "vcdp-nat64-icmp-error: thread: %u flow-id %u (session %u, %s) rewrite #1: %U rewrite #2: %U\n",
             t->thread_index, t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward",
             format_vcdp_nat64_rewrite, &rewrites[0], format_vcdp_nat64_rewrite, &rewrites[1]);

  return s;
}

VCDP_SERVICE_DECLARE(drop)

static int
icmp_to_icmp6_cb (vlib_buffer_t *b, ip4_header_t * ip4, ip6_header_t * ip6, void *arg)
{
  nat64_rewrite_data_t *nat_rewrite = arg;
  // Set IPv6 source address and destination address

  // Whatever is in the IPv4 source into the IPv6 source (NAT64 prefix + IPv4 SA)
  ip6->src_address = nat_rewrite->ip6.src_address;

  // Get the IPv6 destination from the NAT rewrite
  ip6->dst_address = nat_rewrite->ip6.dst_address;

  return 0;
}
static int
icmp_to_icmp6_inner_cb (vlib_buffer_t *b, ip4_header_t * ip4, ip6_header_t * ip6, void *arg)
{
  // Update the IPv6 header from the session
  nat64_rewrite_data_t *nat_rewrite = arg;
  // Set IPv6 source address and destination address (inverse because of ICMP error)
  ip6->src_address = nat_rewrite->ip6.dst_address;
  ip6->dst_address = nat_rewrite->ip6.src_address;
  return 0;
}

static int
icmp6_to_icmp_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
  nat64_rewrite_data_t *nat_rewrite = arg;
  // Whatever is in the IPv4 source into the IPv6 source (NAT64 prefix + IPv4 SA)
  ip4->src_address = nat_rewrite->ip4.src_address;
  // Get the IPv6 destination from the NAT rewrite
  ip4->dst_address = nat_rewrite->ip4.dst_address;

  return 0;
}
static int
icmp6_to_icmp_inner_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
  // Update the IPv6 header from the session
  nat64_rewrite_data_t *nat_rewrite = arg;
  // Set IPv6 source address and destination address (inverse because of ICMP error)
  ip4->src_address = nat_rewrite->ip4.dst_address;
  ip4->dst_address = nat_rewrite->ip4.src_address;
  return 0;
}
static_always_inline void
nat64_icmp_error_process_one(vlib_node_runtime_t *node, nat64_rewrite_data_t *nat_rewrites, vcdp_session_t *session,
                             u16 *to_next, vlib_buffer_t **b)
{
  if (session->session_version != nat_rewrites[0].version) {
    vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
    goto end_of_packet;
  }

  // The flow-id comes from the inner packet
  int dir = vcdp_direction_from_flow_index(b[0]->flow_id);
  int rv;
  if (dir == VCDP_FLOW_FORWARD) { // IPv6 -> IPv4
    rv = icmp6_to_icmp(vlib_get_main(), b[0], icmp6_to_icmp_cb, &nat_rewrites[0], icmp6_to_icmp_inner_cb, &nat_rewrites[0]);
    if (rv) {
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_NAT_ICMP_ERROR_TRANS64];
      goto end_of_packet;
    }
  } else {
    rv = icmp_to_icmp6(b[0], icmp_to_icmp6_cb, &nat_rewrites[1], icmp_to_icmp6_inner_cb, &nat_rewrites[1]);
    if (rv) {
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_NAT_ICMP_ERROR_TRANS46];
      goto end_of_packet;
    }
  }

#if 0
  // Drop any ICMP error longer than 576 bytes
  if (clib_net_to_host_u16(ip->length) > 576 || b[0]->current_length > 576) {
    b[0]->error = node->errors[VCDP_NAT_ICMP_ERROR_TOOLONG];
    vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
    goto end_of_packet;
  }

#endif

end_of_packet:
  vcdp_next(b[0], to_next);
}

/*
 * ICMP error handling. The following rules apply:
 * The session matched by the inner packet is used to translate the outer.
 * ICMP received for out2in payload (inside of NAT):
 *   - Translate outer header according to session in forward direction
 *   - Translate inner header according to session in reverse direction
 * ICMP received for in2out payload (outside of NAT):
 *   - Translate outer header according to session in reverse direction
 *   - Translate inner header according to session in forward direction
*/

static_always_inline u16
vcdp_nat64_icmp_error_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;
  nat_main_t *nat = &nat_main;
  u32 thread_index = vlib_get_thread_index();
  vcdp_session_t *session;
  u32 session_idx;
  nat64_rewrite_data_t *nat_rewrites;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  vlib_get_buffers(vm, from, bufs, n_left);
  while (n_left > 0) {
    session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    session = vcdp_session_at_index_check(vcdp, session_idx);
    if (!session) {
      b[0]->error = node->errors[VCDP_NAT_ICMP_ERROR_NO_SESSION];
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      vcdp_next(b[0], to_next);

      goto next;
    }
    nat_rewrites = vec_elt_at_index(nat->flows64, session_idx << 1);

    // Call fastpath process on outer and then on inner
    nat64_icmp_error_process_one(node, nat_rewrites, session, to_next, b);

  next:
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
        vcdp_nat64_icmp_error_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->thread_index = thread_index;
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_NODE_FN(vcdp_nat64_icmp_error_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_nat64_icmp_error_inline(vm, node, frame);
}

VLIB_REGISTER_NODE(vcdp_nat64_icmp_error_node) = {
  .name = "vcdp-nat64-icmp-error",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_nat64_icmp_error_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_NAT_ICMP_N_ERROR,
  .error_counters = vcdp_nat_icmp_error_counters,
};

VCDP_SERVICE_DEFINE(nat64_icmp_error) = {
  .node_name = "vcdp-nat64-icmp-error",
  .runs_before = VCDP_SERVICES("vcdp-tunnel-output"),
  .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle", "vcdp-tcp-check"),
  .is_terminal = 0};
