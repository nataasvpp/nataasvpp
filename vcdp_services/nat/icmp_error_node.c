// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2023 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp_services/nat/nat.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include "rewrite.h"
#include <vcdp_services/nat/nat.api_enum.h>

typedef struct {
  u32 thread_index;
  u32 flow_id;
} vcdp_nat_icmp_error_trace_t;

static u8 *
format_vcdp_nat_icmp_error_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_nat_icmp_error_trace_t *t = va_arg(*args, vcdp_nat_icmp_error_trace_t *);
  nat_main_t *nm = &nat_main;
  u32 session_idx = vcdp_session_from_flow_index(t->flow_id);
  nat_rewrite_data_t *rewrites = vec_elt_at_index(nm->flows, session_idx << 1);

  s = format(s, "vcdp-nat-icmp-error: thread: %u flow-id %u (session %u, %s) rewrite #1: %U rewrite #2: %U\n",
             t->thread_index, t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward",
             format_vcdp_nat_rewrite, &rewrites[0], format_vcdp_nat_rewrite, &rewrites[1]);

  return s;
}

VCDP_SERVICE_DECLARE(drop)

static_always_inline void
nat_icmp_error_process_one(vlib_node_runtime_t * node, nat_rewrite_data_t *nat_rewrites, vcdp_session_t *session, u16 *to_next, vlib_buffer_t **b)
{
  ip4_header_t *ip = vcdp_get_ip4_header(b[0]);

  icmp46_header_t *icmp;
  icmp_echo_header_t *echo;

  if (session->session_version != nat_rewrites[0].version) {
    vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
    goto end_of_packet;
  }

  // Drop any ICMP error longer than 576 bytes
  if (clib_net_to_host_u16(ip->length) > 576 || b[0]->current_length > 576) {
    b[0]->error = node->errors[VCDP_NAT_ICMP_ERROR_TOOLONG];
    vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
    goto end_of_packet;
  }

  // The flow-id comes from the inner packet
  int dir = vcdp_direction_from_flow_index(b[0]->flow_id);
  icmp = (icmp46_header_t *) ip4_next_header(ip);
  echo = (icmp_echo_header_t *) (icmp + 1);
  ip4_header_t *inner_ip = (ip4_header_t *) (echo + 1);

  // Validate checksums
  ip_csum_t sum = ip_incremental_checksum(0, icmp, b[0]->current_length - sizeof(ip4_header_t));
  sum = ~ip_csum_fold(sum);
  if (!ip4_header_checksum_is_valid(inner_ip) || (u16)sum != 0) {
    b[0]->error = node->errors[VCDP_NAT_ICMP_ERROR_CHECKSUM];
    vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
    goto end_of_packet;
  }

  nat_rewrite_data_t icmp_error_rewrite;
  clib_memcpy(&icmp_error_rewrite, &nat_rewrites[dir], sizeof(nat_rewrite_data_t));
  nat_rewrite_outer(ip, &nat_rewrites[dir]);
  if (dir == VCDP_FLOW_FORWARD) {
    icmp_error_rewrite.ops = NAT_REWRITE_OP_DADDR;
    icmp_error_rewrite.rewrite.daddr = icmp_error_rewrite.rewrite.saddr;
  } else {
    icmp_error_rewrite.ops = NAT_REWRITE_OP_SADDR;
    icmp_error_rewrite.rewrite.saddr = icmp_error_rewrite.rewrite.daddr;
  }
  nat_rewrite(inner_ip, &icmp_error_rewrite);

  // Recalculate ICMP checksum
  icmp->checksum = 0;
  sum = ip_incremental_checksum(0, icmp, b[0]->current_length - ip4_header_bytes(ip));
  icmp->checksum = ~ip_csum_fold (sum);
  ip->checksum = ip4_header_checksum (ip);

end_of_packet:
// vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
  vcdp_next(b[0], to_next);

  return;
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
vcdp_nat_icmp_error_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vcdp_main_t *vcdp = &vcdp_main;
  nat_main_t *nat = &nat_main;
  u32 thread_index = vlib_get_thread_index();
  vcdp_session_t *session;
  u32 session_idx;
  nat_rewrite_data_t *nat_rewrites;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;

  vlib_get_buffers(vm, from, bufs, n_left);
  while (n_left > 0) {
    session_idx = vcdp_session_from_flow_index(b[0]->flow_id);
    session = vcdp_session_at_index_check(vcdp, session_idx);
    if (!session) {
      // b[0]->error = node->errors[VCDP_NAT_ICMP_ERROR_NO_SESSION];
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      vcdp_next(b[0], to_next);

      goto next;
    }
    // TODO: Check if session is valid
    nat_rewrites = vec_elt_at_index(nat->flows, session_idx << 1);

    // Call fastpath process on outer and then on inner
    nat_icmp_error_process_one(node, nat_rewrites, session, to_next, b);

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
        vcdp_nat_icmp_error_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->thread_index = thread_index;
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_NODE_FN(vcdp_nat_icmp_error_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return vcdp_nat_icmp_error_inline(vm, node, frame);
}

VLIB_REGISTER_NODE(vcdp_nat_icmp_error_node) = {
  .name = "vcdp-nat-icmp-error",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_nat_icmp_error_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_NAT_ICMP_N_ERROR,
  .error_counters = vcdp_nat_icmp_error_counters,
};

VCDP_SERVICE_DEFINE(nat_icmp_error) = {
  .node_name = "vcdp-nat-icmp-error",
  .runs_before = VCDP_SERVICES("vcdp-tunnel-output"),
  .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle", "vcdp-tcp-check"),
  .is_terminal = 0};
