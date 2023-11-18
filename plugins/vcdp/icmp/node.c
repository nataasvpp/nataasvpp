// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

// Forward an ICMP error packet. Look up the inner embedded packet and forward it via the ICMP error specific service
// chain.

// Calculate inner session key
// Lookup using inner key
// Pass off to ICMP error specific service chain
// Or handoff to different thread

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_16_8.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include <vcdp/lookup/lookup_inlines.h>
#include <vcdp/vcdp.api_enum.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u64 hash;
  u32 flow_id;
  u32 error;
  u32 remote_worker;
  bool hit;
  u32 session_idx;
  u32 service_bitmap;
  vcdp_session_ip4_key_t k4;
} vcdp_icmp_fwd_trace_t;

typedef struct {
  u32 next_index;
  u32 flow_id;
} vcdp_icmp_handoff_trace_t;

static u8 *
format_vcdp_icmp_handoff_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_icmp_handoff_trace_t *t = va_arg(*args, vcdp_icmp_handoff_trace_t *);

  s = format(s,
             "vcdp-icmp-handoff: next index %d "
             "flow-id %u (session %u, %s)",
             t->next_index, t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

static u32
icmp_service_chain(u32 pbmp)
{
  u32 nbmp = 0;
  vcdp_service_main_t *sm = &vcdp_service_main;
  int i;
  for (i = 0; i < vec_len(sm->services); i++) {
    if (pbmp & sm->services[i]->service_mask[0]) {
      if (sm->services[i]->icmp_error) {
        nbmp |= sm->services[i]->icmp_error_mask;
      }
      if (sm->services[i]->is_terminal) {
        nbmp |= sm->services[i]->service_mask[0];
      }
    }
  }
  return nbmp;
}

VCDP_SERVICE_DECLARE(drop);

static_always_inline uword
vcdp_icmp_error_fwd_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vcdp_session_t *session;
  u32 session_index;
  u32 *bi, *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u32 to_local[VLIB_FRAME_SIZE], n_local = 0;
  u32 to_remote[VLIB_FRAME_SIZE], n_remote = 0;
  u16 thread_indices[VLIB_FRAME_SIZE];
  u16 local_next_indices[VLIB_FRAME_SIZE];
  vcdp_session_ip4_key_t keys[VLIB_FRAME_SIZE], *k4= keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  f64 time_now = vlib_time_now(vm);
  bool hits[VLIB_FRAME_SIZE], *hit = hits;
  u32 session_indices[VLIB_FRAME_SIZE], *si = session_indices;
  u32 service_bitmaps[VLIB_FRAME_SIZE], *sb = service_bitmaps;
  int rvs[VLIB_FRAME_SIZE], *rv = rvs;
  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  ptd->current_time = time_now;

  // Calculate key and hash
  while (n_left) {
    rv[0] = vcdp_calc_key_v4_icmp(b[0], vcdp_buffer(b[0])->context_id, k4, h);
    h += 1;
    k4 += 1;
    b += 1;
    rv += 1;
    n_left -= 1;
  }

  h = hashes;
  k4 = keys;
  b = bufs;
  u16 *current_next = local_next_indices;
  bi = from;
  n_left = frame->n_vectors;
  rv = rvs;

  while (n_left) {
    b[0]->error = 0;
    clib_bihash_kv_16_8_t kv;
    clib_memcpy_fast(&kv, k4, 16);
    if (rv[0] < 0) {
        // DROP PACKET
      to_local[n_local] = bi[0];
      n_local++;
      b[0]->flow_id = ~0; // No session
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      vcdp_next(b[0], current_next);
      current_next++;
      goto next;
    }
    VCDP_DBG(5, "Looking up: %U", format_vcdp_session_key, k4);
    if (clib_bihash_search_inline_with_hash_16_8(&vcdp->table4, h[0], &kv)) {
      // DROP PACKET
      to_local[n_local] = bi[0];
      n_local++;
      b[0]->flow_id = ~0; // No session
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      vcdp_next(b[0], current_next);
      current_next++;
      goto next;
    }

    // Figure out if this is local or remote thread
    u32 flow_thread_index = vcdp_thread_index_from_lookup(kv.value);
    if (flow_thread_index == thread_index) {
      /* known flow which belongs to this thread */
      u32 flow_index = kv.value & (~(u32) 0);
      to_local[n_local] = bi[0];
      session_index = vcdp_session_from_flow_index(flow_index);
      si[0] = session_index;
      b[0]->flow_id = flow_index;

      session = vcdp_session_at_index(ptd, session_index);
      if (vcdp_session_is_expired(session, time_now)) {
        // Received a packet against an expired session. Recycle the session.
        VCDP_DBG(2, "Expired session: %u %U %.02f %.02f (%.02f)", session_index, format_vcdp_session_key, k4,
                     session->timer.next_expiration, time_now, session->timer.next_expiration - time_now);
        vcdp_session_remove(vcdp, ptd, session, thread_index, session_index);
        // DROP PACKET
      }

      //   ICMP chain
      // Calculate the service chain for this packet, based on direction...
      u32 nbmp = icmp_service_chain(session->bitmaps[vcdp_direction_from_flow_index(flow_index)]);
      VCDP_DBG(5, "ICMP Service Chain: %U", format_vcdp_bitmap, nbmp);
      vcdp_buffer(b[0])->service_bitmap = sb[0] = nbmp;

      /* The tenant of the buffer is the tenant of the session */
      vcdp_buffer(b[0])->tenant_index = session->tenant_idx;
      vcdp_next(b[0], current_next);

      current_next++;
      n_local++;
      session->pkts[vcdp_direction_from_flow_index(flow_index)]++;
      session->bytes[vcdp_direction_from_flow_index(flow_index)] += vlib_buffer_length_in_chain (vm, b[0]);
    } else {
      /* known flow which belongs to remote thread */
      to_remote[n_remote] = bi[0];
      thread_indices[n_remote] = flow_thread_index;
      n_remote++;
    }

    b[0]->flow_id = kv.value & (~(u32) 0);

  next:
    b += 1;
    n_left -= 1;
    h += 1;
    k4 += 1;
    bi += 1;
    hit += 1;
    si += 1;
    sb += 1;
  }

  /* handover buffers to remote node */
  if (n_remote) {
    // u32 n_remote_enq;
    /*n_remote_enq = */vlib_buffer_enqueue_to_thread(vm, node, vcdp->frame_queue_icmp_index, to_remote, thread_indices, n_remote, 1);
    // vlib_node_increment_counter(vm, node->node_index, VCDP_ICMP_FWD_ERROR_REMOTE, n_remote_enq);
    // vlib_node_increment_counter(vm, node->node_index, VCDP_ICMP_FWD_ERROR_CON_DROP, n_remote - n_remote_enq);
  }

  /* enqueue local */
  if (n_local) {
    vlib_buffer_enqueue_to_next(vm, node, to_local, local_next_indices, n_local);
  }

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    bi = from;
    h = hashes;
    si = session_indices;
    hit = hits;
    sb = service_bitmaps;
    u32 *in_local = to_local;
    u32 *in_remote = to_remote;

    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_icmp_fwd_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
        t->flow_id = b[0]->flow_id;
        t->hash = h[0];
        t->hit = hit[0];
        t->session_idx = si[0];
        t->service_bitmap = sb[0];
        if (bi[0] == in_local[0]) {
          t->next_index = local_next_indices[(in_local++) - to_local];
        } else {
          t->next_index = ~0;
          t->remote_worker = thread_indices[(in_remote++) - to_remote];
        }
        if (b[0]->error) {
          t->error = b[0]->error;
        } else {
          t->error = 0;
        }
        clib_memcpy(&t->k4, &keys[i], sizeof(t->k4));
        bi++;
        b++;
        h++;
        hit++;
        si++;
        sb++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_NODE_FN(vcdp_icmp_fwd_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
   return vcdp_icmp_error_fwd_inline(vm, node, frame);
}

/*
 * This node is used to handoff packets to the correct thread.
 */
VLIB_NODE_FN(vcdp_icmp_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  f64 time_now = vlib_time_now(vm);

  ptd->current_time = time_now;

  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left) {
    u32 flow_index = b[0]->flow_id;
    u32 session_index = vcdp_session_from_flow_index(flow_index);
    vcdp_session_t *session = vcdp_session_at_index_check(ptd, session_index);
    if (!session) {
      // Session has been deleted underneath us
        vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
        b[0]->error = node->errors[VCDP_HANDOFF_ERROR_NO_SESSION];
        goto next;
    }

    // Check if session has expired. If so send it back to the icmp_fwd node to be created.
    if (vcdp_session_is_expired(session, time_now)) {
      VCDP_DBG(2, "Forwarding against expired handoff session, deleting and recreating %d", session_index);
      vcdp_session_remove(vcdp, ptd, session, thread_index, session_index);
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_HANDOFF_ERROR_NO_SESSION];
      goto next;
    }

    //   ICMP chain
    // Calculate the service chain for this packet, based on direction...
    u32 nbmp = icmp_service_chain(session->bitmaps[vcdp_direction_from_flow_index(flow_index)]);
    vcdp_buffer(b[0])->service_bitmap = nbmp;

  next:
    vcdp_next(b[0], current_next);
    current_next += 1;
    b += 1;
    n_left -= 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    current_next = next_indices;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_icmp_handoff_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->next_index = current_next[0];
        b++;
        current_next++;
      } else
        break;
    }
  }

  return frame->n_vectors;
}

/*
 * next_index is ~0 if the packet was enqueued to the remote node
 */
static u8 *
format_vcdp_icmp_fwd_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_icmp_fwd_trace_t *t = va_arg (*args, vcdp_icmp_fwd_trace_t *);
  u32 indent = format_get_indent (s);

  if (t->error)
    s = format(s, "error: %u", t->error);
  else if (t->next_index == ~0)
    s = format(s, "handoff: %u", t->remote_worker);
  else
    if (t->hit)
      s = format(s, "found session, index: %d", t->session_idx);
    else
      s = format(s, "missed session, index: %d", t->session_idx);
  s = format(s, "\n%Unext index: %u, rx ifindex %d, hash 0x%x flow-id %u  key 0x%U",
             format_white_space, indent, t->next_index, t->sw_if_index, t->hash, t->flow_id, format_hex_bytes_no_wrap, (u8 *) &t->k4, sizeof(t->k4));
  s = format(s, "\n%Uservice chain: %U", format_white_space, indent, format_vcdp_bitmap, t->service_bitmap);
  return s;

}

VLIB_REGISTER_NODE(vcdp_icmp_fwd_ip4_node) = {
  .name = "vcdp-icmp-error-forwarding",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_icmp_fwd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VCDP_SERVICE_DEFINE(icmp_error_fwd) = {
  .node_name = "vcdp-icmp-error-forwarding",
  .runs_before = VCDP_SERVICES("vcdp-drop"),
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 0
};

VLIB_REGISTER_NODE(vcdp_icmp_handoff_node) = {
  .name = "vcdp-icmp-handoff",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_icmp_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
};
