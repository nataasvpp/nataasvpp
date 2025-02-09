// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include <vcdp/lookup/lookup_inlines.h>
#include <vcdp/vcdp.api_enum.h>

typedef struct {
  u32 next_index;
} vcdp_create_trace_t;

static u8 *
format_vcdp_create_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_create_trace_t *t = va_arg(*args, vcdp_create_trace_t *);

  s = format(s, "vcdp-create: next-index %u", t->next_index);
  return s;
}

VCDP_SERVICE_DECLARE(drop)

void
vcdp_set_service_chain(vcdp_tenant_t *tenant, u8 proto, u32 *bitmaps)
{
  if (proto == IP_PROTOCOL_TCP) {
    bitmaps[VCDP_FLOW_FORWARD] = tenant->tcp_bitmaps[VCDP_FLOW_FORWARD];
    bitmaps[VCDP_FLOW_REVERSE] = tenant->tcp_bitmaps[VCDP_FLOW_REVERSE];
  } else {
    bitmaps[VCDP_FLOW_FORWARD] = tenant->bitmaps[VCDP_FLOW_FORWARD];
    bitmaps[VCDP_FLOW_REVERSE] = tenant->bitmaps[VCDP_FLOW_REVERSE];
  }
}

//
// Terminal service.
// Recycle back to fast-path lookup
//
static_always_inline uword
vcdp_create_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, bool is_ip6)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *from;
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vcdp_session_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  int rv;

  // Session created successfully: pass packet back to vcdp-lookup
  // Session already exists / collision: pass packet back to vcdp-lookup
  // Cannot create key, or table is full: pass packet to drop
  from = vlib_frame_vector_args(frame);
  vlib_get_buffers(vm, from, b, n_left);

  while (n_left) {
    u16 tenant_idx = vcdp_buffer(b[0])->tenant_index;
    // vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx);

    rv = vcdp_calc_key_slow(b[0], vcdp_buffer(b[0])->context_id, k, h, is_ip6);
    vcdp_log_debug("Creating session for: %U", format_vcdp_session_key, k);

    if (rv != 0) {
      b[0]->error = node->errors[VCDP_CREATE_ERROR_NO_KEY];
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      goto next;
    }

    u32 flow_index = ~0;
    vcdp_session_t *session = vcdp_create_session(tenant_idx, k, 0, false, &flow_index);
    if (session) {
      session->rx_id = vcdp_buffer(b[0])->rx_id;
      vcdp_buffer(b[0])->service_bitmap = session->bitmaps[VCDP_FLOW_FORWARD];
    } else {
      vcdp_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_CREATE_ERROR_FULL_TABLE]; // TODO: Other causes too, like session exists.
    }
    b[0]->flow_id = flow_index;

next:
    vcdp_next(b[0], next);
    next += 1;
    h += 1;
    k += 1;
    b += 1;
    n_left -= 1;
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
        vcdp_create_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->next_index = nexts[i];
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_NODE_FN(vcdp_create_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
   return vcdp_create_inline(vm, node, frame, false);
}

VLIB_NODE_FN(vcdp_create_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
   return vcdp_create_inline(vm, node, frame, true);
}

VLIB_REGISTER_NODE(vcdp_create_ip4_node) = {
  .name = "vcdp-create",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_create_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_CREATE_N_ERROR,
  .error_counters = vcdp_create_error_counters,
};
VLIB_REGISTER_NODE(vcdp_create_ip6_node) = {
  .name = "vcdp-create-ip6",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_create_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = VCDP_CREATE_N_ERROR,
  .error_counters = vcdp_create_error_counters,
};

VCDP_SERVICE_DEFINE(create) = {
  .node_name = "vcdp-create",
  .runs_before = VCDP_SERVICES("vcdp-drop"),
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 0
};
