// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/service.h>
#include <vcdp/lookup/lookup_inlines.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <cbor.h>
#include "punt.h"

#define foreach_vcdp_punt_error _(PUNT, "punt")

typedef enum {
#define _(sym, str) VCDP_PUNT_ERROR_##sym,
  foreach_vcdp_punt_error
#undef _
    VCDP_PUNT_N_ERROR,
} vcdp_punt_error_t;

static char *vcdp_punt_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_punt_error
#undef _
};

typedef enum {
  VCDP_PUNT_NEXT_DROP,
  VCDP_PUNT_NEXT_LOOKUP,
  VCDP_PUNT_N_NEXT
} vcdp_punt_next_t;
typedef enum {
  VCDP_PUNT_INPUT_NEXT_DROP,
  VCDP_PUNT_INPUT_N_NEXT
} vcdp_punt_input_next_t;

typedef struct {
  u32 flow_id;
} vcdp_punt_trace_t;

static u8 *
format_vcdp_punt_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_punt_trace_t *t = va_arg(*args, vcdp_punt_trace_t *);

  s = format(s, "vcdp-punt: flow-id %u (session %u, %s)", t->flow_id, t->flow_id >> 1,
             t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

u32
vcdp_create_session_v4_core(u32 tenant_id, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst, u16 dport);

int
vcdp_nat_session_create(u32 session_idx, int instr, u8 proto, ip4_address_t old_addr, u16 old_port,
                        ip4_address_t new_addr, u16 new_port);

static void process_item(cbor_item_t *item)
{
  u8 action = cbor_get_int(cbor_array_get(item, 0));
  u8 *src = cbor_bytestring_handle(cbor_tag_item(cbor_array_get(item, 1)));
  u16 sport = cbor_get_int(cbor_array_get(item, 2));
  u8 proto = cbor_get_int(cbor_array_get(item, 3));
  u8 *dst = cbor_bytestring_handle(cbor_tag_item(cbor_array_get(item, 4)));
  u16 dport = cbor_get_int(cbor_array_get(item, 5));
  int instr = cbor_get_int(cbor_array_get(item, 6));
  u8 *rwr_addr = cbor_bytestring_handle(cbor_tag_item(cbor_array_get(item, 7)));
  u16 rwr_port = cbor_get_int(cbor_array_get(item, 8));

  switch (action) {
  case 1: // Create session
    u32 tenant_id = 0;
    ip_address_t ipsrc, ipdst;
    clib_memcpy(&ipsrc.ip.ip4, src, 4);
    clib_memcpy(&ipdst.ip.ip4, dst, 4);

    u32 session_idx = vcdp_create_session_v4_core(tenant_id, &ipsrc, clib_host_to_net_u16(sport), proto, &ipdst,
                                                  clib_host_to_net_u16(dport));

    clib_warning("Create session: %d", session_idx);
    clib_warning("Action: %d %U %U %d %d %d %U %d", action, format_ip4_address, src, format_ip4_address, dst, sport,
                 dport, instr, format_ip4_address, rwr_addr, rwr_port);

    // Create NAT rewrite
    ip4_address_t rewrite;
    clib_memcpy(&rewrite, rwr_addr, 4);
    if (instr == 0)
      vcdp_nat_session_create(session_idx, instr, proto, ipsrc.ip.ip4, clib_host_to_net_u16(sport), rewrite,
                              clib_host_to_net_u16(rwr_port));
    else
      vcdp_nat_session_create(session_idx, instr, proto, ipdst.ip.ip4, clib_host_to_net_u16(dport), rewrite,
                              clib_host_to_net_u16(rwr_port));
    break;
  case 2: // Delete session
    // NOT YET IMPLEMENTED
  default:
    clib_warning("Action not supported: %d", action);
    return;
  }
}

VLIB_NODE_FN(vcdp_punt_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *from, *bi;
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE] = {0}, *next = nexts;

  from = vlib_frame_vector_args(frame);
  vlib_get_buffers(vm, from, b, n_left);

  b = bufs;
  next = nexts;
  bi = from;
  n_left = frame->n_vectors;

  while (n_left > 0) {
    next[0] = VCDP_PUNT_INPUT_NEXT_DROP;
    clib_warning("Receiving instructions from the control-plane");
    b[0]->error = 0;
    size_t length;
    void *data = vlib_buffer_get_current(b[0]);
    udp_header_t *udp = (udp_header_t *) (vlib_buffer_get_current(b[0]) - sizeof(udp_header_t));
    length = udp->length - sizeof(udp_header_t);
    struct cbor_load_result result;
    cbor_item_t *root = cbor_load(data, length, &result);
    for (size_t i = 0; i < cbor_array_size(root); i++) {
      process_item(cbor_array_get(root, i));
    }

    /* Pretty-print the result */
    cbor_describe(root, stdout);
    fflush(stdout);
    /* Deallocate the result */
    cbor_decref(&root);

    // next:
    b += 1;
    n_left -= 1;
    bi += 1;
    next += 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter(vm, node->node_index, VCDP_PUNT_ERROR_PUNT, n_left);
  n_left = frame->n_vectors;
  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    vlib_get_buffers(vm, from, bufs, n_left);
    b = bufs;
    for (i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_punt_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_punt_input_node) = {
  .name = "vcdp-punt-input",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_punt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_punt_error_strings),
  .error_strings = vcdp_punt_error_strings,
  .n_next_nodes = VCDP_PUNT_INPUT_N_NEXT,
  .next_nodes = { "error-drop"}
};

cbor_item_t *
vcdp_encode_key (vcdp_session_ip4_key_t *key)
{
  // Python Cbor only supports 260, let's move to 52 later
  cbor_item_t *src = cbor_build_tag(260, cbor_build_bytestring((cbor_data)&key->src, 4));
  cbor_item_t *dst = cbor_build_tag(260, cbor_build_bytestring((cbor_data)&key->dst, 4));
  cbor_item_t *array = cbor_new_definite_array(6);

  cbor_array_push(array, cbor_move(cbor_build_uint8(0))); // Mapping request
  cbor_array_push(array, cbor_move(src));
  cbor_array_push(array, cbor_move(cbor_build_uint16(clib_net_to_host_u16(key->sport))));
  cbor_array_push(array, cbor_move(cbor_build_uint8(key->proto)));
  cbor_array_push(array, cbor_move(dst));
  cbor_array_push(array, cbor_move(cbor_build_uint16(clib_net_to_host_u16(key->dport))));
  return array;
}

/*
 * Drop packet and send a mapping request to the control plane.
 * Encode 5-tuple key as CBOR in an array.
 * 
 * - Separate UDP listener to receive mapping responses.
 */
VLIB_NODE_FN(vcdp_punt_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_punt_main_t *pm = &vcdp_punt_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *from, *bi;
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE] = {0}, *next = nexts;

  from = vlib_frame_vector_args(frame);
  vlib_get_buffers(vm, from, b, n_left);

  vcdp_session_ip4_key_t keys[VLIB_FRAME_SIZE], *k4= keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  int service_chain[VLIB_FRAME_SIZE], *sc = service_chain;

  // Re-calculate key (and hash)
  while (n_left) {
    vcdp_calc_key_v4 (b[0], b[0]->flow_id, k4, h, sc);

    h += 1;
    k4 += 1;
    b += 1;
    sc += 1;
    n_left -= 1;
  }

  k4 = keys;
  b = bufs;
  next = nexts;
  bi = from;
  n_left = frame->n_vectors;

  while (n_left > 0) {
    // First instantiation of the control plane protocol.
    // Hijack packet buffer to be the UDP control packet.

    next[0] = VCDP_PUNT_NEXT_LOOKUP;
    clib_warning("Punting packet with flow-id %u", b[0]->flow_id);
    ip4_header_t *ip = vlib_buffer_get_current(b[0]);
    ip->checksum = 0;
    ip->ttl = 64;
    ip->src_address.as_u32 = pm->src.as_u32;
    ip->dst_address.as_u32 = pm->dst.as_u32;
    ip->protocol = IP_PROTOCOL_UDP;

    udp_header_t *udp = (udp_header_t *)(ip + 1);
    udp->src_port = clib_host_to_net_u16(33434);
    udp->dst_port = clib_host_to_net_u16(33434);
    udp->checksum = 0;
    u8 *data = (u8 *)(udp + 1);

    // Encode 5-tuple key as CBOR in an array.
    clib_warning("Encoding key as CBOR %U", format_vcdp_session_key, k4);
    cbor_item_t *root = cbor_new_definite_array(1);
    cbor_array_push(root, cbor_move(vcdp_encode_key(k4)));

    /* Output: `buffer_size` bytes of data in the `buffer` */
    size_t buffer_size = 512;
    buffer_size = cbor_serialize(root, data, buffer_size);
    clib_warning("Serialized CBOR %d bytes: %U", buffer_size, format_hex_bytes, data, buffer_size);
    cbor_describe(root, stdout);
    cbor_decref(&root);

    clib_warning("Wrote %d bytes of CBOR", buffer_size);

    udp->length = clib_host_to_net_u16(buffer_size + sizeof(udp_header_t));
    ip->length = clib_host_to_net_u16(buffer_size + sizeof(udp_header_t) + sizeof(ip4_header_t));
    ip->checksum = ip4_header_checksum(ip);
    b[0]->current_length = buffer_size + sizeof(udp_header_t) + sizeof(ip4_header_t);
    b[0]->error = 0;

  // next:
    b += 1;
    n_left -= 1;
    k4 += 1;
    bi += 1;
    next += 1;
  }

  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter(vm, node->node_index, VCDP_PUNT_ERROR_PUNT, n_left);
  n_left = frame->n_vectors;
  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    vlib_get_buffers(vm, from, bufs, n_left);
    b = bufs;
    for (i = 0; i < n_left; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_punt_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        b++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(vcdp_punt_node) = {
  .name = "vcdp-punt",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_punt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_punt_error_strings),
  .error_strings = vcdp_punt_error_strings,
  .n_next_nodes = VCDP_PUNT_N_NEXT,
  .next_nodes = { "error-drop", "ip4-lookup", "ip4-receive" }
};

VCDP_SERVICE_DEFINE(vcdp_punt) = {
  .node_name = "vcdp-punt", 
  .runs_before = VCDP_SERVICES(0), 
  .runs_after = VCDP_SERVICES(0),
  .is_terminal = 1
};