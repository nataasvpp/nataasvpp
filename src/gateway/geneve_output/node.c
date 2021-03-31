/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <gateway/gateway.h>
#include <vcdp/common.h>

#define VCDP_GENEVE_OPTION_CLASS	   ((u16) 0xDEAD)
#define VCDP_GENEVE_OPTION_TYPE_SESSION_ID ((u8) 0xBE)
#define VCDP_GENEVE_OPTION_SESSION_ID_SIZE ((u8) 0x2)
#define VCDP_GENEVE_OPTION_SESSION_ID_FIRST_WORD                              \
  (VCDP_GENEVE_OPTION_CLASS << 16) |                                          \
    (VCDP_GENEVE_OPTION_TYPE_SESSION_ID << 8) |                               \
    (VCDP_GENEVE_OPTION_SESSION_ID_SIZE << 0)
#define VCDP_GENEVE_OPTION_LEN (12)
#define VCDP_GENEVE_TOTAL_LEN  (8 + VCDP_GENEVE_OPTION_LEN)

#define foreach_vcdp_geneve_output_error _ (NO_OUTPUT, "no output data")

typedef enum
{
#define _(sym, str) VCDP_GENEVE_OUTPUT_ERROR_##sym,
  foreach_vcdp_geneve_output_error
#undef _
    VCDP_GENEVE_OUTPUT_N_ERROR,
} vcdp_geneve_output_error_t;

static char *vcdp_geneve_output_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_geneve_output_error
#undef _
};

#define foreach_vcdp_geneve_output_next                                       \
  _ (DROP, "error-drop")                                                      \
  _ (IP4_LOOKUP, "ip4-lookup")

typedef enum
{
#define _(n, x) VCDP_GENEVE_OUTPUT_NEXT_##n,
  foreach_vcdp_geneve_output_next
#undef _
    VCDP_GENEVE_OUTPUT_N_NEXT
} vcdp_geneve_output_next_t;

typedef struct
{
  u32 flow_id;
  u16 encap_size;
  u8 encap_data[124];
} vcdp_geneve_output_trace_t;

static u8 *
format_vcdp_geneve_output_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_geneve_output_trace_t *t = va_arg (*args, vcdp_geneve_output_trace_t *);
  u32 indent = format_get_indent (s);
  s =
    format (s, "vcdp-geneve_output: flow-id %u (session %u, %s)\n", t->flow_id,
	    t->flow_id >> 1, t->flow_id & 0x1 ? "backward" : "forward");
  s = format (s, "%U", format_white_space, indent);
  s = format (s, "encap-data: %U", format_hex_bytes, t->encap_data,
	      t->encap_size);
  return s;
}

static_always_inline int
vcdp_geneve_output_load_data (gw_main_t *gm,
			      gw_geneve_output_data_t *geneve_out,
			      vcdp_session_t *session, vlib_buffer_t *b,
			      u32 session_idx)
{
  u32 tenant_idx = vcdp_buffer (b)->tenant_index;
  gw_tenant_t *tenant = gw_tenant_at_index (gm, tenant_idx);
  u8 direction = b->flow_id & 0x1;
  ip4_header_t *ip4 = (void *) geneve_out->encap_data;
  udp_header_t *udp;
  ethernet_header_t *eth;
  u32 *gnv;
  if (PREDICT_FALSE (!(tenant->flags & GW_TENANT_F_OUTPUT_DATA_SET)))
    return -1;
  geneve_out->session_version = session->session_version;
  geneve_out->encap_size = 0;
  /* Start with IP header */
  ip4->src_address = tenant->geneve_src_ip[direction];
  ip4->dst_address = tenant->geneve_dst_ip[direction];
  ip4->protocol = IP_PROTOCOL_UDP;
  ip4->ip_version_and_header_length = 0x45;
  ip4->tos = IP_DSCP_CS0;
  ip4->ttl = 0xff;
  ip4->flags_and_fragment_offset = 0;
  ip4->length = 0;
  ip4->checksum = ip4_header_checksum (ip4);
  ip4->length = /* stored in host byte order, incremented and swapped
		   later */
    sizeof (ip4_header_t) + sizeof (udp_header_t) + VCDP_GENEVE_TOTAL_LEN +
    sizeof (ethernet_header_t);
  geneve_out->encap_size += sizeof (*ip4);
  udp = (void *) (geneve_out->encap_data + geneve_out->encap_size);
  udp->src_port = tenant->geneve_src_port[direction];
  udp->dst_port = tenant->geneve_dst_port[direction];
  udp->checksum = 0;
  udp->length = /* stored in host byte order, incremented and swapped
		   later */
    sizeof (udp_header_t) + VCDP_GENEVE_TOTAL_LEN + sizeof (ethernet_header_t);
  geneve_out->encap_size += sizeof (*udp);
  gnv = (void *) (geneve_out->encap_data + geneve_out->encap_size);
  gnv[0] =
    // Not sure if 0x0C or 0x03 (number of bytes or of 4B-words???)
    clib_host_to_net_u32 (0x0C006558); /*3 words of option geneve version 0*/
  gnv[1] = clib_host_to_net_u32 (tenant->tenant_id << 8);
  gnv[2] = clib_host_to_net_u32 (VCDP_GENEVE_OPTION_SESSION_ID_FIRST_WORD);
  /* TODO: proper session id generation !!! (upon creation) */
  gnv[3] =
    clib_host_to_net_u32 (session->session_version); /* session id low  */
  gnv[4] = clib_host_to_net_u32 (session_idx);	     /* session id high */
  geneve_out->encap_size += VCDP_GENEVE_TOTAL_LEN;
  eth = (void *) (geneve_out->encap_data + geneve_out->encap_size);
  /* TODO: fix mac to something decent (right now,
   we take old mac src/dst and behave as "bump in the wire") */
  clib_memcpy_fast (eth, b->data + b->current_data - sizeof (*eth),
		    sizeof (*eth));
  geneve_out->encap_size += sizeof (*eth);
  ASSERT (geneve_out->encap_size < sizeof (geneve_out->encap_data));
  return 0;
}

static_always_inline void
geneve_output_rewrite_one (vlib_main_t *vm, vlib_node_runtime_t *node,
			   gw_main_t *gm, gw_geneve_output_data_t *geneve_out,
			   vcdp_session_t *session, u32 session_idx,
			   u16 *to_next, vlib_buffer_t **b)
{
  if (PREDICT_FALSE (geneve_out->session_version != session->session_version &&
		     vcdp_geneve_output_load_data (gm, geneve_out, session,
						   b[0], session_idx)))
    {
      to_next[0] = VCDP_GENEVE_OUTPUT_NEXT_DROP;
      vlib_node_increment_counter (vm, node->node_index,
				   VCDP_GENEVE_OUTPUT_ERROR_NO_OUTPUT, 1);
    }
  else
    {
      ip4_header_t *ip;
      udp_header_t *udp;
      ip_csum_t csum;
      u8 *data;
      u16 orig_len = vlib_buffer_length_in_chain (vm, b[0]);
      b[0]->flags |=
	(VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
      vnet_buffer2 (b[0])->oflags |=
	VNET_BUFFER_OFFLOAD_F_UDP_CKSUM | VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
      vlib_buffer_advance (b[0], -geneve_out->encap_size);
      data = vlib_buffer_get_current (b[0]);
      vnet_buffer (b[0])->l3_hdr_offset = b[0]->current_data;
      vnet_buffer (b[0])->l4_hdr_offset =
	b[0]->current_data + sizeof (ip4_header_t);
      clib_memcpy_fast (data, geneve_out->encap_data, geneve_out->encap_size);
      /* fixup */
      ip = (void *) data;
      ip->length = clib_net_to_host_u16 (ip->length + orig_len);
      csum = ip->checksum;
      csum = ip_csum_update (csum, 0, ip->length, ip4_header_t, length);
      ip->checksum = ip_csum_fold (csum);
      udp = (void *) (data + sizeof (ip4_header_t));
      udp->length = clib_net_to_host_u16 (udp->length + orig_len);
      to_next[0] = VCDP_GENEVE_OUTPUT_NEXT_IP4_LOOKUP;
    }
}

#define vlib_prefetch_buffer_data_with_offset(b, type, offset)                \
  CLIB_PREFETCH (b->data + b->current_data + (offset), CLIB_CACHE_LINE_BYTES, \
		 type)
VLIB_NODE_FN (vcdp_geneve_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  gw_main_t *gm = &gateway_main;
  vcdp_main_t *vcdp = &vcdp_main;

  u32 thread_index = vm->thread_index;
  gw_per_thread_data_t *gptd =
    vec_elt_at_index (gm->per_thread_data, thread_index);
  vcdp_per_thread_data_t *vptd =
    vec_elt_at_index (vcdp->per_thread_data, thread_index);

  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);

  /* Pipeline load buffer data -> load session_data + geneve_output_data
   * ->process */
  while (n_left >= 2)
    {
      u32 si0, si1, si2, si3;
      vcdp_session_t *session0, *session1;
      gw_geneve_output_data_t *geneve_out0, *geneve_out1;
      if (n_left >= 6)
	{
	  vlib_prefetch_buffer_header (b[4], STORE);
	  vlib_prefetch_buffer_header (b[5], STORE);
	  vlib_prefetch_buffer_data_with_offset (b[4], STORE, -64);
	  vlib_prefetch_buffer_data_with_offset (b[5], STORE, -64);
	}
      if (n_left >= 4)
	{
	  si2 = vcdp_session_from_flow_index (b[2]->flow_id);
	  si3 = vcdp_session_from_flow_index (b[3]->flow_id);
	  CLIB_PREFETCH (vptd->sessions + si2, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (vptd->sessions + si3, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (gptd->output + b[2]->flow_id,
			 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (gptd->output + b[3]->flow_id,
			 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	}
      si0 = vcdp_session_from_flow_index (b[0]->flow_id);
      si1 = vcdp_session_from_flow_index (b[1]->flow_id);
      session0 = vcdp_session_at_index (vptd, si0);
      session1 = vcdp_session_at_index (vptd, si1);
      geneve_out0 = vec_elt_at_index (gptd->output, b[0]->flow_id);
      geneve_out1 = vec_elt_at_index (gptd->output, b[1]->flow_id);

      geneve_output_rewrite_one (vm, node, gm, geneve_out0, session0, si0,
				 to_next, b);
      geneve_output_rewrite_one (vm, node, gm, geneve_out1, session1, si1,
				 to_next + 1, b + 1);

      to_next += 2;
      b += 2;
      n_left -= 2;
    }

  while (n_left)
    {
      u32 session_idx = vcdp_session_from_flow_index (b[0]->flow_id);
      vcdp_session_t *session = vcdp_session_at_index (vptd, session_idx);
      gw_geneve_output_data_t *geneve_out =
	vec_elt_at_index (gptd->output, b[0]->flow_id);

      geneve_output_rewrite_one (vm, node, gm, geneve_out, session,
				 session_idx, to_next, b);
      to_next++;
      b++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      n_left = frame->n_vectors;
      b = bufs;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vcdp_geneve_output_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      t->encap_size = gptd->output[b[0]->flow_id].encap_size;
	      clib_memcpy_fast (t->encap_data,
				gptd->output[b[0]->flow_id].encap_data,
				gptd->output[b[0]->flow_id].encap_size);
	      b++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (vcdp_geneve_output_node) = {
  .name = "vcdp-geneve-output",
  .vector_size = sizeof (u32),
  .format_trace = format_vcdp_geneve_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (vcdp_geneve_output_error_strings),
  .error_strings = vcdp_geneve_output_error_strings,

  .n_next_nodes = VCDP_GENEVE_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(n, x) [VCDP_GENEVE_OUTPUT_NEXT_##n] = x,
          foreach_vcdp_geneve_output_next
#undef _
  }

};