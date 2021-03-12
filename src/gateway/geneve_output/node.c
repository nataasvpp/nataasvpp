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
} vcdp_geneve_output_trace_t;

static u8 *
format_vcdp_geneve_output_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_geneve_output_trace_t *t = va_arg (*args, vcdp_geneve_output_trace_t *);

  s = format (s, "vcdp-geneve_output: flow-id %u (session %u, %s)", t->flow_id,
	      t->flow_id >> 1, t->flow_id & 0x1 ? "backward" : "forward");
  return s;
}

static_always_inline int
vcdp_geneve_output_load_data (gw_main_t *gm,
			      gw_geneve_output_data_t *geneve_out,
			      vcdp_session_t *session, vlib_buffer_t *b,
			      u32 session_idx)
{
  gw_tenant_t *tenant = gw_tenant_at_index (gm, session_idx);
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
  ip4->length = /* stored in host byte order, incremented and swapped
		   later */
    sizeof (ip4_header_t) + sizeof (udp_header_t) + 8 /*(geneve)*/ +
    sizeof (ethernet_header_t);
  ip4->checksum = ip4_header_checksum (ip4);
  geneve_out->encap_size += sizeof (*ip4);
  udp = (void *) (geneve_out->encap_data + geneve_out->encap_size);
  udp->src_port = tenant->geneve_src_port[direction];
  udp->dst_port = tenant->geneve_dst_port[direction];
  udp->checksum = 0;
  udp->length = /* stored in host byte order, incremented and swapped
		   later */
    sizeof (udp_header_t) + 8 /*(geneve)*/ + sizeof (ethernet_header_t);
  geneve_out->encap_size += sizeof (*udp);
  gnv = (void *) (geneve_out->encap_data + geneve_out->encap_size);
  gnv[0] = clib_host_to_net_u32 (0x6558); /*no option geneve version 0*/
  gnv[1] = clib_host_to_net_u32 (tenant->tenant_id << 8);
  geneve_out->encap_size += 8;
  eth = (void *) (geneve_out->encap_data + geneve_out->encap_size);
  clib_memcpy_fast (&eth, b->data + b->current_data - sizeof (*eth),
		    sizeof (*eth));
  geneve_out->encap_size += sizeof (*eth);
  ASSERT (geneve_out->encap_size < sizeof (geneve_out->encap_data));
  return 0;
}

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
  vcdp_session_t *session;
  gw_geneve_output_data_t *geneve_out;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left)
    {
      u32 session_idx = vcdp_session_from_flow_index (b[0]->flow_id);
      session = vcdp_session_at_index (vptd, session_idx);
      geneve_out = vec_elt_at_index (gptd->output, b[0]->flow_id);

      if (PREDICT_FALSE (geneve_out->session_version !=
			   session->session_version &&
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
	  u8 *data;
	  u16 orig_len = b[0]->current_length;
	  b[0]->flags |= VNET_BUFFER_F_OFFLOAD;
	  vnet_buffer2 (b[0])->oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;
	  vlib_buffer_advance (b[0], -geneve_out->encap_size);
	  data = vlib_buffer_get_current (b[0]);
	  clib_memcpy_fast (data, geneve_out->encap_data,
			    geneve_out->encap_size);
	  /* fixup */
	  ip = (void *) data;
	  ip->length = clib_net_to_host_u16 (ip->length + orig_len);
	  udp = (void *) (data + sizeof (udp_header_t));
	  udp->length = clib_net_to_host_u16 (udp->length + orig_len);
	  to_next[0] = VCDP_GENEVE_OUTPUT_NEXT_IP4_LOOKUP;
	}
      to_next++;
      b++;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      n_left = frame->n_vectors;
      vlib_get_buffers (vm, from, bufs, n_left);
      b = bufs;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vcdp_geneve_output_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
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