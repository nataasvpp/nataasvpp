/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vcdp/service.h>
#include <vcdp/vcdp.h>

u8 *
format_vcdp_session_state (u8 *s, va_list *args)
{
  u8 session_state = va_arg (*args, u32);
#define _(n, str)                                                             \
  if (session_state == VCDP_SESSION_STATE_##n)                                \
    s = format (s, "%s", (str));
  foreach_vcdp_session_state
#undef _
    return s;
}

u8 *
format_vcdp_session_type (u8 *s, va_list *args)
{
  u32 session_type = va_arg (*args, u32);
  if (session_type == VCDP_SESSION_TYPE_IP4)
    s = format (s, "ipv4");
  return s;
}

/* Tenant Session_index Session_Type Protocol Context Ingress -> Egress State
 * TTL(seconds) */
u8 *
format_vcdp_session (u8 *s, va_list *args)
{
  u32 session_index = va_arg (*args, u32);
  vcdp_session_t *session = va_arg (*args, vcdp_session_t *);
  u32 tenant_id = va_arg (*args, u32);
  f64 now = va_arg (*args, f64);
  f64 remaining_time = session->timer.next_expiration - now;
  u64 session_net = clib_host_to_net_u64 (session->session_id);
  u8 n_keys = vcdp_session_n_keys (session);
  vcdp_ip4_key_t key;
  vcdp_normalise_key (session, &key, VCDP_SESSION_KEY_PRIMARY);
  s = format (s, "0x%U\t%d\t%d\t%U\t%U\t", format_hex_bytes, &session_net,
	      sizeof (u64), tenant_id, session_index, format_vcdp_session_type,
	      session->type, format_ip_protocol, key.proto);
  s = format (s, "%d\t%U:%u\t-> %U:%u\t%U\t%f",
	      session->key[VCDP_SESSION_KEY_PRIMARY].context_id,
	      format_ip4_address, &key.ip_addr_lo, key.port_lo,
	      format_ip4_address, &key.ip_addr_hi, key.port_hi,
	      format_vcdp_session_state, session->state, remaining_time);
  if (n_keys == 2)
    {
      vcdp_normalise_key (session, &key, VCDP_SESSION_KEY_SECONDARY);
      s = format (s, "\n\t\t\t\t\t\t\t%d\t%U:%u\t-> %U:%u",
		  session->key[VCDP_SESSION_KEY_SECONDARY].context_id,
		  format_ip4_address, &key.ip_addr_lo, key.port_lo,
		  format_ip4_address, &key.ip_addr_hi, key.port_hi);
    }
  return s;
}

u8 *
format_vcdp_bitmap (u8 *s, va_list *args)
{
  u32 bmp = va_arg (*args, u32);
#define _(x, str, idx)                                                        \
  if (bmp & (0x1 << idx))                                                     \
    s = format (s, "%s,", str);
  foreach_vcdp_service
#undef _
    return s;
}

u8 *
format_vcdp_session_detail (u8 *s, va_list *args)
{
  vcdp_per_thread_data_t *ptd = va_arg (*args, vcdp_per_thread_data_t *);
  u32 session_index = va_arg (*args, u32);
  f64 now = va_arg (*args, f64);
  vcdp_session_t *session = vcdp_session_at_index (ptd, session_index);

  f64 remaining_time = session->timer.next_expiration - now;
  u64 session_net = clib_host_to_net_u64 (session->session_id);
  vlib_counter_t fctr, bctr;
  uword thread_index = ptd - vcdp_main.per_thread_data;
  vcdp_ip4_key_t key;
  vlib_get_combined_counter (&ptd->per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP],
			     session_index << 1, &fctr);
  vlib_get_combined_counter (&ptd->per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP],
			     (session_index << 1) | 0x1, &bctr);
  /* TODO: deal with secondary keys */
  vcdp_normalise_key (session, &key, VCDP_SESSION_KEY_PRIMARY);

  s = format (s, "  session id: 0x%U\n", format_hex_bytes, &session_net,
	      sizeof (u64));
  s = format (s, "  thread index: %d\n", thread_index);
  s = format (s, "  session index: %d\n", session_index);
  s = format (s, "  specification: %U\t%U:%u\t-> %U:%u\n", format_ip_protocol,
	      key.proto, format_ip4_address, &key.ip_addr_lo, key.port_lo,
	      format_ip4_address, &key.ip_addr_hi, key.port_hi);
  s = format (s, "  state: %U\n", format_vcdp_session_state, session->state);
  s = format (s, "  expires after: %fs\n", remaining_time);
  s = format (s, "  forward service chain: %U\n", format_vcdp_bitmap,
	      session->bitmaps[VCDP_FLOW_FORWARD]);
  s = format (s, "  reverse service chain: %U\n", format_vcdp_bitmap,
	      session->bitmaps[VCDP_FLOW_REVERSE]);
  s = format (s, "  counters:\n");
  s = format (s, "    forward flow:\n");
  s = format (s, "      bytes: %llu\n", fctr.bytes);
  s = format (s, "      packets: %llu\n", fctr.packets);
  s = format (s, "    reverse flow:\n");
  s = format (s, "      bytes: %llu\n", bctr.bytes);
  s = format (s, "      packets: %llu\n", bctr.packets);
  return s;
}

u8 *
format_vcdp_tenant (u8 *s, va_list *args)
{

  u32 indent = format_get_indent (s);
  __clib_unused vcdp_main_t *vcdp = va_arg (*args, vcdp_main_t *);
  u32 tenant_idx = va_arg (*args, u32);
  vcdp_tenant_t *tenant = va_arg (*args, vcdp_tenant_t *);
  s = format (s, "index: %d\n", tenant_idx);
  s = format (s, "%Ucontext: %d\n", format_white_space, indent,
	      tenant->context_id);
  s = format (s, "%Uforward service chain:\n", format_white_space, indent);
  s = format (s, "%U%U\n", format_white_space, indent + 2, format_vcdp_bitmap,
	      tenant->bitmaps[VCDP_FLOW_FORWARD]);
  s = format (s, "%Ureverse service chain:\n", format_white_space, indent);
  s = format (s, "%U%U\n", format_white_space, indent + 2, format_vcdp_bitmap,
	      tenant->bitmaps[VCDP_FLOW_REVERSE]);
  return s;
}

u8 *
format_vcdp_tenant_extra (u8 *s, va_list *args)
{
  u32 indent = format_get_indent (s);
  vcdp_main_t *vcdp = va_arg (*args, vcdp_main_t *);
  u32 tenant_idx = va_arg (*args, u32);
  __clib_unused vcdp_tenant_t *tenant = va_arg (*args, vcdp_tenant_t *);
  counter_t ctr;
  vlib_counter_t ctr2;
  s = format (s, "%s\n", "Counters:");

#define _(x, y, z)                                                            \
  ctr = vlib_get_simple_counter (                                             \
    &vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x], tenant_idx);  \
  s = format (s, "%U%s: %llu\n", format_white_space, indent + 2, z, ctr);
  foreach_vcdp_tenant_session_counter
#undef _
#define _(x, y, z)                                                            \
  vlib_get_combined_counter (                                                 \
    &vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x], tenant_idx, &ctr2); \
  s = format (s, "%U%s: %llu packets\n", format_white_space, indent + 2, z,   \
	      ctr2.packets);                                                  \
  s = format (s, "%U  %llu bytes\n", format_white_space,                      \
	      indent + strlen (z) + 2, ctr2.bytes);
    foreach_vcdp_tenant_data_counter
#undef _
      s = format (s, "%U%s\n", format_white_space, indent,
		  "Configured Timeout:");

#define _(x, y, z)                                                            \
  s = format (s, "%U%s: %d seconds\n", format_white_space, indent + 2, z,     \
	      tenant->timeouts[VCDP_TIMEOUT_##x]);
  foreach_vcdp_timeout
#undef _
    return s;
}
