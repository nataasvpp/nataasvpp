/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vcdp/vcdp.h>
#include <vcdp_services/tcp-check/tcp_check.h>

u8 *
format_vcdp_tcp_check_session_flags(u8 *s, va_list *args) {
  u32 flags = va_arg(*args, u32);
#define _(name, x, str)                                                        \
  if (flags & VCDP_TCP_CHECK_SESSION_FLAG_##name)                              \
    s = format(s, "%s", (str));
  foreach_vcdp_tcp_check_session_flag
#undef _

    return s;
}

u32
vcdp_table_format_insert_tcp_check_session(
  table_t *t, u32 n, vcdp_main_t *vcdp, u32 session_index,
  vcdp_session_t *session, vcdp_tcp_check_session_state_t *tcp_session) {
  u64 session_net = clib_host_to_net_u64(session->session_id);
  vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, session->tenant_idx);
  vcdp_session_ip46_key_t skey;
  vcdp_ip4_key_t *key4 = &skey.key4.ip4_key;
  vcdp_ip6_key_t *key6 = &skey.key6.ip6_key;
  /* Session id */
  table_format_cell(t, n, 0, "0x%U", format_hex_bytes, &session_net,
                    sizeof(session_net));
  /* Tenant id */
  table_format_cell(t, n, 1, "%d", tenant->tenant_id);
  /* Session index */
  table_format_cell(t, n, 2, "%d", session_index);
  /* Session type */
  table_format_cell(t, n, 3, "%U", format_vcdp_session_type, session->type);
  /* Session flags */
  table_format_cell(t, n, 4, "%U", format_vcdp_tcp_check_session_flags,
                    tcp_session->flags);
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4) {
    vcdp_normalise_ip4_key(session, &skey.key4, VCDP_SESSION_KEY_PRIMARY);
    table_format_cell(t, n, 5, "%d", skey.key4.context_id);
    table_format_cell(t, n, 6, "%U:%u", format_ip4_address, &key4->ip_addr_lo,
                      key4->port_lo);
    table_format_cell(t, n, 7, "%U:%u", format_ip4_address, &key4->ip_addr_hi,
                      key4->port_hi);
  } else if (session->key_flags & VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6) {
    vcdp_normalise_ip6_key(session, &skey.key6, VCDP_SESSION_KEY_PRIMARY);
    table_format_cell(t, n, 5, "%d", skey.key6.context_id);
    table_format_cell(t, n, 6, "%U:%u", format_ip6_address, &key6->ip6_addr_lo,
                      key6->port_lo);
    table_format_cell(t, n, 7, "%U:%u", format_ip6_address, &key6->ip6_addr_hi,
                      key6->port_hi);
  }
  n += 1;
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4) {
    vcdp_normalise_ip4_key(session, &skey.key4, VCDP_SESSION_KEY_SECONDARY);
    table_format_cell(t, n, 5, "%d", skey.key4.context_id);
    table_format_cell(t, n, 6, "%U:%u", format_ip4_address, &key4->ip_addr_lo,
                      key4->port_lo);
    table_format_cell(t, n, 7, "%U:%u", format_ip4_address, &key4->ip_addr_hi,
                      key4->port_hi);
    n += 1;
  } else if (session->key_flags & VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6) {
    vcdp_normalise_ip6_key(session, &skey.key6, VCDP_SESSION_KEY_SECONDARY);
    table_format_cell(t, n, 5, "%d", skey.key6.context_id);
    table_format_cell(t, n, 6, "%U:%u", format_ip6_address, &key6->ip6_addr_lo,
                      key6->port_lo);
    table_format_cell(t, n, 7, "%U:%u", format_ip6_address, &key6->ip6_addr_hi,
                      key6->port_hi);
    n += 1;
  }
  return n;
}
