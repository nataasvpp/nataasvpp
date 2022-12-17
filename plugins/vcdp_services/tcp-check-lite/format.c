// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vcdp_services/tcp-check/tcp_check.h>

u8 *
format_vcdp_tcp_check_session_flags(u8 *s, va_list *args)
{
  u32 flags = va_arg(*args, u32);
#define _(name, x, str)                                                                                                \
  if (flags & VCDP_TCP_CHECK_SESSION_FLAG_##name)                                                                      \
    s = format(s, "%s", (str));
  foreach_vcdp_tcp_check_session_flag
#undef _

    return s;
}

u32
vcdp_table_format_insert_tcp_check_session(table_t *t, u32 n, vcdp_main_t *vcdp, u32 session_index,
                                           vcdp_session_t *session, vcdp_tcp_check_session_state_t *tcp_session)
{
  u64 session_net = clib_host_to_net_u64(session->session_id);
  vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, session->tenant_idx);
  vcdp_session_ip4_key_t *skey;

  /* Session id */
  table_format_cell(t, n, 0, "0x%U", format_hex_bytes, &session_net, sizeof(session_net));
  /* Tenant id */
  table_format_cell(t, n, 1, "%d", tenant->tenant_id);
  /* Session index */
  table_format_cell(t, n, 2, "%d", session_index);
  /* Session type */
  table_format_cell(t, n, 3, "%U", format_vcdp_session_type, session->type);
  /* Session flags */
  table_format_cell(t, n, 4, "%U", format_vcdp_tcp_check_session_flags, tcp_session->flags);
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4) {
    skey = &session->keys[VCDP_SESSION_KEY_PRIMARY];
    table_format_cell(t, n, 5, "%d", skey->context_id);
    table_format_cell(t, n, 6, "%U:%u", format_ip4_address, &skey->src, skey->sport);
    table_format_cell(t, n, 7, "%U:%u", format_ip4_address, &skey->dst, skey->dport);
  }
  n += 1;
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4) {
    skey = &session->keys[VCDP_SESSION_KEY_SECONDARY];
    table_format_cell(t, n, 5, "%d", skey->context_id);
    table_format_cell(t, n, 6, "%U:%u", format_ip4_address, &skey->src, skey->sport);
    table_format_cell(t, n, 7, "%U:%u", format_ip4_address, &skey->dst, skey->dport);
    n += 1;
  }
  return n;
}
