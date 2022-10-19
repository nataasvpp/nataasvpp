// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vcdp/service.h>
#include <vcdp/vcdp.h>
#include <vppinfra/format_table.h>

u8 *
format_vcdp_session_state(u8 *s, va_list *args) {
  u8 session_state = va_arg(*args, u32);
#define _(n, str)                                                              \
  if (session_state == VCDP_SESSION_STATE_##n)                                 \
    s = format(s, "%s", (str));
  foreach_vcdp_session_state
#undef _
    return s;
}

u8 *
format_vcdp_session_type(u8 *s, va_list *args) {
  u32 session_type = va_arg(*args, u32);
  if (session_type == VCDP_SESSION_TYPE_IP4)
    s = format(s, "ipv4");
  else if (session_type == VCDP_SESSION_TYPE_IP6)
    s = format(s, "ipv6");
  return s;
}

u32
vcdp_table_format_insert_session(table_t *t, u32 n, u32 session_index,
                                 vcdp_session_t *session, u32 tenant_id,
                                 f64 now) {
  f64 remaining_time = session->timer.next_expiration - now;
  u64 session_net = clib_host_to_net_u64(session->session_id);
  vcdp_session_ip46_key_t skey;
  vcdp_ip4_key_t *key4 = &skey.key4.ip4_key;
  vcdp_ip6_key_t *key6 = &skey.key6.ip6_key;
  /* Session id */
  table_format_cell(t, n, 0, "0x%U", format_hex_bytes, &session_net,
                    sizeof(session_net));
  /* Tenant id */
  table_format_cell(t, n, 1, "%d", tenant_id);
  /* Session index */
  table_format_cell(t, n, 2, "%d", session_index);
  /* Session type */
  table_format_cell(t, n, 3, "%U", format_vcdp_session_type, session->type);
  /* Protocol */
  table_format_cell(t, n, 4, "%U", format_ip_protocol, session->proto);
  /* Session state */
  table_format_cell(t, n, 8, "%U", format_vcdp_session_state, session->state);
  /* Remaining time */
  table_format_cell(t, n, 9, "%f", remaining_time);

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

u8 *
format_vcdp_bitmap(u8 *s, va_list *args) {
  u32 bmp = va_arg(*args, u32);
  vcdp_service_main_t *sm = &vcdp_service_main;
  int i;
  for (i = 0; i < vec_len(sm->services); i++)
    if (bmp & sm->services[i]->service_mask[0])
      s = format(s, "%s,", sm->services[i]->node_name);
  return s;
}

u8 *
format_vcdp_session_detail(u8 *s, va_list *args) {
  vcdp_per_thread_data_t *ptd = va_arg(*args, vcdp_per_thread_data_t *);
  u32 session_index = va_arg(*args, u32);
  f64 now = va_arg(*args, f64);
  vcdp_session_t *session = vcdp_session_at_index(ptd, session_index);

  f64 remaining_time = session->timer.next_expiration - now;
  u64 session_net = clib_host_to_net_u64(session->session_id);
  vlib_counter_t fctr, bctr;
  uword thread_index = ptd - vcdp_main.per_thread_data;
  vcdp_session_ip46_key_t skey;
  vcdp_ip4_key_t *key4 = &skey.key4.ip4_key;
  vcdp_ip6_key_t *key6 = &skey.key6.ip6_key;
  vlib_get_combined_counter(&ptd->per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP],
                            session_index << 1, &fctr);
  vlib_get_combined_counter(&ptd->per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP],
                            (session_index << 1) | 0x1, &bctr);
  /* TODO: deal with secondary keys */
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    vcdp_normalise_ip4_key(session, &skey.key4, VCDP_SESSION_KEY_PRIMARY);
  else
    vcdp_normalise_ip6_key(session, &skey.key6, VCDP_SESSION_KEY_PRIMARY);

  s = format(s, "  session id: 0x%U\n", format_hex_bytes, &session_net,
             sizeof(u64));
  s = format(s, "  thread index: %d\n", thread_index);
  s = format(s, "  session index: %d\n", session_index);
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    s =
      format(s, "  specification: %U\t%U:%u\t-> %U:%u\n", format_ip_protocol,
             key4->proto, format_ip4_address, &key4->ip_addr_lo, key4->port_lo,
             format_ip4_address, &key4->ip_addr_hi, key4->port_hi);
  else
    s =
      format(s, "  specification: %U\t%U:%u\t-> %U:%u\n", format_ip_protocol,
             key6->proto, format_ip6_address, &key6->ip6_addr_lo, key6->port_lo,
             format_ip6_address, &key6->ip6_addr_hi, key6->port_hi);
  s = format(s, "  state: %U\n", format_vcdp_session_state, session->state);
  s = format(s, "  expires after: %fs\n", remaining_time);
  s = format(s, "  forward service chain: %U\n", format_vcdp_bitmap,
             session->bitmaps[VCDP_FLOW_FORWARD]);
  s = format(s, "  reverse service chain: %U\n", format_vcdp_bitmap,
             session->bitmaps[VCDP_FLOW_REVERSE]);
  s = format(s, "  counters:\n");
  s = format(s, "    forward flow:\n");
  s = format(s, "      bytes: %llu\n", fctr.bytes);
  s = format(s, "      packets: %llu\n", fctr.packets);
  s = format(s, "    reverse flow:\n");
  s = format(s, "      bytes: %llu\n", bctr.bytes);
  s = format(s, "      packets: %llu\n", bctr.packets);
  return s;
}

u8 *
format_vcdp_tenant(u8 *s, va_list *args) {

  u32 indent = format_get_indent(s);
  __clib_unused vcdp_main_t *vcdp = va_arg(*args, vcdp_main_t *);
  u32 tenant_idx = va_arg(*args, u32);
  vcdp_tenant_t *tenant = va_arg(*args, vcdp_tenant_t *);
  s = format(s, "index: %d\n", tenant_idx);
  s = format(s, "%Ucontext: %d\n", format_white_space, indent,
             tenant->context_id);
  s = format(s, "%Uforward service chain:\n", format_white_space, indent);
  s = format(s, "%U%U\n", format_white_space, indent + 2, format_vcdp_bitmap,
             tenant->bitmaps[VCDP_FLOW_FORWARD]);
  s = format(s, "%Ureverse service chain:\n", format_white_space, indent);
  s = format(s, "%U%U\n", format_white_space, indent + 2, format_vcdp_bitmap,
             tenant->bitmaps[VCDP_FLOW_REVERSE]);
  return s;
}

u8 *
format_vcdp_tenant_extra(u8 *s, va_list *args) {
  u32 indent = format_get_indent(s);
  vcdp_main_t *vcdp = va_arg(*args, vcdp_main_t *);
  vlib_main_t *vm = vlib_get_main();
  u32 tenant_idx = va_arg(*args, u32);
  __clib_unused vcdp_tenant_t *tenant = va_arg(*args, vcdp_tenant_t *);
  counter_t ctr;
  vlib_counter_t ctr2;
  s = format(s, "%s\n", "Counters:");

#define _(x, y, z)                                                             \
  ctr = vlib_get_simple_counter(                                               \
    &vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_##x], tenant_idx);   \
  s = format(s, "%U%s: %llu\n", format_white_space, indent + 2, z, ctr);
  foreach_vcdp_tenant_session_counter
#undef _
#define _(x, y, z)                                                             \
  vlib_get_combined_counter(                                                   \
    &vcdp->tenant_data_ctr[VCDP_TENANT_DATA_COUNTER_##x], tenant_idx, &ctr2);  \
  s = format(s, "%U%s: %llu packets\n", format_white_space, indent + 2, z,     \
             ctr2.packets);                                                    \
  s = format(s, "%U  %llu bytes\n", format_white_space,                        \
             indent + strlen(z) + 2, ctr2.bytes);
    foreach_vcdp_tenant_data_counter
#undef _
      s =
        format(s, "%U%s\n", format_white_space, indent, "Configured Timeout:");

#define _(x, y, z)                                                             \
  s = format(s, "%U%s: %d seconds\n", format_white_space, indent + 2, z,       \
             tenant->timeouts[VCDP_TIMEOUT_##x]);
  foreach_vcdp_timeout
#undef _

    s = format(s, "%U%s\n", format_white_space, indent,
               "Configured Slowpath nodes:");
#define _(sym, default, name)                                                  \
  s = format(s, "%U%s: %U\n", format_white_space, indent + 2, name,            \
             format_vlib_node_name, vm,                                        \
             tenant->sp_node_indices[VCDP_SP_NODE_##sym]);
  foreach_vcdp_sp_node
#undef _
    return s;
}

u8 *
format_vcdp_sp_node(u8 *s, va_list *args) {
  u32 sp_index = va_arg(*args, u32);
#define _(sym, default, name)                                                  \
  if (sp_index == VCDP_SP_NODE_##sym)                                          \
    s = format(s, name);
  foreach_vcdp_sp_node
#undef _
    return s;
}

uword
unformat_vcdp_service(unformat_input_t *input, va_list *args) {
  vcdp_service_main_t *sm = &vcdp_service_main;
  u32 *result = va_arg(*args, u32 *);
  int i;
  for (i = 0; i < vec_len(sm->services); i++) {
    vcdp_service_registration_t *reg = vec_elt_at_index(sm->services, i)[0];
    if (unformat(input, reg->node_name)) {
      *result = reg->index_in_bitmap[0];
      return 1;
    }
  }
  return 0;
}

uword
unformat_vcdp_service_bitmap(unformat_input_t *input, va_list *args) {
  u32 *result = va_arg(*args, u32 *);
  int i = -1;
  u32 bitmap = 0;
  while (unformat_user(input, unformat_vcdp_service, &i))
    bitmap |= 1 << i;
  if (i > -1) {
    *result = bitmap;
    return 1;
  }
  return 0;
}

uword
unformat_vcdp_sp_node(unformat_input_t *input, va_list *args) {
  u32 *result = va_arg(*args, u32 *);
#define _(sym, default, str)                                                   \
  if (unformat(input, str)) {                                                  \
    *result = VCDP_SP_NODE_##sym;                                              \
    return 1;                                                                  \
  }
  foreach_vcdp_sp_node
#undef _
    return 0;
}
