// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vcdp/service.h>
#include <vcdp/vcdp.h>
#include <vppinfra/format_table.h>
#include <vcdp/timer.h>
#include <vcdp/timer_lru.h>

u8 *
format_vcdp_session_state(u8 *s, va_list *args)
{
  u8 session_state = va_arg(*args, u32);
#define _(n, str)                                                                                                      \
  if (session_state == VCDP_SESSION_STATE_##n)                                                                         \
    s = format(s, "%s", (str));
  foreach_vcdp_session_state
#undef _
    return s;
}

u8 *
format_vcdp_session_type(u8 *s, va_list *args)
{
  u32 session_type = va_arg(*args, u32);
  switch (session_type) {
    case VCDP_SESSION_TYPE_IP4:
      return format(s, "ipv4");
    case VCDP_SESSION_TYPE_IP6:
      return format(s, "ipv6");
    case VCDP_SESSION_TYPE_NAT64:
      return format(s, "nat64");
    default:
      return format(s, "unknown");
  }
  return s;
}

u8 *
format_vcdp_session_ip4_key(u8 *s, va_list *args)
{
  vcdp_session_ip4_key_t *k = va_arg(*args, vcdp_session_ip4_key_t *);
  u32 context_id = k->context_id;
  s = format(s, "%d: %U: %U:%d %U:%d", context_id, format_ip_protocol, k->proto, format_ip4_address, &k->src,
             clib_net_to_host_u16(k->sport), format_ip4_address, &k->dst, clib_net_to_host_u16(k->dport));
  return s;
}

u8 *
format_vcdp_session_ip6_key(u8 *s, va_list *args)
{
  vcdp_session_ip6_key_t *k = va_arg(*args, vcdp_session_ip6_key_t *);
  u32 context_id = k->context_id;
  s = format(s, "%d: %U: %U:%d %U:%d", context_id, format_ip_protocol, k->proto, format_ip6_address, &k->src,
             clib_net_to_host_u16(k->sport), format_ip6_address, &k->dst, clib_net_to_host_u16(k->dport));
  return s;
}

u8 *
format_vcdp_session_key(u8 *s, va_list *args)
{
  vcdp_session_key_t *key = va_arg(*args, vcdp_session_key_t *);
  if (key->is_ip6)
    s = format(s, "%U", format_vcdp_session_ip6_key, &key->ip6);
  else
   s = format(s, "%U", format_vcdp_session_ip4_key, &key->ip4);
  return s;
}

u8 *
format_vcdp_bitmap(u8 *s, va_list *args)
{
  u32 bmp = va_arg(*args, u32);
  vcdp_service_main_t *sm = &vcdp_service_main;
  int i;
  for (i = 0; i < vec_len(sm->services); i++)
    if (bmp & sm->services[i]->service_mask[0])
      s = format(s, "%s,", sm->services[i]->node_name);
  return s;
}

u8 *
format_vcdp_session_detail(u8 *s, va_list *args)
{
  vcdp_per_thread_data_t *ptd = va_arg(*args, vcdp_per_thread_data_t *);
  u32 session_index = va_arg(*args, u32);
  f64 now = va_arg(*args, f64);
  vcdp_session_t *session = vcdp_session_at_index(ptd, session_index);

  f64 remaining_time = vcdp_session_remaining_time(session, now);
  u64 session_net = clib_host_to_net_u64(session->session_id);
  uword thread_index = ptd - vcdp_main.per_thread_data;
  vcdp_session_key_t *skey;

  /* TODO: deal with secondary keys */
  s = format(s, "  session id: 0x%U\n", format_hex_bytes, &session_net, sizeof(u64));
  s = format(s, "  thread index: %d\n", thread_index);
  s = format(s, "  session index: %d\n", session_index);
  skey = &session->keys[VCDP_SESSION_KEY_PRIMARY];
  s = format(s, "  primary key: %U\n", format_vcdp_session_key, skey);
  skey = &session->keys[VCDP_SESSION_KEY_SECONDARY];
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4)
    s = format(s, "  secondary key: %U\n", format_vcdp_session_key, skey);
  s = format(s, "  state: %U\n", format_vcdp_session_state, session->state);
  if (session->state != VCDP_SESSION_STATE_STATIC)
    s = format(s, "  expires after: %fs\n", remaining_time);
  s = format(s, "  forward service chain: %U\n", format_vcdp_bitmap, session->bitmaps[VCDP_FLOW_FORWARD]);
  s = format(s, "  reverse service chain: %U\n", format_vcdp_bitmap, session->bitmaps[VCDP_FLOW_REVERSE]);
  s = format(s, "  counters:\n");
  s = format(s, "    forward flow:\n");
  s = format(s, "      bytes: %llu\n", session->bytes[VCDP_FLOW_FORWARD]);
  s = format(s, "      packets: %llu\n", session->pkts[VCDP_FLOW_FORWARD]);
  s = format(s, "    reverse flow:\n");
  s = format(s, "      bytes: %llu\n", session->bytes[VCDP_FLOW_REVERSE]);
  s = format(s, "      packets: %llu\n", session->pkts[VCDP_FLOW_REVERSE]);

  vcdp_service_main_t *sm = &vcdp_service_main;
  int i;
  vec_foreach_index(i, sm->services) {
    if ((session->bitmaps[VCDP_FLOW_FORWARD] /*| session->bitmaps[VCDP_FLOW_REVERSE]*/) &
        sm->services[i]->service_mask[0]) {
      if (sm->services[i]->format_service)
        s = sm->services[i]->format_service(s, thread_index, session_index);
    }
  }

  return s;
}

u8 *
format_vcdp_tenant(u8 *s, va_list *args)
{

  u32 indent = format_get_indent(s);
  __clib_unused vcdp_main_t *vcdp = va_arg(*args, vcdp_main_t *);
  u32 tenant_idx = va_arg(*args, u32);
  vcdp_tenant_t *tenant = va_arg(*args, vcdp_tenant_t *);
  s = format(s, "index: %d\n", tenant_idx);
  s = format(s, "%Ucontext: %d\n", format_white_space, indent, tenant->context_id);
  s = format(s, "%Uforward service chain:\n", format_white_space, indent);
  s = format(s, "%U%U\n", format_white_space, indent + 2, format_vcdp_bitmap, tenant->bitmaps[VCDP_SERVICE_CHAIN_FORWARD]);
  if (tenant->bitmaps[VCDP_SERVICE_CHAIN_FORWARD] != tenant->tcp_bitmaps[VCDP_SERVICE_CHAIN_FORWARD]) {
    s = format(s, "%Uforward tcp service chain:\n", format_white_space, indent);
    s = format(s, "%U%U\n", format_white_space, indent + 2, format_vcdp_bitmap, tenant->tcp_bitmaps[VCDP_SERVICE_CHAIN_FORWARD]);
  }
  s = format(s, "%Ureverse service chain:\n", format_white_space, indent);
  s = format(s, "%U%U\n", format_white_space, indent + 2, format_vcdp_bitmap, tenant->bitmaps[VCDP_SERVICE_CHAIN_REVERSE]);
  if (tenant->bitmaps[VCDP_SERVICE_CHAIN_REVERSE] != tenant->tcp_bitmaps[VCDP_SERVICE_CHAIN_REVERSE]) {
    s = format(s, "%Ureverse tcp service chain:\n", format_white_space, indent);
    s = format(s, "%U%U\n", format_white_space, indent + 2, format_vcdp_bitmap, tenant->tcp_bitmaps[VCDP_SERVICE_CHAIN_REVERSE]);
  }
  s = format(s, "%Umiss service chain:\n", format_white_space, indent);
  s = format(s, "%U%U\n", format_white_space, indent + 2, format_vcdp_bitmap, tenant->bitmaps[VCDP_SERVICE_CHAIN_MISS]);
  return s;
}

u8 *
format_vcdp_tenant_extra(u8 *s, va_list *args)
{
  u32 indent = format_get_indent(s);
  vcdp_main_t *vcdp = va_arg(*args, vcdp_main_t *);
  u32 tenant_idx = va_arg(*args, u32);
  __clib_unused vcdp_tenant_t *tenant = va_arg(*args, vcdp_tenant_t *);

  counter_t ctr;
  vlib_counter_t ctr2;
  s = format(s, "%s\n", "Counters:");

  ctr = vlib_get_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_CREATED], tenant_idx);
  s = format(s, "%Ucreated: %llu\n", format_white_space, indent + 2, ctr);
  ctr = vlib_get_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_REMOVED], tenant_idx);
  s = format(s, "%Uexpired: %llu\n", format_white_space, indent + 2, ctr);

  vlib_get_combined_counter(&vcdp->tenant_combined_ctr[VCDP_TENANT_COUNTER_RX], tenant_idx, &ctr2);
  s = format(s, "%Urx: %llu packets\n", format_white_space, indent + 2, ctr2.packets);
  s = format(s, "%U  %llu bytes\n", format_white_space, indent + strlen("rx") + 2, ctr2.bytes);
  vlib_get_combined_counter(&vcdp->tenant_combined_ctr[VCDP_TENANT_COUNTER_TX], tenant_idx, &ctr2);
  s = format(s, "%Utx: %llu packets\n", format_white_space, indent + 2, ctr2.packets);
  s = format(s, "%U  %llu bytes\n", format_white_space, indent + strlen("tx") + 2, ctr2.bytes);

  return s;
}

uword
unformat_vcdp_service(unformat_input_t *input, va_list *args)
{
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
unformat_vcdp_service_bitmap(unformat_input_t *input, va_list *args)
{
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
