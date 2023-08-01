// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp/vcdp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <vcdp/vcdp.api_enum.h>
#include <vcdp/vcdp.api_types.h>
#include <vcdp/vcdp_types_funcs.h>
#include "vcdp.h"

#define REPLY_MSG_ID_BASE vcdp->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_vcdp_tenant_add_del_t_handler(vl_api_vcdp_tenant_add_del_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = mp->tenant_id;
  u32 context_id = mp->context_id == ~0 ? tenant_id : mp->context_id;
  u8 is_add = mp->is_add;

  clib_error_t *err = vcdp_tenant_add_del(vcdp, tenant_id, context_id, (vcdp_tenant_flags_t)mp->flags, is_add);
  vl_api_vcdp_tenant_add_del_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO_END(VL_API_VCDP_TENANT_ADD_DEL_REPLY);
}

static int
vcdp_api_services_to_bitmap(vl_api_vcdp_service_name_t *services, int n_services, u32 *bitmap)
{
  u32 idx = 0;
  for (int i = 0; i < n_services; i++) {
    char *cstring = (char *) services[i].data;
    unformat_input_t tmp;
    unformat_init_string(&tmp, cstring, strnlen(cstring, sizeof(services[0].data)));
    int rv = unformat_user(&tmp, unformat_vcdp_service, &idx);
    unformat_free(&tmp);
    if (!rv)
      return -1;
    *bitmap |= (1 << idx);
  }
  return 0;
}

static void
vl_api_vcdp_set_services_t_handler(vl_api_vcdp_set_services_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = mp->tenant_id;
  u32 bitmap = 0;
  vcdp_session_direction_t dir = vcdp_api_direction(mp->dir);
  int rv = vcdp_api_services_to_bitmap(mp->services, mp->n_services, &bitmap);
  if (rv)
    goto fail;

  clib_error_t *err = vcdp_set_services(vcdp, tenant_id, bitmap, dir);
  vl_api_vcdp_set_services_reply_t *rmp;
  rv = err ? -1 : 0;
fail:
  REPLY_MACRO_END(VL_API_VCDP_SET_SERVICES_REPLY);
}

static void
vl_api_vcdp_set_services_defaults_t_handler(vl_api_vcdp_set_services_defaults_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 bitmap = 0;
  vl_api_vcdp_set_services_defaults_reply_t *rmp;
  vcdp_session_direction_t dir = vcdp_api_direction(mp->dir);
  int rv = vcdp_api_services_to_bitmap(mp->services, mp->n_services, &bitmap);
  if (rv)
    goto fail;

  rv = vcdp_set_services_defaults(bitmap, dir);

fail:
  REPLY_MACRO_END(VL_API_VCDP_SET_SERVICES_DEFAULTS_REPLY);
}

static void
vl_api_vcdp_set_timeout_t_handler(vl_api_vcdp_set_timeout_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = clib_net_to_host_u32(mp->tenant_id);
  u32 timeout_id = clib_net_to_host_u32(mp->timeout_id);
  u32 timeout_value = clib_net_to_host_u32(mp->timeout_value);
  clib_error_t *err = vcdp_set_timeout(vcdp, tenant_id, timeout_id, timeout_value);
  vl_api_vcdp_set_timeout_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO(VL_API_VCDP_SET_TIMEOUT_REPLY);
}

static void
vl_api_vcdp_set_timeout_defaults_t_handler(vl_api_vcdp_set_timeout_defaults_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vl_api_vcdp_set_timeout_defaults_reply_t *rmp;
  u32 timeouts[VCDP_N_TIMEOUT] = {mp->timeout_embryonic, mp->timeout_established, mp->timeout_tcp_transitory,
                                  mp->timeout_tcp_established, mp->timeout_security};

  int rv = vcdp_set_timeout_defaults(timeouts);

  REPLY_MACRO_END(VL_API_VCDP_SET_TIMEOUT_DEFAULTS_REPLY);
}

static vl_api_vcdp_session_state_t
vcdp_session_state_encode(vcdp_session_state_t x)
{
  switch (x) {
  case VCDP_SESSION_STATE_FSOL:
    return VCDP_API_SESSION_STATE_FSOL;
  case VCDP_SESSION_STATE_ESTABLISHED:
    return VCDP_API_SESSION_STATE_ESTABLISHED;
  case VCDP_SESSION_STATE_TIME_WAIT:
    return VCDP_API_SESSION_STATE_TIME_WAIT;
  default:
    return -1;
  }
};

static void
vl_api_vcdp_session_add_t_handler(vl_api_vcdp_session_add_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vl_api_vcdp_session_add_reply_t *rmp;

  ip_address_t src, dst;
  ip_address_decode2(&mp->src, &src);
  ip_address_decode2(&mp->dst, &dst);

  int rv = vcdp_create_session_v4_2(mp->tenant_id, &src, clib_host_to_net_u16(mp->sport), mp->protocol, &dst, clib_host_to_net_u16(mp->dport));

  REPLY_MACRO_END(VL_API_VCDP_SESSION_ADD_REPLY);
}

static void
vl_api_vcdp_session_lookup_t_handler(vl_api_vcdp_session_lookup_t *mp)
{
  vl_api_vcdp_session_lookup_reply_t *rmp;
  int rv = 0;
  vcdp_main_t *vcdp = &vcdp_main;
  // vcdp_per_thread_data_t *ptd;
  vcdp_session_t *session;
  // uword thread_index;
  // uword session_index;

  // vcdp_tenant_t *tenant;
  // u32 tenant_id;
  f64 now = vlib_time_now(vlib_get_main());

  // Lookup session in the flow table
  ip_address_t src, dst;
  ip_address_decode2(&mp->src, &src);
  ip_address_decode2(&mp->dst, &dst);

  session = vcdp_lookup_session_v4(mp->tenant_id, &src, clib_host_to_net_u16(mp->sport),
                                   mp->protocol, &dst,
                                   clib_host_to_net_u16(mp->dport));
  if (!session)
    rv = -1;

  // Return session details from the per-thread session table
  // This is accessed outside of the lock, so it may be stale?
  REPLY_MACRO2_END(VL_API_VCDP_SESSION_LOOKUP_REPLY,
  ({
  if (session) {
    rmp->session_id = session->session_id;
    rmp->thread_index = 0; //thread_index;
    rmp->tenant_id = mp->tenant_id;
    rmp->session_idx = 0; //session_index;
    rmp->session_type = vcdp_session_type_encode(session->type);
    rmp->protocol = ip_proto_encode(session->proto);
    rmp->state = vcdp_session_state_encode(session->state);
    rmp->remaining_time = session->timer.next_expiration - now;
    rmp->forward_bitmap = session->bitmaps[VCDP_FLOW_FORWARD];
    rmp->reverse_bitmap = session->bitmaps[VCDP_FLOW_REVERSE];
    vcdp_session_ip4_key_encode(&session->keys[VCDP_SESSION_KEY_PRIMARY], &rmp->primary_key);
    vcdp_session_ip4_key_encode(&session->keys[VCDP_SESSION_KEY_SECONDARY], &rmp->secondary_key);
  }}));
}

static void
vcdp_send_tenant_details(vl_api_registration_t *rp, u32 context, u16 tenant_index, vcdp_tenant_t *tenant)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vl_api_vcdp_tenant_details_t *mp;

  size_t msg_size;
  msg_size = sizeof(*mp) + VCDP_N_TIMEOUT * sizeof(mp->timeout[0]);

  mp = vl_msg_api_alloc_zero(msg_size);
  mp->_vl_msg_id = ntohs(VL_API_VCDP_TENANT_DETAILS + vcdp->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->context_id = clib_host_to_net_u32(tenant->context_id);
  mp->index = clib_host_to_net_u32(tenant_index);
  mp->forward_bitmap = clib_host_to_net_u32(tenant->bitmaps[VCDP_FLOW_FORWARD]);
  mp->reverse_bitmap = clib_host_to_net_u32(tenant->bitmaps[VCDP_FLOW_REVERSE]);
  mp->n_timeout = clib_host_to_net_u32(VCDP_N_TIMEOUT);
#define _(name, y, z) mp->timeout[VCDP_TIMEOUT_##name] = clib_host_to_net_u32(tenant->timeouts[VCDP_TIMEOUT_##name]);
  foreach_vcdp_timeout
#undef _
    vl_api_send_msg(rp, (u8 *) mp);
}

static void
vl_api_vcdp_tenant_dump_t_handler(vl_api_vcdp_tenant_dump_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_tenant_t *tenant;
  u16 tenant_index;
  vl_api_registration_t *rp;
  rp = vl_api_client_index_to_registration(mp->client_index);
  if (rp == 0)
    return;

  pool_foreach_index (tenant_index, vcdp->tenants) {
    tenant = vcdp_tenant_at_index(vcdp, tenant_index);
    vcdp_send_tenant_details(rp, mp->context, tenant_index, tenant);
  }
}

static void
vl_api_vcdp_session_clear_t_handler(vl_api_vcdp_session_clear_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  int rv = 0;
  vl_api_vcdp_session_clear_reply_t *rmp;

  vcdp_session_clear();

  REPLY_MACRO_END(VL_API_VCDP_SESSION_CLEAR_REPLY);
}

#include <vcdp/vcdp.api.c>
static clib_error_t *
vcdp_plugin_api_hookup(vlib_main_t *vm)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp->msg_id_base = setup_message_id_table();
  return 0;
}
VLIB_API_INIT_FUNCTION(vcdp_plugin_api_hookup);
