// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp/vcdp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <vcdp/vcdp.api_enum.h>
#include <vcdp/vcdp.api_types.h>
#include <vcdp/vcdp_types_funcs.h>

#define REPLY_MSG_ID_BASE vcdp->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_vcdp_tenant_add_del_t_handler(vl_api_vcdp_tenant_add_del_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = clib_net_to_host_u32(mp->tenant_id);
  u32 context_id = mp->context_id == ~0 ? tenant_id : clib_net_to_host_u32(mp->context_id);
  u8 is_add = mp->is_add;
  clib_error_t *err = vcdp_tenant_add_del(vcdp, tenant_id, context_id, 0, is_add);
  vl_api_vcdp_tenant_add_del_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO(VL_API_VCDP_TENANT_ADD_DEL_REPLY);
}

static void
vl_api_vcdp_set_services_t_handler(vl_api_vcdp_set_services_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = clib_net_to_host_u32(mp->tenant_id);
  u32 bitmap = 0;
  u8 idx = 0;
  u8 dir = vcdp_api_direction(mp->dir);
  int rv;
  for (uword i = 0; i < mp->n_services; i++) {
    char *cstring = (char *) mp->services[i].data;
    unformat_input_t tmp;
    unformat_init_string(&tmp, cstring, strnlen(cstring, sizeof(mp->services[0].data)));
    rv = unformat_user(&tmp, unformat_vcdp_service, &idx);
    unformat_free(&tmp);
    if (!rv) {
      rv = -1;
      goto fail;
    }
    bitmap |= (1 << idx);
  }
  clib_error_t *err = vcdp_set_services(vcdp, tenant_id, bitmap, dir);
  vl_api_vcdp_set_services_reply_t *rmp;
  rv = err ? -1 : 0;
fail:
  REPLY_MACRO(VL_API_VCDP_SET_SERVICES_REPLY);
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
vcdp_send_session_details(vl_api_registration_t *rp, u32 context, u32 session_index, u32 thread_index,
                          vcdp_session_t *session)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vlib_main_t *vm = vlib_get_main();
  vl_api_vcdp_session_details_t *mp;
  vcdp_session_ip4_key_t skey;
  vcdp_tenant_t *tenant;
  u32 tenant_id;
  f64 remaining_time;
  remaining_time = session->timer.next_expiration - vlib_time_now(vm);
  size_t msg_size;
  u8 n_keys = vcdp_session_n_keys(session);
  tenant = vcdp_tenant_at_index(vcdp, session->tenant_idx);
  tenant_id = tenant->tenant_id;
  msg_size = sizeof(*mp) + sizeof(mp->keys[0]) * n_keys;

  mp = vl_msg_api_alloc_zero(msg_size);
  mp->_vl_msg_id = ntohs(VL_API_VCDP_SESSION_DETAILS + vcdp->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->session_id = clib_host_to_net_u64(session->session_id);
  mp->thread_index = clib_host_to_net_u32(thread_index);
  mp->tenant_id = clib_host_to_net_u32(tenant_id);
  mp->session_idx = clib_host_to_net_u32(session_index);
  mp->session_type = vcdp_session_type_encode(session->type);
  mp->protocol = ip_proto_encode(session->proto);
  mp->state = vcdp_session_state_encode(session->state);
  mp->remaining_time = clib_host_to_net_f64(remaining_time);
  mp->forward_bitmap = clib_host_to_net_u32(session->bitmaps[VCDP_FLOW_FORWARD]);
  mp->reverse_bitmap = clib_host_to_net_u32(session->bitmaps[VCDP_FLOW_REVERSE]);
  mp->n_keys = n_keys;
  for (int i = 0; i < n_keys; i++) {
    if ((i == 0 && session->key_flags & VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4) ||
        (i == 1 && session->key_flags & VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4)) {
      vcdp_session_ip4_key_encode(&skey, &mp->keys[i]);
    }
  }
  vl_api_send_msg(rp, (u8 *) mp);
}

static void
vl_api_vcdp_session_dump_t_handler(vl_api_vcdp_session_dump_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd;
  vcdp_session_t *session;
  uword thread_index;
  uword session_index;
  vl_api_registration_t *rp;
  rp = vl_api_client_index_to_registration(mp->client_index);
  if (rp == 0)
    return;

  vec_foreach_index (thread_index, vcdp->per_thread_data) {
    ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
    pool_foreach_index (session_index, ptd->sessions) {
      session = vcdp_session_at_index(ptd, session_index);
      vcdp_send_session_details(rp, mp->context, session_index, thread_index, session);
    }
  }
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

#include <vcdp/vcdp.api.c>
static clib_error_t *
vcdp_plugin_api_hookup(vlib_main_t *vm)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp->msg_id_base = setup_message_id_table();
  return 0;
}
VLIB_API_INIT_FUNCTION(vcdp_plugin_api_hookup);
