// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp/vcdp.h>
#include <string.h> // Add this include for memcmp

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <vcdp/vcdp.api_enum.h>
#include <vcdp/vcdp.api_types.h>
#include <vcdp/vcdp_types_funcs.h>
#include <vnet/mfib/mfib_table.h>
#include "vcdp.h"
#include "timer_lru.h"

#define REPLY_MSG_ID_BASE vcdp->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_vcdp_tenant_add_del_t_handler(vl_api_vcdp_tenant_add_del_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = mp->tenant_id;
  u32 context_id = mp->context_id == ~0 ? tenant_id : mp->context_id;
  u8 is_add = mp->is_add;

  clib_error_t *err = vcdp_tenant_add_del(vcdp, tenant_id, context_id, mp->default_tenant_id, is_add);
  vl_api_vcdp_tenant_add_del_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO_END(VL_API_VCDP_TENANT_ADD_DEL_REPLY);
}


  // for (uword i = 0; i < mp->n_services; i++) {
  //   char *cstring = (char *) mp->services[i].data;
  //   unformat_input_t tmp;
  //   unformat_init_string(&tmp, cstring, strnlen(cstring, sizeof(mp->services[0].data)));
  //   rv = unformat_user(&tmp, unformat_vcdp_service, &idx);
  //   unformat_free(&tmp);
  //   if (!rv) {
  //     rv = -1;
  //     goto fail;
  //   }
  //   bitmap |= (1 << idx);
  // }

uword
unformat_service_names(unformat_input_t *input, va_list *va)
{
  u32 *bitmap = va_arg(*va, u32 *);
  u32 idx = 0;
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "%U", unformat_vcdp_service, &idx))
      *bitmap |= (1 << idx);
    else
      goto error;
  }
  return 1;
error:
  return 0;
}

static void
vl_api_vcdp_set_services_t_handler(vl_api_vcdp_set_services_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 tenant_id = mp->tenant_id;
  u32 bitmap = 0;
  int rv = 0;

  unformat_input_t input;
  unformat_init_string (&input, (char *)mp->services.buf, vl_api_string_len(&mp->services));
  if (!unformat_user(&input, unformat_service_names, &bitmap))
    goto fail;
  clib_error_t *err = vcdp_set_services(vcdp, tenant_id, bitmap, mp->dir);
  vl_api_vcdp_set_services_reply_t *rmp;
  rv = err ? -1 : 0;
fail:
  unformat_free(&input);
  REPLY_MACRO_END(VL_API_VCDP_SET_SERVICES_REPLY);
}

static void
vl_api_vcdp_set_timeout_t_handler(vl_api_vcdp_set_timeout_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 timeouts[VCDP_N_TIMEOUT] = {mp->embryonic, mp->established, mp->tcp_transitory, mp->tcp_established, mp->security};
  clib_error_t *err = vcdp_set_timeout(vcdp, timeouts);
  vl_api_vcdp_set_timeout_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO_END(VL_API_VCDP_SET_TIMEOUT_REPLY);
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
  int rv = 0;

  vcdp_session_key_t primary_key, secondary_key, *secondary_keyp, zero_key = {0};
  vcdp_session_key_decode(&mp->primary_key, &primary_key);
  vcdp_session_key_decode(&mp->secondary_key, &secondary_key);

  // Check if the optional secondary_key is set (all zeroes)
  if (clib_memcmp(&secondary_key, &zero_key, sizeof(vcdp_session_key_t)) == 0) {
    secondary_keyp = 0;
  } else {
    secondary_keyp = &secondary_key;
  }

  u16 tenant_idx = vcdp_tenant_idx_by_id(mp->tenant_id);
  if (tenant_idx == (u16)~0) {
    clib_warning("Tenant ID %u not found", mp->tenant_id);
    rv = -1;
    goto done;
  }
  u32 flow_index;
  vcdp_session_t *session = vcdp_create_session(tenant_idx, &primary_key, secondary_keyp,
                                                true, &flow_index);
  if (!session)
    rv = -1;

  done:
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

  session = vcdp_lookup_session(mp->context_id, &src, clib_host_to_net_u16(mp->sport), mp->proto, &dst,
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
    rmp->context_id = mp->context_id;
    rmp->session_idx = 0; //session_index;
    rmp->session_type = vcdp_session_type_encode(session->type);
    rmp->proto = ip_proto_encode(session->proto);
    rmp->state = vcdp_session_state_encode(session->state);
    rmp->remaining_time = vcdp_session_remaining_time(session, now);
    rmp->forward_bitmap = session->bitmaps[VCDP_FLOW_FORWARD];
    rmp->reverse_bitmap = session->bitmaps[VCDP_FLOW_REVERSE];
    vcdp_session_key_encode(&session->keys[VCDP_SESSION_KEY_PRIMARY], &rmp->primary_key);
    vcdp_session_key_encode(&session->keys[VCDP_SESSION_KEY_SECONDARY], &rmp->secondary_key);
    rmp->bytes[0] = session->bytes[0];
    rmp->bytes[1] = session->bytes[1];
    rmp->pkts[0] = session->pkts[0];
    rmp->pkts[1] = session->pkts[1];
  }}));
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

size_t vcdp_sessions_serialize(unsigned char **buffer, u32 *no_sessions);
static void
vl_api_vcdp_sessions_cbor_t_handler(vl_api_vcdp_sessions_cbor_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  int rv = 0;
  vl_api_vcdp_sessions_cbor_reply_t *rmp;

  unsigned char *buffer;
  u32 no_sessions;
  u32 len = vcdp_sessions_serialize(&buffer, &no_sessions);

  REPLY_MACRO3_END(VL_API_VCDP_SESSIONS_CBOR_REPLY, len, ({
    clib_memcpy(&rmp->cbor_data, buffer, len);
    rmp->len = len;
    free(buffer); // Use VPP allocator instead
  }));
}

static void
vl_api_ip_multicast_group_join_t_handler (vl_api_ip_multicast_group_join_t *mp)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vl_api_ip_multicast_group_join_reply_t *rmp;
  int rv = 0;
  const fib_route_path_t path_for_us = {
    .frp_proto = DPO_PROTO_IP6,
    .frp_addr = zero_addr,
    .frp_sw_if_index = 0xffffffff,
    .frp_fib_index = ~0,
    .frp_weight = 1,
    .frp_flags = FIB_ROUTE_PATH_LOCAL,
    .frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
  };
  mfib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = 128,
  };
  u32 fib_index = 0;
  ip_address_decode(&mp->grp_address, &pfx.fp_grp_addr);
  // mfib_table_lock(mfib_table->mft_index, FIB_PROTOCOL_IP6, src);

  mfib_table_entry_path_update(fib_index, &pfx, MFIB_SOURCE_SPECIAL, MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF, &path_for_us);
  mfib_table_entry_update(fib_index, &pfx, MFIB_SOURCE_SPECIAL, MFIB_RPF_ID_NONE,
                         MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF);
  mfib_table_lock(fib_index, FIB_PROTOCOL_IP6, MFIB_SOURCE_DHCP);
  // mfib_table_unlock (fib_index, FIB_PROTOCOL_IP6, MFIB_SOURCE_DHCP);

  REPLY_MACRO_END(VL_API_IP_MULTICAST_GROUP_JOIN_REPLY);
}
static void
vl_api_ip_multicast_group_leave_t_handler (vl_api_ip_multicast_group_leave_t *mp)
{

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
