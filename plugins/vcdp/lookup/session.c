// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_16_8.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>
#include "lookup_inlines.h"
#include <vcdp/vcdp.api_enum.h>

/*
 * Create a static VCDP session. (No timer)
 */
void vcdp_set_service_chain(vcdp_tenant_t *tenant, u8 proto, u32 *bitmaps);

vcdp_session_t *
vcdp_create_session_v4(u16 tenant_idx, vcdp_session_ip4_key_t *primary, vcdp_session_ip4_key_t *secondary,
                       bool is_static, u32 *flow_index)
{
  clib_bihash_kv_16_8_t kv = {};
  clib_bihash_kv_8_8_t kv2;

  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vlib_get_thread_index(); // TODO: Check if this should be vm->thread_index instead
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
  vcdp_session_t *session;
  pool_get(ptd->sessions, session);
  u32 session_idx = session - ptd->sessions;
  u32 pseudo_flow_idx = (session_idx << 1);
  u64 value = vcdp_session_mk_table_value(thread_index, pseudo_flow_idx);
  *flow_index = pseudo_flow_idx;
  if (!tenant) return 0;

  kv.key[0] = primary->as_u64[0];
  kv.key[1] = primary->as_u64[1];
  kv.value = value;
  if (clib_bihash_add_del_16_8(&vcdp->table4, &kv, 2)) {
    /* already exists */
    VCDP_DBG(0, "session already exists");
    pool_put(ptd->sessions, session);
    return 0;
  }

  session->type = VCDP_SESSION_TYPE_IP4;
  session->key_flags = VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4;

  session->session_version += 1;
  u64 session_id = (ptd->session_id_ctr & (vcdp->session_id_ctr_mask)) | ptd->session_id_template;
  ptd->session_id_ctr += 2; /* two at a time, because last bit is reserved for direction */
  session->session_id = session_id;
  session->tenant_idx = tenant_idx;
  session->rx_id = ~0; // TODO: Set rx_ID into sessions!!!!
  session->proto = primary->proto;

  kv2.key = session_id;
  kv2.value = value;
  clib_bihash_add_del_8_8(&vcdp->session_index_by_id, &kv2, 1);

  /* Assign service chain */
  // TODO. Set service chain based on traffic type!!!!
  vcdp_set_service_chain(tenant, session->proto, session->bitmaps);

  clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_PRIMARY], primary, sizeof(session->keys[0]));
  if (secondary) {
    clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_SECONDARY], secondary, sizeof(session->keys[1]));
    session->key_flags |= VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4;
    kv.key[0] = secondary->as_u64[0];
    kv.key[1] = secondary->as_u64[1];
    kv.value = value | 0x1;
    if (clib_bihash_add_del_16_8(&vcdp->table4, &kv, 2)) {
      // XXXX: Also delete previous key from hash
      /* already exists */
      VCDP_DBG(0, "session already exists");
      pool_put(ptd->sessions, session);
      return 0;
    }
  }

  if (is_static) {
    session->state = VCDP_SESSION_STATE_STATIC;
  } else {
    session->timer.handle = VCDP_TIMER_HANDLE_INVALID;
    vcdp_session_timer_start(&ptd->wheel, &session->timer, session_idx, vlib_time_now(vlib_get_main()),
                             tenant->timeouts[VCDP_TIMEOUT_EMBRYONIC]);
  }
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_CREATED], thread_index, tenant_idx, 1);
  VCDP_DBG(3, "Creating session: %d %U %llx", session_idx, format_vcdp_session_key, primary, session_id);

  return session;
}

vcdp_session_t *
vcdp_lookup_session_v4(u32 tenant_id, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst, u16 dport)
{
  vcdp_main_t *vcdp = &vcdp_main;

  u16 tenant_idx;
  vcdp_tenant_t *tenant = vcdp_tenant_get_by_id(tenant_id, &tenant_idx);
  if (!tenant) return 0;
  u32 context_id = tenant->context_id;

  vcdp_session_ip4_key_t k = {
    .context_id = context_id,
    .src = src->ip.ip4.as_u32,
    .dst = dst->ip.ip4.as_u32,
    .sport = sport,
    .dport = dport,
    .proto = protocol,
  };
  clib_bihash_kv_16_8_t kv = {.key[0] = k.as_u64[0],
                              .key[1] = k.as_u64[1],
                              .value = 0};


  if (clib_bihash_search_inline_16_8(&vcdp->table4, &kv) == 0) {
      // Figure out if this is local or remote thread
      u32 thread_index = vcdp_thread_index_from_lookup(kv.value);
      /* known flow which belongs to this thread */
      u32 flow_index = kv.value & (~(u32) 0);
      u32 session_index = vcdp_session_from_flow_index(flow_index);
      vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
      return pool_elt_at_index(ptd->sessions, session_index);
  }

  return 0;
}
