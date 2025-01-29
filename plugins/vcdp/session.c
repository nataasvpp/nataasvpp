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
#include <vcdp/lookup/lookup_inlines.h>
#include <vcdp/vcdp.api_enum.h>
#include "timer_lru.h"
#include "session.h"

/*
 * Create a static VCDP session. (No timer)
 */
void vcdp_set_service_chain(vcdp_tenant_t *tenant, u8 proto, u32 *bitmaps);

static int
vcdp_session_add_del_key(vcdp_session_key_t *k, int is_add, u64 value, u64 *h)
{
  vcdp_main_t *vcdp = &vcdp_main;
  clib_bihash_kv_40_8_t kv;

  clib_memcpy(&kv.key, k, 40);
  kv.value = value;
  *h = clib_bihash_hash_40_8(&kv);
  return clib_bihash_add_del_with_hash_40_8(&vcdp->session_hash, &kv, *h, is_add);
}

vcdp_session_t *
vcdp_create_session(u16 tenant_idx, vcdp_session_key_t *primary, vcdp_session_key_t *secondary, bool is_static,
                    u32 *flow_index)
{

  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vlib_get_thread_index();
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
  if (!tenant) {
    vcdp_log_err("Unknown tenant %d", tenant_idx);
    return 0;
  }

  /* See if we can expire some sessions. */
  f64 now = vlib_time_now(vlib_get_main());
  vcdp_timer_lru_free_one(vcdp, thread_index, now);

  if (pool_free_elts(ptd->sessions) == 0) {
    vcdp_log_debug("No free sessions %U", format_vcdp_session_key, primary);
    return 0;
  }

  u64 h;
  vcdp_session_t *session;
  pool_get(ptd->sessions, session);
  u32 session_idx = session - ptd->sessions;
  u32 pseudo_flow_idx = (session_idx << 1);
  u64 value = vcdp_session_mk_table_value(thread_index, pseudo_flow_idx);
  *flow_index = pseudo_flow_idx;

  if (vcdp_session_add_del_key(primary, 2, value, &h)) {
    /* already exists */
    vcdp_log_err("session already exists %U", format_vcdp_session_key, primary);
    pool_put(ptd->sessions, session);
    return 0;
  }
  clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_PRIMARY], primary, sizeof(session->keys[0]));

  if (secondary) {
    if (vcdp_session_add_del_key(secondary, 2, value | 0x1, &h)) {
      /* already exists */
      vcdp_log_err("session already exists %U", format_vcdp_session_key, secondary);
      pool_put(ptd->sessions, session);
      return 0;
    }
    clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_SECONDARY], secondary, sizeof(session->keys[1]));
  }

  // session->type = VCDP_SESSION_TYPE_IP4;
  session->state = VCDP_SESSION_STATE_FSOL;

  session->session_version += 1;
  u64 session_id = (ptd->session_id_ctr & (vcdp->session_id_ctr_mask)) | ptd->session_id_template;
  ptd->session_id_ctr += 2; /* two at a time, because last bit is reserved for direction */
  session->session_id = session_id;
  session->tenant_idx = tenant_idx;
  session->rx_id = ~0; // TODO: Set rx_ID into sessions!!!!
  session->created = unix_time_now();
  session->pkts[VCDP_FLOW_FORWARD] = 0;
  session->pkts[VCDP_FLOW_REVERSE] = 0;
  session->bytes[VCDP_FLOW_FORWARD] = 0;
  session->bytes[VCDP_FLOW_REVERSE] = 0;

  clib_bihash_kv_8_8_t kv2;
  kv2.key = session_id;
  kv2.value = value;
  if (clib_bihash_add_del_8_8(&vcdp->session_index_by_id, &kv2, 1)) {
    vcdp_log_err("cannot add: %lx session already exists", session_id);
  }

  /* Assign service chain */
  vcdp_set_service_chain(tenant, primary->proto, session->bitmaps);

  if (is_static) {
    session->state = VCDP_SESSION_STATE_STATIC;
  } else {
    vcdp_session_timer_start(vcdp, session, thread_index, vlib_time_now(vlib_get_main()), VCDP_TIMEOUT_EMBRYONIC);
  }
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_CREATED], thread_index, tenant_idx, 1);
  vcdp_log_debug("Creating session: %d %U %llx", session_idx, format_vcdp_session_key, primary, session_id);

  return session;
}

vcdp_session_t *
vcdp_lookup_session(u32 context_id, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst, u16 dport)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u64 value;
  if (!src || !dst)
    return 0;
  if (src->version != dst->version)
    return 0;

  if (src->version == AF_IP6) {
    ;
  };

  vcdp_session_key_t k = {
    .context_id = context_id,
    .src = src->ip,
    .dst = dst->ip,
    .sport = sport,
    .dport = dport,
    .proto = protocol,
  };
  clib_bihash_kv_40_8_t kv;
  clib_memcpy(&kv.key, &k, sizeof(k));
  if (clib_bihash_search_inline_40_8(&vcdp->session_hash, &kv))
    return 0;
  value = kv.value;
  u32 thread_index, session_index;
  return vcdp_session_from_lookup_value(vcdp, value, &thread_index, &session_index);
}

void
vcdp_session_remove_core(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_session_t *session, u32 thread_index,
                         u32 session_index, bool stop_timer)
{
  u64 h;
  clib_bihash_kv_8_8_t kv2 = {0};
  kv2.key = session->session_id;

  /* Stop timer if running */
  vcdp_log_debug("Removing session %u %llx", session_index, session->session_id);
  if (stop_timer) {
    vcdp_log_debug("Stopping timer for session %u", session_index);
    vcdp_session_timer_stop(vcdp, session, thread_index);
  }
  if (vcdp_session_add_del_key(&session->keys[VCDP_SESSION_KEY_PRIMARY], 0, 0, &h)) {
    vcdp_log_err("Failed to remove session key from table");
  }
  if (vcdp_session_add_del_key(&session->keys[VCDP_SESSION_KEY_SECONDARY], 0, 0, &h)) {
    vcdp_log_err("Failed to remove session from session hash - secondary");
  }

  if (clib_bihash_add_del_8_8(&vcdp->session_index_by_id, &kv2, 0)) {
    vcdp_log_err("Removing %lx failed", session->session_id);
  }
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_REMOVED], thread_index,
                                session->tenant_idx, 1);

  vlib_increment_combined_counter(&vcdp->tenant_combined_ctr[VCDP_TENANT_COUNTER_TX], thread_index, session->tenant_idx,
                                  session->pkts[VCDP_FLOW_FORWARD], session->bytes[VCDP_FLOW_FORWARD]);
  vlib_increment_combined_counter(&vcdp->tenant_combined_ctr[VCDP_TENANT_COUNTER_RX], thread_index, session->tenant_idx,
                                  session->pkts[VCDP_FLOW_REVERSE], session->bytes[VCDP_FLOW_REVERSE]);
  pool_put_index(ptd->sessions, session_index);
}

void
vcdp_session_remove(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_session_t *session, u32 thread_index,
                    u32 session_index)
{
  vcdp_session_remove_core(vcdp, ptd, session, thread_index, session_index, true);
}
void
vcdp_session_remove_no_timer(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_session_t *session, u32 thread_index,
                             u32 session_index)
{
  vcdp_session_remove_core(vcdp, ptd, session, thread_index, session_index, false);
}

/*
 * An existing session is being reused for a new flow with the same 6-tuple.
 * Reset counters.
 */
void
vcdp_session_reopen(vcdp_main_t *vcdp, u32 thread_index, vcdp_session_t *session)
{
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_REMOVED], thread_index,
                                session->tenant_idx, 1);
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_CREATED], thread_index,
                                session->tenant_idx, 1);
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_REUSED], thread_index, session->tenant_idx,
                                1);

  session->bytes[VCDP_FLOW_FORWARD] = 0;
  session->bytes[VCDP_FLOW_REVERSE] = 0;
  session->pkts[VCDP_FLOW_FORWARD] = 0;
  session->pkts[VCDP_FLOW_REVERSE] = 0;
}

bool
vcdp_session_is_expired(vcdp_session_t *session, f64 time_now)
{
  return (session->state != VCDP_SESSION_STATE_STATIC && (vcdp_session_remaining_time(session, time_now) == 0));
}

bool
vcdp_session_is_expired_session_idx(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, u32 session_index)
{
  vcdp_session_t *session = vcdp_session_at_index(ptd, session_index);
  return vcdp_session_is_expired(session, vlib_time_now(vlib_get_main()));
}

int
vcdp_session_try_add_secondary_key(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, u32 thread_index,
                                   u32 pseudo_flow_index, vcdp_session_key_t *key)
{
  u64 value;
  vcdp_session_t *session;
  u32 session_index;
  u64 h;

  value = vcdp_session_mk_table_value(thread_index, pseudo_flow_index);
  session_index = vcdp_session_from_flow_index(pseudo_flow_index);
  session = vcdp_session_at_index(ptd, session_index);
  clib_memcpy(&session->keys[VCDP_SESSION_KEY_SECONDARY], key, sizeof(*key));

  return vcdp_session_add_del_key(key, 2, value, &h);
}

/*
 * vcdp_session_clear. Delete all sessions.
 * This requires to be called within a barrier.
 */
void
vcdp_session_clear(void)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd;
  u32 thread_index;
  u32 *to_delete = 0;
  u32 *session_index;
  vcdp_session_t *session;

  vec_foreach_index (thread_index, vcdp->per_thread_data) {
    ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
    pool_foreach (session, ptd->sessions) {
      if (session->state != VCDP_SESSION_STATE_STATIC) {
        vec_add1(to_delete, session - ptd->sessions);
      }
    }
    vec_foreach (session_index, to_delete) {
      session = vcdp_session_at_index(ptd, *session_index);
      vcdp_session_remove(vcdp, ptd, session, thread_index, *session_index);
    }
    vec_reset_length(to_delete);
  }
}
