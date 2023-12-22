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

/*
 * Create a static VCDP session. (No timer)
 */
void vcdp_set_service_chain(vcdp_tenant_t *tenant, u8 proto, u32 *bitmaps);

static int
vcdp_session_add_del_key4(vcdp_session_ip4_key_t *k, int is_add, u64 value, u64 *h)
{
  vcdp_main_t *vcdp = &vcdp_main;
  clib_bihash_kv_16_8_t kv = {
    .key[0] = k->as_u64[0],
    .key[1] = k->as_u64[1],
    .value = value,
  };
  *h = clib_bihash_hash_16_8(&kv);
  return clib_bihash_add_del_with_hash_16_8(&vcdp->table4, &kv, *h, is_add);
}

static int
vcdp_session_add_del_key6(vcdp_session_ip6_key_t *k, int is_add, u64 value, u64 *h)
{
  vcdp_main_t *vcdp = &vcdp_main;
  clib_bihash_kv_40_8_t kv;

  clib_memcpy(&kv.key, k, 40);
  kv.value = value;
  *h = clib_bihash_hash_40_8(&kv);
  return clib_bihash_add_del_with_hash_40_8(&vcdp->table6, &kv, *h, is_add);
}

static int
vcdp_session_add_del_key(vcdp_session_key_t *k, int is_add, u64 value, u64 *h)
{
  return k->is_ip6 ? vcdp_session_add_del_key6(&k->ip6, is_add, value, h) :
                     vcdp_session_add_del_key4(&k->ip4, is_add, value, h);
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
    VCDP_DBG(0, "Unknown tenant %d", tenant_idx);
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
    VCDP_DBG(0, "session already exists");
    pool_put(ptd->sessions, session);
    return 0;
  }
  session->key_flags = primary->is_ip6 ? VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6 : VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4;
  session->proto = primary->is_ip6 ? primary->ip6.proto : primary->ip4.proto;
  clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_PRIMARY], primary, sizeof(session->keys[0]));

  if (secondary) {
    if (vcdp_session_add_del_key(secondary, 2, value, &h)) {
      /* already exists */
      VCDP_DBG(0, "session already exists");
      pool_put(ptd->sessions, session);
      return 0;
    }
    session->key_flags |=
      secondary->is_ip6 ? VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6 : VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4;
    clib_memcpy_fast(&session->keys[VCDP_SESSION_KEY_SECONDARY], secondary, sizeof(session->keys[1]));
  }

  // session->type = VCDP_SESSION_TYPE_IP4;

  session->session_version += 1;
  u64 session_id = (ptd->session_id_ctr & (vcdp->session_id_ctr_mask)) | ptd->session_id_template;
  ptd->session_id_ctr += 2; /* two at a time, because last bit is reserved for direction */
  session->session_id = session_id;
  session->tenant_idx = tenant_idx;
  session->rx_id = ~0; // TODO: Set rx_ID into sessions!!!!
  session->created = unix_time_now();

  clib_bihash_kv_8_8_t kv2;
  kv2.key = session_id;
  kv2.value = value;
  if (clib_bihash_add_del_8_8(&vcdp->session_index_by_id, &kv2, 1)) {
    VCDP_DBG(0, "cannot add: %lx session already exists", session_id);
  }

  /* Assign service chain */
  // TODO. Set service chain based on traffic type!!!!
  vcdp_set_service_chain(tenant, session->proto, session->bitmaps);

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
vcdp_lookup_session(u32 tenant_id, ip_address_t *src, u16 sport, u8 protocol, ip_address_t *dst, u16 dport)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u64 value;
  if (!src || !dst)
    return 0;
  if (src->version != dst->version)
    return 0;

  u16 tenant_idx;
  vcdp_tenant_t *tenant = vcdp_tenant_get_by_id(tenant_id, &tenant_idx);
  if (!tenant) return 0;
  u32 context_id = tenant->context_id;

  if (src->version == AF_IP6) {

    vcdp_session_ip6_key_t k = {
      .context_id = context_id,
      .src = src->ip.ip6,
      .dst = dst->ip.ip6,
      .sport = sport,
      .dport = dport,
      .proto = protocol,
    };
    clib_bihash_kv_40_8_t kv;
    clib_memcpy(&kv.key, &k, sizeof(k));
    if (clib_bihash_search_inline_40_8(&vcdp->table6, &kv))
      return 0;
    value = kv.value;
  } else {
    vcdp_session_ip4_key_t k = {
      .context_id = context_id,
      .src = src->ip.ip4.as_u32,
      .dst = dst->ip.ip4.as_u32,
      .sport = sport,
      .dport = dport,
      .proto = protocol,
    };
    clib_bihash_kv_16_8_t kv = {.key[0] = k.as_u64[0], .key[1] = k.as_u64[1], .value = 0};
    if (clib_bihash_search_inline_16_8(&vcdp->table4, &kv))
      return 0;
    value = kv.value;
  }
  // Figure out if this is local or remote thread
  u32 thread_index = vcdp_thread_index_from_lookup(value);
  /* known flow which belongs to this thread */
  u32 flow_index = value & (~(u32) 0);
  u32 session_index = vcdp_session_from_flow_index(flow_index);
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  return pool_elt_at_index(ptd->sessions, session_index);
}

void
vcdp_session_remove(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_session_t *session, u32 thread_index,
                    u32 session_index)
{
  u64 h;
  clib_bihash_kv_8_8_t kv2 = {0};
  kv2.key = session->session_id;

  /* Stop timer if running */
  VCDP_DBG(2, "Removing session %u %llx", session_index, session->session_id);
  VCDP_DBG(2, "Stopping timer for session %u", session_index);
  vcdp_session_timer_stop(&ptd->wheel, &session->timer);

  // Is this session on the expiry queue?
  u32 index = vec_search(ptd->expired_sessions, session_index);
  if (index != ~0) {
    VCDP_DBG(1, "WARNING: Found session to be removed on expired vector %u", session_index);
    vec_del1(ptd->expired_sessions, index);
  }

  if (vcdp_session_add_del_key(&session->keys[VCDP_SESSION_KEY_PRIMARY], 0, 0, &h)) {
    VCDP_DBG(1, "Failed to remove session key from table");
  }

  if (session->key_flags & (VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4|VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6)) {
    if (vcdp_session_add_del_key(&session->keys[VCDP_SESSION_KEY_SECONDARY], 0, 0, &h)) {
      VCDP_DBG(1, "Failed to remove session from table4 - secondary");
    }
  }

  if (clib_bihash_add_del_8_8(&vcdp->session_index_by_id, &kv2, 0)) {
    VCDP_DBG(1, "Removing %lx failed", session->session_id);
  }
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_REMOVED], thread_index,
                                session->tenant_idx, 1);


  vlib_increment_combined_counter(&vcdp->tenant_combined_ctr[VCDP_TENANT_COUNTER_TX], thread_index,
                                  session->tenant_idx, session->pkts[VCDP_FLOW_FORWARD], session->bytes[VCDP_FLOW_FORWARD]);
  vlib_increment_combined_counter(&vcdp->tenant_combined_ctr[VCDP_TENANT_COUNTER_RX], thread_index,
                                  session->tenant_idx, session->pkts[VCDP_FLOW_REVERSE], session->bytes[VCDP_FLOW_REVERSE]);
  pool_put_index(ptd->sessions, session_index);
}

void
vcdp_session_remove_or_rearm(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, u32 thread_index, u32 session_index)
{
  /* Session may have been removed already */
  if (pool_is_free_index(ptd->sessions, session_index))
    return;
  vcdp_session_t *session = vcdp_session_at_index(ptd, session_index);
  f64 diff = (session->timer.next_expiration - (ptd->current_time + VCDP_TIMER_INTERVAL)) / VCDP_TIMER_INTERVAL;
  if (diff > (f64) 1.) {
    /* Rearm the timer accordingly */
    VCDP_DBG(2, "Rearming timer for session %u Now: %.2f Ticks: %.2f %llx", session_index,
             ptd->current_time, diff, session->session_id);
    vcdp_session_timer_update_maybe_past(&ptd->wheel, &session->timer, session_index, ptd->current_time, diff);
  } else {
    VCDP_DBG(2, "Removing session %u %llx", session_index, session->session_id);
    vcdp_session_remove(vcdp, ptd, session, thread_index, session_index);
  }
}

/*
 * An existing TCP session is being reused for a new flow with the same 6-tuple.
 * Reset counters.
 */
void
vcdp_session_reopen(vcdp_main_t *vcdp, u32 thread_index, vcdp_session_t *session)
{
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_REMOVED], thread_index,
                                session->tenant_idx, 1);
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_CREATED], thread_index,
                                session->tenant_idx, 1);
  vlib_increment_simple_counter(&vcdp->tenant_simple_ctr[VCDP_TENANT_COUNTER_REUSED], thread_index,
                                session->tenant_idx, 1);

  session->bytes[VCDP_FLOW_FORWARD] = 0;
  session->bytes[VCDP_FLOW_REVERSE] = 0;
  session->pkts[VCDP_FLOW_FORWARD] = 0;
  session->pkts[VCDP_FLOW_REVERSE] = 0;
}

bool
vcdp_session_is_expired(vcdp_session_t *session, f64 time_now)
{
  return (session->state != VCDP_SESSION_STATE_STATIC && session->timer.next_expiration - time_now < 1);
}

int
vcdp_session_try_add_secondary_key(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, u32 thread_index,
                                   u32 pseudo_flow_index, vcdp_session_key_t *key, u64 *h)
{
  int rv;
  u64 value;
  vcdp_session_t *session;
  u32 session_index;

  value = vcdp_session_mk_table_value(thread_index, pseudo_flow_index);
  session_index = vcdp_session_from_flow_index(pseudo_flow_index);
  session = vcdp_session_at_index(ptd, session_index);
  clib_memcpy(&session->keys[VCDP_SESSION_KEY_SECONDARY], key, sizeof(*key));

  rv = vcdp_session_add_del_key(key, 2, value, h);
  if (rv == 0) {
    session->key_flags |= key->is_ip6 ? VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6 : VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4;
  }
  return rv;
}
