// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_funcs_h
#define included_vcdp_funcs_h
#include <vcdp/vcdp.h>

static_always_inline void
vcdp_session_remove(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_session_t *session, u32 thread_index,
                    u32 session_index)
{
  clib_bihash_kv_8_8_t kv2 = {0};
  clib_bihash_kv_16_8_t kv = {0};
  kv2.key = session->session_id;
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4) {
    clib_memcpy_fast(&kv.key, &session->keys[VCDP_SESSION_KEY_PRIMARY], sizeof(kv.key));
    clib_bihash_add_del_16_8(&vcdp->table4, &kv, 0);
  }
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4) {
    clib_memcpy_fast(&kv.key, &session->keys[VCDP_SESSION_KEY_SECONDARY], sizeof(kv.key));
    clib_bihash_add_del_16_8(&vcdp->table4, &kv, 0);
  }
  clib_bihash_add_del_8_8(&vcdp->session_index_by_id, &kv2, 0);
  vlib_increment_simple_counter(&vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_REMOVED], thread_index,
                                session->tenant_idx, 1);
  pool_put_index(ptd->sessions, session_index);
}

static_always_inline void
vcdp_session_remove_or_rearm(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, u32 thread_index, u32 session_index)
{
  vcdp_session_t *session = vcdp_session_at_index(ptd, session_index);
  f64 diff = (session->timer.next_expiration - (ptd->current_time + VCDP_TIMER_INTERVAL)) / VCDP_TIMER_INTERVAL;
  if (diff > (f64) 1.)
    /* Rearm the timer accordingly */
    vcdp_session_timer_start(&ptd->wheel, &session->timer, session_index, ptd->current_time, diff);
  else
    vcdp_session_remove(vcdp, ptd, session, thread_index, session_index);
}

static void
vcdp_session_key_swap(vcdp_session_ip4_key_t *key)
{
  u16 tmp = key->dport;
  key->dport = key->sport;
  key->sport = tmp;

  u32 tmp2 = key->dst;
  key->dst = key->src;
  key->src = tmp2;
}

static_always_inline int
vcdp_session_try_add_secondary_key(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, u32 thread_index,
                                   u32 pseudo_flow_index, vcdp_session_ip4_key_t *key, u64 *h)
{
  int rv;
  clib_bihash_kv_16_8_t kv;
  u64 value;
  vcdp_session_t *session;
  u32 session_index;
  value = vcdp_session_mk_table_value(thread_index, pseudo_flow_index);

  vcdp_session_key_swap(key);

  kv.key[0] = key->as_u64[0];
  kv.key[1] = key->as_u64[1];
  kv.value = value;
  *h = clib_bihash_hash_16_8(&kv);
  if ((rv = vcdp_bihash_add_del_inline_with_hash_16_8(&vcdp->table4, &kv, *h, 2)) == 0) {
    session_index = vcdp_session_from_flow_index(pseudo_flow_index);
    session = vcdp_session_at_index(ptd, session_index);
    session->keys[VCDP_SESSION_KEY_SECONDARY] = *key;
    session->key_flags |= VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4;
  }
  return rv;
}

#endif
