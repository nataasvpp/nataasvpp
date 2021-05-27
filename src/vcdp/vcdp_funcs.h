/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_vcdp_funcs_h__
#define __included_vcdp_funcs_h__
#include <vcdp/vcdp.h>

static_always_inline void
vcdp_session_remove (vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd,
		     vcdp_session_t *session, u32 thread_index,
		     u32 session_index)
{
  clib_bihash_kv_8_8_t kv2 = { 0 };
  clib_bihash_kv_24_8_t kv = { 0 };
  kv2.key = session->session_id;
  pool_put_index (ptd->sessions, session_index);
  if (session->key_flags & (VCDP_SESSION_KEY_FLAG_PRI_INIT_VALID |
			    VCDP_SESSION_KEY_FLAG_PRI_RESP_VALID))
    {
      clib_memcpy_fast (&kv.key, &session->key[VCDP_SESSION_KEY_PRIMARY],
			sizeof (session->key[0]));
      clib_bihash_add_del_24_8 (&vcdp->table4, &kv, 0);
    }
  if (session->key_flags & (VCDP_SESSION_KEY_FLAG_SEC_INIT_VALID |
			    VCDP_SESSION_KEY_FLAG_SEC_RESP_VALID))
    {
      clib_memcpy_fast (&kv.key, &session->key[VCDP_SESSION_KEY_SECONDARY],
			sizeof (session->key[0]));
      clib_bihash_add_del_24_8 (&vcdp->table4, &kv, 0);
    }
  clib_bihash_add_del_8_8 (&vcdp->session_index_by_id, &kv2, 0);
  vlib_increment_simple_counter (
    &vcdp->tenant_session_ctr[VCDP_TENANT_SESSION_COUNTER_REMOVED],
    thread_index, session->tenant_idx, 1);
}

static_always_inline void
vcdp_session_remove_or_rearm (vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd,
			      u32 thread_index, u32 session_index)
{
  vcdp_session_t *session = vcdp_session_at_index (ptd, session_index);
  f64 diff = (session->timer.next_expiration -
	      (ptd->current_time + VCDP_TIMER_INTERVAL)) /
	     VCDP_TIMER_INTERVAL;
  if (diff > (f64) 1.)
    /* Rearm the timer accordingly */
    vcdp_session_timer_start (&ptd->wheel, &session->timer, session_index,
			      ptd->current_time, diff);
  else
    vcdp_session_remove (vcdp, ptd, session, thread_index, session_index);
}

static_always_inline int
vcdp_session_try_add_secondary_key (vcdp_main_t *vcdp,
				    vcdp_per_thread_data_t *ptd,
				    u32 thread_index, u32 pseudo_flow_index,
				    vcdp_session_ip4_key_t *key, u64 *h,
				    uword key_flags_added,
				    uword key_flags_removed)
{
  int rv;
  clib_bihash_kv_24_8_t kv;
  vcdp_session_t *session;
  u32 session_index;
  kv.key[0] = key->ip4_key.as_u64x2[0];
  kv.key[1] = key->ip4_key.as_u64x2[1];
  kv.key[2] = key->as_u64;
  kv.value = vcdp_session_mk_table_value (thread_index, pseudo_flow_index);
  *h = clib_bihash_hash_24_8 (&kv);
  if ((rv = vcdp_bihash_add_del_inline_with_hash_24_8 (&vcdp->table4, &kv, *h,
						       2)) == 0)
    {
      session_index = vcdp_session_from_flow_index (pseudo_flow_index);
      session = vcdp_session_at_index (ptd, session_index);
      session->key[VCDP_SESSION_KEY_SECONDARY] = *key;
      session->pseudo_dir[VCDP_SESSION_KEY_SECONDARY] =
	pseudo_flow_index & 0x1;
      session->key_flags |= key_flags_added;
      session->key_flags &= ~key_flags_removed;
    }
  return rv;
}

static_always_inline u8
vcdp_renormalise_key (vcdp_session_ip4_key_t *key, u32 old_pseudo)
{
  u8 proto = key->ip4_key.proto;
  if ((proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_UDP) &&
      key->ip4_key.ip_addr_hi < key->ip4_key.ip_addr_lo)
    {
      u32 tmp_ip4;
      u16 tmp_port;
      tmp_ip4 = key->ip4_key.ip_addr_hi;
      tmp_port = key->ip4_key.port_hi;
      key->ip4_key.ip_addr_hi = key->ip4_key.ip_addr_lo;
      key->ip4_key.port_hi = key->ip4_key.port_lo;
      key->ip4_key.ip_addr_lo = tmp_ip4;
      key->ip4_key.port_lo = tmp_port;
      old_pseudo ^= 0x1;
    }
  return old_pseudo;
}

#endif