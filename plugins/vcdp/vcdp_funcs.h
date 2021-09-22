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
  vcdp_bihash_kv46_t kv = { 0 };
  kv2.key = session->session_id;
  pool_put_index (ptd->sessions, session_index);
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    {
      clib_memcpy_fast (&kv.kv4.key,
			&session->keys[VCDP_SESSION_KEY_PRIMARY].key4,
			sizeof (kv.kv4.key));
      clib_bihash_add_del_24_8 (&vcdp->table4, &kv.kv4, 0);
    }
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4)
    {
      clib_memcpy_fast (&kv.kv4.key,
			&session->keys[VCDP_SESSION_KEY_SECONDARY].key4,
			sizeof (kv.kv4.key));
      clib_bihash_add_del_24_8 (&vcdp->table4, &kv.kv4, 0);
    }
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    {
      clib_memcpy_fast (&kv.kv6.key,
			&session->keys[VCDP_SESSION_KEY_PRIMARY].key6,
			sizeof (kv.kv6.key));
      clib_bihash_add_del_48_8 (&vcdp->table6, &kv.kv6, 0);
    }
  if (session->key_flags & VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6)
    {
      clib_memcpy_fast (&kv.kv6.key,
			&session->keys[VCDP_SESSION_KEY_SECONDARY].key6,
			sizeof (kv.kv6.key));
      clib_bihash_add_del_48_8 (&vcdp->table6, &kv.kv6, 0);
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
				    vcdp_session_ip46_key_t *key,
				    ip46_type_t type, u64 *h)
{
  int rv;
  vcdp_bihash_kv46_t kv;
  u64 value;
  vcdp_session_t *session;
  u32 session_index;
  value = vcdp_session_mk_table_value (thread_index, pseudo_flow_index);

  if (type == IP46_TYPE_IP4)
    {
      kv.kv4.key[0] = key->key4.ip4_key.as_u64x2[0];
      kv.kv4.key[1] = key->key4.ip4_key.as_u64x2[1];
      kv.kv4.key[2] = key->key4.as_u64;
      kv.kv4.value = value;
      *h = clib_bihash_hash_24_8 (&kv.kv4);
      if ((rv = vcdp_bihash_add_del_inline_with_hash_24_8 (
	     &vcdp->table4, &kv.kv4, *h, 2)) == 0)
	{
	  session_index = vcdp_session_from_flow_index (pseudo_flow_index);
	  session = vcdp_session_at_index (ptd, session_index);
	  session->keys[VCDP_SESSION_KEY_SECONDARY] = *key;
	  session->pseudo_dir[VCDP_SESSION_KEY_SECONDARY] =
	    pseudo_flow_index & 0x1;
	  session->key_flags |= VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4;
	}
    }
  else
    {
      kv.kv6.key[0] = key->key6.ip6_key.as_u64;
      kv.kv6.key[1] = key->key6.ip6_key.as_u64x4[0];
      kv.kv6.key[2] = key->key6.ip6_key.as_u64x4[1];
      kv.kv6.key[3] = key->key6.ip6_key.as_u64x4[2];
      kv.kv6.key[4] = key->key6.ip6_key.as_u64x4[3];
      kv.kv6.key[5] = key->key6.as_u64;
      kv.kv6.value = value;
      *h = clib_bihash_hash_48_8 (&kv.kv6);
      if ((rv = vcdp_bihash_add_del_inline_with_hash_48_8 (
	     &vcdp->table6, &kv.kv6, *h, 2)) == 0)
	{
	  session_index = vcdp_session_from_flow_index (pseudo_flow_index);
	  session = vcdp_session_at_index (ptd, session_index);
	  session->keys[VCDP_SESSION_KEY_SECONDARY] = *key;
	  session->pseudo_dir[VCDP_SESSION_KEY_SECONDARY] =
	    pseudo_flow_index & 0x1;
	  session->key_flags |= VCDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6;
	}
    }

  return rv;
}

static_always_inline u8
vcdp_renormalise_ip4_key (vcdp_session_ip4_key_t *key, u32 old_pseudo)
{
  if (key->ip4_key.ip_addr_hi < key->ip4_key.ip_addr_lo)
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