#ifndef __NAT_INLINES_H__
#define __NAT_INLINES_H__

#include <vcdp/vcdp.h>
#include "nat.h"
#include <vcdp/session.h>
#include <stdio.h>
#include <stdint.h>

static_always_inline int
nat_try_add_secondary_key(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, u32 thread_index, u32 pseudo_flow_index,
                          f64 now, vcdp_session_key_t *key, int *n_expired)
{
  u64 value;
  u32 owner_thread_index, session_index;

  if (vcdp_lookup(key, &value) == 0) {
    vcdp_session_t *session = vcdp_session_from_lookup_value(vcdp, value, &owner_thread_index, &session_index);
    if (owner_thread_index == thread_index) {
      // We own it - check if expired
      if (vcdp_session_is_expired(session, now)) {
        *n_expired = 1;
        vcdp_session_remove(vcdp, ptd, session, thread_index, session_index);
        if (vcdp_session_try_add_secondary_key(vcdp, ptd, thread_index, pseudo_flow_index, key) == 0) {
          return 0;
        }
      } else {
        *n_expired = 0;
      }
    }
  } else {
    if (vcdp_session_try_add_secondary_key(vcdp, ptd, thread_index, pseudo_flow_index, key) == 0) {
      return 0;
    }
  }
  return -1;
}

/*
 * Try to allocate a port for the new key. If success, return 0, otherwise return -1.
 * New port is written to new_key->ip4.dport.
 */
static_always_inline int
nat_try_port_allocation(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, u32 thread_index, u32 pseudo_flow_index,
                        vcdp_session_key_t *org_key, vcdp_session_key_t *new_key, int *n_retries, int *n_expired)
{
  nat_main_t *nat = &nat_main;
  f64 now = vlib_time_now(vlib_get_main());

  // Try same source port
  new_key->dport = org_key->sport;
  if (nat_try_add_secondary_key(vcdp, ptd, thread_index, pseudo_flow_index, now, new_key, n_expired) == 0) {
    return 0;
  }

  for (int retries = 0; retries < nat->port_retries; retries++) {
    new_key->dport = clib_host_to_net_u16(1024 + (random_u32(&nat->random_seed) % 64512));
    if (nat_try_add_secondary_key(vcdp, ptd, thread_index, pseudo_flow_index, now, new_key, n_expired) == 0) {
      *n_retries = retries + 1;
      return 0;
    }
  }
  return -1;
}

#endif
