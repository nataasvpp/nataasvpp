// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

/*
 * A NAT instance is mostly a pool of addresses. The address is either statically configured or learnt from an interface
 * address. The NAT code is interface agnostic, neither does it care if the pool addresses are reachable or not.
 * Think of it as a blind rewrite engine. With a few instance counters.
 */
#include <assert.h>
#include <vcdp/vcdp.h>
#include <vcdp_services/nat/nat.h>
#include <vppinfra/pool.h>
#include <vlib/stats/stats.h>
#include <vnet/fib/fib_source.h>
#include <vnet/fib/fib_table.h>
#include "vcdp_nat_dpo.h"

nat_main_t nat_main;

nat_instance_t *
vcdp_nat_lookup_by_uuid(char *uuid, u16 *nat_idx)
{
  nat_main_t *nat = &nat_main;

  uword *p = hash_get_mem(nat->uuid_hash, uuid);
  if (p == 0) {
    return 0;
  }
  *nat_idx = p[0];
  return pool_elt_at_index(nat->instances, p[0]);
}

// The NAT node counters are a set of two dimensional vectors (thread, NAT instance index).
// The NAT instance names are symlinked into the vectors.
static void
vcdp_nat_init_counters(void)
{
  nat_main_t *nat = &nat_main;
  clib_spinlock_init(&nat->counter_lock);
  vcdp_nat_init_counters_simple(nat->simple_counters);
  vcdp_nat_init_counters_combined(nat->combined_counters);
}

static u32 **simple_dir_entry_indices = 0;
static u32 **combined_dir_entry_indices = 0;

static void
vcdp_nat_init_counters_per_instance(nat_instance_t *instance, u16 nat_idx)
{
  /* Allocate counters for this interface. */
  nat_main_t *nat = &nat_main;
  vec_validate (simple_dir_entry_indices, nat_idx);
  vec_validate (combined_dir_entry_indices, nat_idx);

  clib_spinlock_lock (&nat->counter_lock);
  vcdp_nat_init_counters_simple_per_instance(nat->simple_counters, nat_idx, instance->nat_id, &simple_dir_entry_indices[nat_idx]);
  vcdp_nat_init_counters_combined_per_instance(nat->combined_counters, nat_idx, instance->nat_id, &combined_dir_entry_indices[nat_idx]);
  clib_spinlock_unlock (&nat->counter_lock);
}

static void
vcdp_nat_remove_counters_per_instance(nat_instance_t *instance, u16 nat_idx)
{
  // Remove symlink
  nat_main_t *nat = &nat_main;

  clib_spinlock_lock (&nat->counter_lock);
  vcdp_nat_remove_counters_simple_per_instance(simple_dir_entry_indices[nat_idx]);
  vcdp_nat_remove_counters_combined_per_instance(combined_dir_entry_indices[nat_idx]);
  vec_free(simple_dir_entry_indices[nat_idx]);
  vec_free(combined_dir_entry_indices[nat_idx]);
  clib_spinlock_unlock (&nat->counter_lock);
}

/*
 * Call this if the pool address isn't already in the FIB
 */
/*static */void
vcdp_nat_dpo_no_entry(ip4_address_t address, u16 nat_idx, bool is_if) {
    // Create DPO for the pool
  dpo_id_t dpo_v4 = DPO_INVALID;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4.as_u32 = address.as_u32,
  };
  fib_source_t fib_src = fib_source_allocate("dpo-vcdp-nat_source", 0x2, FIB_SOURCE_BH_SIMPLE);
  vcdp_nat_dpo_create(DPO_PROTO_IP4, nat_idx, &dpo_v4, is_if);
  u32 fib_flags = FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT;
  fib_flags |= FIB_ENTRY_FLAG_EXCLUSIVE ;
  fib_table_entry_special_dpo_add(0, &pfx, fib_src, fib_flags, &dpo_v4);
  dpo_reset(&dpo_v4);
}

// TODO: Support prefixes as well as a vector of addresses
int
vcdp_nat_add(char *nat_id, u32 context_id, ip4_address_t *addrs, bool is_if)
{
  nat_main_t *nat = &nat_main;
  nat_instance_t *instance;
  u16 nat_idx;

  size_t uuid_len = strnlen_s(nat_id, sizeof(instance->nat_id));
  if (uuid_len == 0 || uuid_len == sizeof(instance->nat_id)) return -1;
  if (addrs == 0) return -1;

  instance = vcdp_nat_lookup_by_uuid(nat_id, &nat_idx);
  if (instance) return -1; // exists already
  if (pool_elts(nat->instances) == vcdp_cfg_main.no_nat_instances)
    return -1;

  // Create pool entry
  pool_get_zero(nat->instances, instance);
  strcpy_s(instance->nat_id, sizeof(instance->nat_id), nat_id);
  instance->addresses = vec_dup(addrs);
  // NB: This approach only works for fixed pools
  nat_idx = instance - nat->instances;
  hash_set_mem(nat->uuid_hash, instance->nat_id, nat_idx);

  // Create DPO for the pool
  //TODO DPO: vcdp_nat_dpo_no_entry(addrs[0], nat_idx, is_if);

  // Initialise counters. Single dimension.
  vcdp_nat_init_counters_per_instance(instance, nat_idx);

  return 0;
}

int
vcdp_nat_remove(char *nat_id)
{
  nat_main_t *nat = &nat_main;
  nat_instance_t *instance;
  u16 nat_idx;

  size_t uuid_len = strnlen_s(nat_id, sizeof(instance->nat_id));
  if (uuid_len == 0 || uuid_len == sizeof(instance->nat_id)) return -1;
  instance = vcdp_nat_lookup_by_uuid(nat_id, &nat_idx);
  if (!instance) return -1; // no instance to remove

  // Remove from uuid hash
  hash_unset_mem(nat->uuid_hash, instance->nat_id);

  vcdp_nat_remove_counters_per_instance(instance, nat_idx);

  // Remove from pool
  pool_put(nat->instances, instance);


  return 0;
}

nat_instance_t *
vcdp_nat_instance_by_tenant_idx(u16 tenant_idx, u16 *nat_idx)
{
  nat_main_t *nat = &nat_main;
  if (vec_len(nat->instance_by_tenant_idx) <= tenant_idx) return 0;
  u16 *nat_idxp = vec_elt_at_index (nat->instance_by_tenant_idx, tenant_idx);
  *nat_idx = *nat_idxp;
  if (*nat_idx == 0xFFFF) return 0;
  return pool_elt_at_index(nat->instances, *nat_idx);
}

/*
 * Map tenant id to NAT instance
 */
int
vcdp_nat_bind_set_unset (u32 tenant_id, char *nat_id, bool is_set)
{
  nat_main_t *nat = &nat_main;
  u16 tenant_idx, nat_idx;

  if (!nat_id) return -1;

  vcdp_tenant_t *tenant = vcdp_tenant_get_by_id(tenant_id, &tenant_idx);
  if (!tenant) return -1;

  if (is_set) {
    nat_instance_t *instance = vcdp_nat_lookup_by_uuid(nat_id, &nat_idx);
    if (!instance) {
      // Check if we have a pending tenant for the interface NAT instance
      nat_if_instance_t *if_instance;
      int rv = -1;
      pool_foreach(if_instance, nat->if_instances) {
        if (strncmp(if_instance->nat_id, nat_id, sizeof(if_instance->nat_id)) == 0) {
          vec_add1(if_instance->pending_tenant_ids, tenant_id);
          rv = 0;
          break;
        }
      };
      return rv;
    }
    vec_validate_init_empty(nat->instance_by_tenant_idx, tenant_idx, 0xFFFF);
    nat->instance_by_tenant_idx[tenant_idx] = nat_idx;
  } else {
    nat->instance_by_tenant_idx[tenant_idx] = 0xFFFF;
  }
  return 0;
}

void *
vcdp_nat_interface_by_sw_if_index(u32 sw_if_index)
{
  nat_main_t *nat = &nat_main;

  if (!nat->interface_by_sw_if_index || sw_if_index > (vec_len(nat->interface_by_sw_if_index) - 1))
    return 0;
  u32 index = nat->interface_by_sw_if_index[sw_if_index];
  if (index == ~0)
    return 0;
  if (pool_is_free_index(nat->if_instances, index))
    return 0;
  return pool_elt_at_index(nat->if_instances, index);
}

static u32 context_id_from_sw_if_index(u32 sw_if_index)
{
  fib_protocol_t fib_proto = FIB_PROTOCOL_IP4;
  fib_table_t *fib_table = 0;
  u32 table_id = 0; // Default to context 0
  u32 fib_index = fib_table_get_index_for_sw_if_index(fib_proto, sw_if_index);
  if (fib_index != ~0) {
    fib_table = fib_table_get(fib_index, fib_proto);
    table_id = fib_table->ft_table_id;
  }
  return table_id;
}
void
vcdp_nat_ip4_add_del_interface_address(ip4_main_t *im, uword opaque, u32 sw_if_index, ip4_address_t *address,
                                       u32 address_length, u32 if_address_index, u32 is_delete)
{
  // Is this an interface we are interested in?
  nat_if_instance_t *if_instance = vcdp_nat_interface_by_sw_if_index(sw_if_index);
  if (!if_instance) return; // Not a NAT interface

  // If address is deleted and address is used as a NAT pool, delete NAT instance
  // TODO: Handle the cases where a secondary address is added (or a secondary address is deleted)

  // Using the VRF ID as the context ID for an interface NAT pool.
  u32 context_id = context_id_from_sw_if_index(sw_if_index);

  if (!is_delete) {
    // If address is added and address is used as a NAT pool, create NAT instance
    clib_warning("Creating NAT instance %s with address %U", if_instance->nat_id, format_ip4_address, address);
    ip4_address_t *v = 0;
    vec_add1(v, *address);
    vcdp_nat_add(if_instance->nat_id, context_id, v, true);
    vec_free(v);

    // Check if we have any pending tenant bindings
    u16 *tenant_id = 0;
    vec_foreach(tenant_id, if_instance->pending_tenant_ids) {
      clib_warning("Binding pending tenant: %d to NAT: %s", *tenant_id, if_instance->nat_id);
      vcdp_nat_bind_set_unset(*tenant_id, if_instance->nat_id, true);
    }
  } else {
    clib_warning("Removing NAT instance %s with address %U", if_instance->nat_id, format_ip4_address, address);
    vcdp_nat_remove(if_instance->nat_id);
  }
}

/*
 * This helper function should be in the IP component
 */
static void
vcdp_nat_register_address_changes(u32 sw_if_index, ip4_add_del_interface_address_function_t func)
{
  ip4_main_t *im4 = &ip4_main;
  ip4_add_del_interface_address_callback_t cb;

  cb.function = func;
  cb.function_opaque = 0;
  vec_add1 (im4->add_del_interface_address_callbacks, cb);
}

// Copy from ip4_forward.c to avoid dependency
static ip4_address_t *
vcdp_ip4_interface_first_address (ip4_main_t * im, u32 sw_if_index,
                             ip_interface_address_t ** result_ia)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *result = 0;

  foreach_ip_interface_address(lm, ia, sw_if_index, 1 /* honor unnumbered */, ({
                                 ip4_address_t *a = ip_interface_address_get_address(lm, ia);
                                 result = a;
                                 break;
                               }));
  if (result_ia)
    *result_ia = result ? ia : 0;
  return result;
}

int
vcdp_nat_if_add(char *nat_id, u32 sw_if_index)
{
  nat_main_t *nat = &nat_main;
  nat_if_instance_t *if_instance;
  nat_instance_t *instance;
  u16 nat_idx;

  size_t uuid_len = strnlen_s(nat_id, sizeof(instance->nat_id));
  if (uuid_len == 0 || uuid_len == sizeof(instance->nat_id)) return -1;

  instance = vcdp_nat_lookup_by_uuid(nat_id, &nat_idx);
  if (instance) return -1; // exists already

  pool_get_zero(nat->if_instances, if_instance);
  if_instance->sw_if_index = sw_if_index;
  vec_validate_init_empty(nat->interface_by_sw_if_index, sw_if_index, ~0);
  nat->interface_by_sw_if_index[sw_if_index] = if_instance - nat->if_instances;
  strcpy_s(if_instance->nat_id, sizeof(instance->nat_id), nat_id);

  // Pick up existing addresses on this interface
  ip4_address_t *address = vcdp_ip4_interface_first_address(&ip4_main, sw_if_index, 0);
  u32 context_id = context_id_from_sw_if_index(sw_if_index);
  if (address) {
    ip4_address_t *v = 0;
    vec_add1(v, *address);
    vcdp_nat_add(if_instance->nat_id, context_id, v, true);
    vec_free(v);
  }

  // Register for address changes on this interface
  vcdp_nat_register_address_changes(sw_if_index, vcdp_nat_ip4_add_del_interface_address);
  return 0;
}

void
vcdp_nat_set_port_retries(u32 port_retries)
{
  nat_main_t *nat = &nat_main;
  nat->port_retries = port_retries;
}

/* Ports are big endian */
static int
vcdp_nat_port_forwarding_session_add(u32 tenant_idx, nat_3tuple_ip4_key_t *key, ip4_address_t *inside, u16 iport)
{
  nat_main_t *nat = &nat_main;
  // Create session data in pool
  nat_port_forwarding_session_t *session;
  pool_get(nat->port_forwarding_sessions, session);

  session->addr.ip4.as_u32 = inside->as_u32;
  session->port = iport;
  session->fib_index = 0; // TODO: Get from tenant
  session->ops = NAT_REWRITE_OP_SADDR | NAT_REWRITE_OP_SPORT | NAT_REWRITE_OP_TXFIB;
  session->nat_idx = 0; // TODO: Needed?
  session->tenant_idx = tenant_idx;

  // Register key in hash
  clib_bihash_kv_16_8_t kv = {
    .key[0] = key->as_u64[0],
    .key[1] = key->as_u64[1],
    .value = session - nat->port_forwarding_sessions
  };

  if (clib_bihash_add_del_16_8(&nat->port_forwarding, &kv, 2)) {
    /* already exists */
    clib_warning("session already exists");
    pool_put(nat->port_forwarding_sessions, session);
    return -1;
  }

  /* Reserve port in NAT pool (if outside address is pool (or part of pool))*/
  clib_warning("NOT YET IMPLEMENTED. Reserving %U:%d from NAT pool", format_ip4_address, &key->addr, ntohs(key->port));
  return 0;
}

static int
vcdp_nat_port_forwarding_session_del(u32 tenant_idx, nat_3tuple_ip4_key_t *key)
{
  nat_main_t *nat = &nat_main;
  clib_bihash_kv_16_8_t kv = {
    .key[0] = key->as_u64[0],
    .key[1] = key->as_u64[1],
  };

  if (clib_bihash_search_inline_16_8(&nat->port_forwarding, &kv)) {
    return -1;
  }

  // Delete from hash
  clib_bihash_add_del_16_8(&nat->port_forwarding, &kv, 0);

  // Delete from pool
  pool_put_index(nat->port_forwarding_sessions, kv.value);

  return 0;
}

int
vcdp_nat_port_forwarding(char *nat_id, u32 tenant_id, ip4_address_t *outside, u16 oport, u8 proto, ip4_address_t *inside, u16 iport,
                         bool is_add)
{
  int rv = 0;
  u32 context_id = 0;

  nat_3tuple_ip4_key_t  key = {
    .context_id = context_id,
    .addr = outside->as_u32,
    .port = htons(oport),
    .proto = proto,
  };

  u16 tenant_idx = vcdp_tenant_idx_by_id(tenant_id);

  if (is_add) {
    rv = vcdp_nat_port_forwarding_session_add(tenant_idx, &key, inside, htons(iport));
  } else {
    rv = vcdp_nat_port_forwarding_session_del(tenant_idx, &key);
  }
  return rv;
}

#define VCDP_NAT_MAX_PORT_ALLOC_RETRIES 32 /* retries to allocate a port */

static clib_error_t *
nat_init(vlib_main_t *vm)
{
  nat_main_t *nat = &nat_main;
  nat->uuid_hash = hash_create_string(0, sizeof(uword));
  pool_init_fixed(nat->instances, vcdp_cfg_main.no_nat_instances);

  // Two flows per session
  vec_validate(nat->flows, 2 * vcdp_cfg_main.no_sessions);
  vec_validate(nat->flows64, 2 * vcdp_cfg_main.no_sessions);

  // Create a FIB entry for the NAT pool addresses.
  // TODO DPO: vcdp_nat_dpo_module_init(); // Only for pool addresses not for interface addresses?

  vcdp_nat_init_counters();

  nat->port_retries = VCDP_NAT_MAX_PORT_ALLOC_RETRIES;

  /* Port forwarding 3-tuple hash */
  clib_bihash_init_16_8(&nat->port_forwarding, "vcdp nat port forwarding", 256, 0);

  // Seed random number generator
  nat->random_seed = random_default_seed();
  return 0;
}
VLIB_INIT_FUNCTION(nat_init);
