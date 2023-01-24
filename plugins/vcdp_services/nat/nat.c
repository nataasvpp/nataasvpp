// Copyright(c) 2022 Cisco Systems, Inc.

/*
 * A NAT instance is mostly a pool of addresses. The address is either statically configured or learnt from an interface
 * address. The NAT code is interface agnostic, neither does it care if the pool addresses are reachable or not.
 * Think of it as a blind rewrite engine. With a few instance counters.
 */
#include <vcdp/vcdp.h>
#include <vcdp_services/nat/nat.h>
#include <vppinfra/pool.h>

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

int
vcdp_nat_add(char *nat_id, ip4_address_t *addrs)
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
  hash_set_mem(nat->uuid_hash, instance->nat_id, instance - nat->instances);

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

  // Remove from pool
  pool_put(nat->instances, instance);

  return 0;
}

nat_instance_t *
vcdp_nat_instance_by_tenant_idx(u16 tenant_idx, u16 *nat_idx)
{
  nat_main_t *nat = &nat_main;
  if (vec_len(nat->instance_by_tenant_idx) <= tenant_idx) return 0;
  nat_idx = vec_elt_at_index (nat->instance_by_tenant_idx, tenant_idx);
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
    if (!instance)
      return -1;
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

void
vcdp_nat_ip4_add_del_interface_address(ip4_main_t *im, uword opaque, u32 sw_if_index, ip4_address_t *address,
                                       u32 address_length, u32 if_address_index, u32 is_delete)
{
  // Is this an interface we are interested in?
  nat_if_instance_t *if_instance = vcdp_nat_interface_by_sw_if_index(sw_if_index);
  if (!if_instance) return; // Not a NAT interface

  // If address is deleted and address is used as a NAT pool, delete NAT instance
  // TODO: Handle the cases where a secondary address is added (or a secondary address is deleted)
  if (!is_delete) {
    // If address is added and address is used as a NAT pool, create NAT instance
    clib_warning("Creating NAT instance %s with address %U", if_instance->nat_id, format_ip4_address, address);
    ip4_address_t *v = 0;
    vec_add1(v, *address);
    vcdp_nat_add(if_instance->nat_id, v);
    vec_free(v);
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
  if (address) {
    ip4_address_t *v = 0;
    vec_add1(v, *address);
    vcdp_nat_add(if_instance->nat_id, v);
    vec_free(v);
  }

  // Register for address changes on this interface
  vcdp_nat_register_address_changes(sw_if_index, vcdp_nat_ip4_add_del_interface_address);
  return 0;
}

static clib_error_t *
nat_init(vlib_main_t *vm)
{
  nat_main_t *nat = &nat_main;
  nat_per_thread_data_t *ptd;
  uword n_threads = vlib_get_n_threads();
  nat->uuid_hash = hash_create_string(0, sizeof(uword));
  pool_init_fixed(nat->instances, vcdp_cfg_main.no_nat_instances);
  vec_validate(nat->ptd, n_threads);
  vec_foreach (ptd, nat->ptd)
    pool_init_fixed(ptd->flows, vcdp_cfg_main.no_sessions_per_thread);

  return 0;
}
VLIB_INIT_FUNCTION(nat_init);
