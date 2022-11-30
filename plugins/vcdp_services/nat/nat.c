// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp/vcdp.h>
#include <vcdp_services/nat/nat.h>
#include <vppinfra/pool.h>

nat_main_t nat_main;

nat_instance_t *
vcdp_nat_lookup_by_uuid(char *uuid, u16 *nat_idx)
{
  nat_main_t *nat = &nat_main;

  uword *p = hash_get(nat->uuid_hash, uuid);
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

  // Create pool entry
  pool_get_zero(nat->instances, instance);
  strcpy_s(instance->nat_id, sizeof(instance->nat_id), nat_id);
  instance->addresses = vec_dup(addrs);
  hash_set(nat->uuid_hash, nat_id, instance - nat->instances);

  return 0;
}


nat_instance_t *
vcdp_nat_instance_by_tenant_idx(u16 tenant_idx, u16 *nat_idx)
{
  nat_main_t *nat = &nat_main;
  if (vec_len(nat->instance_by_tenant_idx) < tenant_idx) return 0;
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

  nat_instance_t *instance = vcdp_nat_lookup_by_uuid(nat_id, &nat_idx);
  if (!instance) return -1;

  vec_validate_init_empty(nat->instance_by_tenant_idx, tenant_idx, 0xFFFF);
  nat->instance_by_tenant_idx[tenant_idx] = nat_idx;

  return 0;
}

static clib_error_t *
nat_init(vlib_main_t *vm)
{
  nat_main_t *nat = &nat_main;
  nat_per_thread_data_t *ptd;
  uword n_threads = vlib_get_n_threads();
  nat->uuid_hash = hash_create_string(0, sizeof(uword));
  vec_validate(nat->ptd, n_threads);
  // TODO: Make configurable
  vec_foreach (ptd, nat->ptd)
    pool_init_fixed(ptd->flows, 2ULL << VCDP_LOG2_SESSIONS_PER_THREAD);

  return 0;
}
VLIB_INIT_FUNCTION(nat_init);
