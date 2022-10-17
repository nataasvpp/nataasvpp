// Copyright(c) 2022 Cisco Systems, Inc.

// Interface-less tunnels.

#include <arpa/inet.h>
#include "tunnel.h"
#include <vppinfra/bihash_template.c>
#include <vnet/adj/adj_nbr.h>
#include <vnet/vxlan/vxlan_packet.h>

vcdp_tunnel_main_t vcdp_tunnel_main;
uword *uuid_hash;

// Unidirectional session. Only accepting flows in forward direction>!>!>!>
// Adds session state to all threads.
void
make_static_key_v4(u32 context_id, ip4_address_t src, ip4_address_t dst,
                   u8 proto, u16 sport, u16 dport,
                   vcdp_session_ip4_key_t *k)
{
  u32 ip_addr_lo = src.as_u32 < dst.as_u32 ? src.as_u32 : dst.as_u32;
  u32 ip_addr_hi = src.as_u32 > dst.as_u32 ? src.as_u32 : dst.as_u32;
  u16 port_lo = sport < dport ? sport : dport;
  u16 port_hi = sport > dport ? sport : dport;

  k->context_id = context_id;
  k->ip4_key.ip_addr_lo = ip_addr_lo;
  k->ip4_key.ip_addr_hi = ip_addr_hi;
  k->ip4_key.port_lo = port_lo;
  k->ip4_key.port_hi = port_hi;
                  
  clib_memset(k->zeros, 0, sizeof(k->zeros));
}

vcdp_main2_t vcdp_main2;

// Create a new session.
// The fields must be in big-endian.
int
vcdp_session_static_add(u32 context_id, ip4_address_t src, ip4_address_t dst,
                        u8 proto, u16 sport, u16 dport) {
  vcdp_session_ip4_key_t key = {0};
  vcdp_main2_t *vm = &vcdp_main2;

  clib_bihash_kv_24_8_t kv = {};
  // clib_bihash_kv_8_8_t kv2;
  u64 value;
  // u8 proto;
  vcdp_session2_t *session;
  u32 session_idx;
  u32 pseudo_flow_idx;

  make_static_key_v4(context_id, src, dst, proto, sport, dport, &key);

  pool_get(vm->sessions, session);
  session_idx = session - vm->sessions;
  pseudo_flow_idx = session_idx << 1; // last bit indicates direction?
  value = pseudo_flow_idx; // a single global session table at the moment

  clib_memcpy_fast(&kv.key, &key, sizeof(kv.key));
  kv.value = value;
  clib_warning("adding key %U", format_bihash_kvp_24_8, &kv);
  clib_warning("adding key: %U %U %d %d", format_ip4_address, &src, format_ip4_address, &dst, sport, dport);

  // proto = ((vcdp_session_ip4_key_t *) k)->ip4_key.proto;
  if (clib_bihash_add_del_24_8(&vm->table4, &kv, 2)) {
    /* collision - remote thread created same entry */
    vcdp_log_err("failed add to bihash %U", format_bihash_kvp_24_8, &kv);
    pool_put(vm->sessions, session);
    return -1;
  }

  return 0;
}

// returns 0 on success (found), < 0 on error (not found)
int
vcdp_session_static_lookup(u32 context_id, ip4_address_t src, ip4_address_t dst,
                           u8 proto, u16 sport, u16 dport, u64 *value) {
  vcdp_session_ip4_key_t key = {0};
  vcdp_main2_t *vm = &vcdp_main2;
  clib_bihash_kv_24_8_t kv, v;
  make_static_key_v4(context_id, src, dst, proto, sport, dport, &key);

  clib_memcpy(&kv.key, &key, sizeof(kv.key));

  clib_warning("looking up key %U", format_bihash_kvp_24_8, &kv);
  clib_warning("looking key: %U %U %d %d", format_ip4_address, &src, format_ip4_address, &dst, sport, dport);

  if (!clib_bihash_search_24_8 (&vm->table4, &kv, &v)) {
    *value = v.value;
    return 0;
  }
  return -1;
}

int
vcdp_session_static_delete()
{
  // NOT YET IMPLEMENTED
  return 0;
}

vcdp_tunnel_t *
vcdp_tunnel_lookup_by_uuid (char *uuid)
{
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;

  uword *p = hash_get(uuid_hash, uuid);
  if (p == 0) {
    return 0;
  }
  return pool_elt_at_index(tm->tunnels, p[0]);
}

vcdp_tunnel_t *
vcdp_tunnel_get(u32 index) {
  return pool_elt_at_index(vcdp_tunnel_main.tunnels, index);
}

static u8 *
vcdp_vxlan_dummy_l2_build_rewrite (vcdp_tunnel_t *t)
{
  ip4_header_t *ip;
  udp_header_t *udp;
  vxlan_header_t *vxlan;
  ethernet_header_t *ethernet;
  u8 *rewrite = 0;

  u16 encap_len = sizeof(ip4_header_t) + sizeof(udp_header_t) + sizeof(vxlan_header_t) + sizeof(ethernet_header_t);
  vec_validate(rewrite, encap_len - 1);
  ip = (ip4_header_t *) rewrite;
  udp = (udp_header_t *) ip + 1;
  vxlan = (vxlan_header_t *) udp + 1;
  ethernet = (ethernet_header_t *) vxlan + 1;

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;

  /* fixup ip4/udp header length and checksum after-the-fact */
  ip->src_address.as_u32 = t->src.ip.ip4.as_u32;
  ip->dst_address.as_u32 = t->dst.ip.ip4.as_u32;
  ip->checksum = 0;

  udp->checksum = 0;
  udp->src_port = t->dport;
  udp->dst_port = t->sport;
  udp->length = 0;

  vnet_set_vni_and_flags(vxlan, t->tenant_id);
  ethernet->type = ETHERNET_TYPE_IP4;

  return (rewrite);
}

int
vcdp_tunnel_create(char *tunnel_id, u32 tenant_id, vcdp_tunnel_method_t method,
                   ip_address_t *src, ip_address_t *dst, u16 sport, u16 dport,
                   u16 mtu) {
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;
  vcdp_tunnel_t *t = vcdp_tunnel_lookup_by_uuid(tunnel_id);
  if (t) {
    return -1;
  }

  // check input
  if (!tunnel_id)
    return -1;

  size_t uuid_len = strnlen_s(tunnel_id, sizeof(t->tunnel_id));
  if (uuid_len == 0 || uuid_len == sizeof(t->tunnel_id)) {
    return -1;
  }
  if (src == 0 || dst == 0 || dport == 0) {
    return -1;
  }

  // Check for duplicate in session table
  int rv;
  u64 value;
  // Swap src and dst to match the lookup on decap
  rv = vcdp_session_static_lookup(0, dst->ip.ip4, src->ip.ip4, IP_PROTOCOL_UDP, htons(dport), 0, &value);
  if (rv == 0) {
    return -1;
  }

  // Create pool entry
  pool_get_zero(tm->tunnels, t);
  strcpy_s(t->tunnel_id, sizeof(t->tunnel_id), tunnel_id);
  t->tenant_id = tenant_id;
  t->src = *src;
  t->dst = *dst;
  t->sport = sport;
  t->dport = dport;
  t->mtu = mtu;
  t->method = method;

  hash_set(uuid_hash, tunnel_id, t - tm->tunnels);

  // Add tunnel to session table
  rv = vcdp_session_static_add(0, dst->ip.ip4, src->ip.ip4, IP_PROTOCOL_UDP, htons(dport), 0);

  if (rv != 0) {
    // error rollback
    pool_put(tm->tunnels, t);
    hash_unset(uuid_hash, tunnel_id);
  }

  t->rewrite = vcdp_vxlan_dummy_l2_build_rewrite(t);

  // Add tenant

  clib_error_t *err = vcdp_tenant_add_del(&vcdp_main, tenant_id, ~0, false);
  if (err) rv = -1;
  return rv;
}

int
vcdp_tunnel_delete(char *tunnel_id)
{
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;
  vcdp_tunnel_t *t = vcdp_tunnel_lookup_by_uuid(tunnel_id);
  if (t == 0) {
    return -1;
  }

  // Remove from session table
  vcdp_session_static_delete();

  // Remove from uuid hash
  hash_unset(uuid_hash, t->tunnel_id);

  // Remove from pool
  pool_put(tm->tunnels, t);

  return 0;
}

// enable on interface
int
vcdp_tunnel_enable_disable_input(u32 sw_if_index, bool is_enable) {
  return vnet_feature_enable_disable("ip4-unicast", "vcdp-tunnel-input",
                                     sw_if_index, is_enable, 0, 0);
}

clib_error_t *
vcdp_tunnel_init(vlib_main_t *vm)
{
  vcdp_main2.log_default = vlib_log_register_class ("vcdp", 0);
  uuid_hash = hash_create_string (0, sizeof (uword));
  clib_bihash_init_24_8(&vcdp_main2.table4, "vcdp ipv4 static session table",
                        BIHASH_IP4_NUM_BUCKETS, 0);

  return 0;
}

VLIB_INIT_FUNCTION (vcdp_tunnel_init);