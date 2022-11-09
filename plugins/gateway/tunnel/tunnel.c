// Copyright(c) 2022 Cisco Systems, Inc.

// Interface-less tunnels.

#include "tunnel.h"
#include <vnet/adj/adj_nbr.h>
#include <vnet/vxlan/vxlan_packet.h>
#include <vpp_plugins/geneve/geneve_packet.h>

vcdp_tunnel_main_t vcdp_tunnel_main;
uword *uuid_hash;

// Unidirectional session. Only accepting flows in forward direction
// Adds session state to all threads.
void
make_static_key_v4(u32 context_id, ip4_address_t src, ip4_address_t dst, u8 proto, u16 sport, u16 dport,
                   vcdp_tunnel_key_t *k)
{
  k->context_id = context_id;
  k->src = src;
  k->dst = dst;
  k->sport = sport;
  k->dport = dport;
  k->proto = proto;
}

// Create a new session.
// The fields must be in big-endian.
int
vcdp_tunnel_add(u32 context_id, ip4_address_t src, ip4_address_t dst, u8 proto, u16 sport, u16 dport, u32 value)
{
  vcdp_tunnel_key_t key = {0};
  clib_bihash_kv_16_8_t kv = {};

  make_static_key_v4(context_id, src, dst, proto, sport, dport, &key);

  clib_memcpy_fast(&kv.key, &key, sizeof(kv.key));
  kv.value = value;

  // proto = ((vcdp_session_ip4_key_t *) k)->ip4_key.proto;
  if (clib_bihash_add_del_16_8(&vcdp_tunnel_main.tunnels_hash, &kv, 2)) {
    vcdp_log_err("failed add to bihash %U", format_bihash_kvp_16_8, &kv);
    return -1;
  }

  return 0;
}

// returns 0 on success (found), < 0 on error (not found)
int
vcdp_tunnel_lookup(u32 context_id, ip4_address_t src, ip4_address_t dst, u8 proto, u16 sport, u16 dport, u64 *value)
{
  vcdp_tunnel_key_t key = {0};
  clib_bihash_kv_16_8_t kv, v;
  make_static_key_v4(context_id, src, dst, proto, sport, dport, &key);

  clib_memcpy(&kv.key, &key, sizeof(kv.key));

  if (!clib_bihash_search_16_8(&vcdp_tunnel_main.tunnels_hash, &kv, &v)) {
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
vcdp_tunnel_lookup_by_uuid(char *uuid)
{
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;

  uword *p = hash_get(uuid_hash, uuid);
  if (p == 0) {
    return 0;
  }
  return pool_elt_at_index(tm->tunnels, p[0]);
}

vcdp_tunnel_t *
vcdp_tunnel_get(u32 index)
{
  return pool_elt_at_index(vcdp_tunnel_main.tunnels, index);
}

static u8 *
vcdp_tunnel_vxlan_dummy_l2_build_rewrite(vcdp_tunnel_t *t, u16 *encap_len)
{
  u8 *rewrite = 0;

  *encap_len = sizeof(ip4_header_t) + sizeof(udp_header_t) + sizeof(vxlan_header_t) + sizeof(ethernet_header_t);
  vec_validate(rewrite, *encap_len - 1);
  ip4_header_t *ip = (ip4_header_t *) rewrite;
  udp_header_t *udp = (udp_header_t *) (ip + 1);
  vxlan_header_t *vxlan = (vxlan_header_t *) (udp + 1);
  ethernet_header_t *ethernet = (ethernet_header_t *) (vxlan + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;

  /* fixup ip4/udp header length and checksum after-the-fact */
  ip->src_address.as_u32 = t->src.ip.ip4.as_u32;
  ip->dst_address.as_u32 = t->dst.ip.ip4.as_u32;
  ip->checksum = 0;

  udp->checksum = 0;
  udp->src_port = clib_host_to_net_u16(t->sport);
  udp->dst_port = clib_host_to_net_u16(t->dport);
  udp->length = 0;

  vnet_set_vni_and_flags(vxlan, t->tenant_id);
  ethernet->type = clib_host_to_net_u16(ETHERNET_TYPE_IP4);
  clib_memcpy(&ethernet->src_address, &t->src_mac.bytes, sizeof(ethernet->src_address));
  clib_memcpy(&ethernet->dst_address, &t->dst_mac.bytes, sizeof(ethernet->dst_address));

  return (rewrite);
}

static u8 *
vcdp_tunnel_geneve_l3_build_rewrite(vcdp_tunnel_t *t, u16 *encap_len)
{
  ASSERT(0); // Not implemented yet.
  return 0;
}

int
vcdp_tunnel_create(char *tunnel_id, u32 tenant_id, vcdp_tunnel_method_t method, ip_address_t *src, ip_address_t *dst,
                   u16 sport, u16 dport, u16 mtu, mac_address_t *src_mac, mac_address_t *dst_mac)
{
  vcdp_tunnel_main_t *tm = &vcdp_tunnel_main;
  vcdp_tunnel_t *t = vcdp_tunnel_lookup_by_uuid(tunnel_id);

  if (t) {
    return -1;
  }

  // check input
  if (!tunnel_id) {
    return -1;
  }

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
  rv = vcdp_tunnel_lookup(0, src->ip.ip4, dst->ip.ip4, IP_PROTOCOL_UDP, clib_host_to_net_u16(sport), clib_host_to_net_u16(dport), &value);
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
  clib_memcpy(&t->src_mac, src_mac, sizeof(t->src_mac));
  clib_memcpy(&t->dst_mac, dst_mac, sizeof(t->dst_mac));
  hash_set(uuid_hash, tunnel_id, t - tm->tunnels);

  // Add tunnel to session table
  rv = vcdp_tunnel_add(0, src->ip.ip4, dst->ip.ip4, IP_PROTOCOL_UDP, clib_host_to_net_u16(sport), clib_host_to_net_u16(dport), t - tm->tunnels);
  if (rv != 0) {
    // error rollback
    pool_put(tm->tunnels, t);
    hash_unset(uuid_hash, tunnel_id);
  }

  switch (method) {
  case VCDP_TUNNEL_VXLAN_DUMMY_L2:
    t->rewrite = vcdp_tunnel_vxlan_dummy_l2_build_rewrite(t, &t->encap_size);
    break;
  case VCDP_TUNNEL_GENEVE_L3:
    t->rewrite = vcdp_tunnel_geneve_l3_build_rewrite(t, &t->encap_size);
    break;
  default:
    ASSERT(0);
  }

  // Add tenant if needed
  // clib_error_t *err = vcdp_tenant_add_del(&vcdp_main, tenant_id, ~0, false);
  // if (err) rv = -1;
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
vcdp_tunnel_enable_disable_input(u32 sw_if_index, bool is_enable)
{
  return vnet_feature_enable_disable("ip4-unicast", "vcdp-tunnel-input", sw_if_index, is_enable, 0, 0);
}

clib_error_t *
vcdp_tunnel_init(vlib_main_t *vm)
{
  vcdp_tunnel_main.log_default = vlib_log_register_class("vcdp", 0);
  uuid_hash = hash_create_string(0, sizeof(uword));
  clib_bihash_init_16_8(&vcdp_tunnel_main.tunnels_hash, "vcdp ipv4 static session table", VCDP_TUNNELS_NUM_BUCKETS, 0);

  return 0;
}

VLIB_INIT_FUNCTION(vcdp_tunnel_init);