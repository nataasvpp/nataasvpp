// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_tunnel_h
#define included_vcdp_tunnel_h

#include <vlib/vlib.h>
#include <vnet/ip/ip_types.h>
#include <gateway/gateway.api_types.h>
#include <vppinfra/hash.h>
#include <vcdp/vcdp.h>

#include <vppinfra/bihash_16_8.h>

#define VCDP_TUNNELS_NUM_BUCKETS 1024

// typedef enum {
//     VCDP_TUNNEL_VXLAN_DUMMY_L2,
//     VCDP_TUNNEL_GENEVE_L3,
// } vcdp_tunnel_method_t;
typedef vl_api_vcdp_tunnel_method_t vcdp_tunnel_method_t; // From .api file

typedef struct {
  char tunnel_id[36];
  u32 tenant_id;
  vcdp_tunnel_method_t method;
  ip_address_t src;
  ip_address_t dst;
  u16 sport;
  u16 dport;
  u16 mtu;
  u8 *rewrite;
  u16 encap_size;
} vcdp_tunnel_t;

typedef struct {
  vcdp_tunnel_t *tunnels; // pool of tunnels
  vlib_log_class_t log_default;
  clib_bihash_16_8_t tunnels_hash;
} vcdp_tunnel_main_t;

typedef struct {
  ip4_address_t src, dst;
  u16 sport;
  u16 dport;
  u32 context_id : 24;
  u8 proto;
} __clib_packed vcdp_tunnel_key_t;
STATIC_ASSERT_SIZEOF(vcdp_tunnel_key_t, 16);

#define vcdp_log_err(...)    vlib_log(VLIB_LOG_LEVEL_ERR, vcdp_tunnel_main.log_default, __VA_ARGS__)
#define vcdp_log_warn(...)   vlib_log(VLIB_LOG_LEVEL_WARNING, vcdp_tunnel_main.log_default, __VA_ARGS__)
#define vcdp_log_notice(...) vlib_log(VLIB_LOG_LEVEL_NOTICE, vcdp_tunnel_main.log_default, __VA_ARGS__)
#define vcdp_log_info(...)   vlib_log(VLIB_LOG_LEVEL_INFO, vcdp_tunnel_main.log_default, __VA_ARGS__)

extern vcdp_tunnel_main_t vcdp_tunnel_main;

clib_error_t *
vcdp_tunnel_init(vlib_main_t *vm);
vcdp_tunnel_t *
vcdp_tunnel_lookup_by_uuid(char *);
int
vcdp_tunnel_create(char *tunnel_id, u32 tenant, vcdp_tunnel_method_t method, ip_address_t *src, ip_address_t *dst,
                   u16 sport, u16 dport, u16 mtu);
int
vcdp_tunnel_lookup(u32 context_id, ip4_address_t src, ip4_address_t dst, u8 proto, u16 sport, u16 dport, u64 *value);
int
vcdp_tunnel_delete(char *tunnel_id);
int
vcdp_tunnel_enable_disable_input(u32 sw_if_index, bool is_enable);
vcdp_tunnel_t *
vcdp_tunnel_get(u32 index);

#endif