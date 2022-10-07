// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_tunnel_h
#define included_vcdp_tunnel_h 1

#include <vlib/vlib.h>
#include <vnet/ip/ip_types.h>
#include <tunnel/tunnel.api_types.h>
#include <vppinfra/hash.h>
#include <vcdp/vcdp.h>

#include <vppinfra/bihash_24_8.h>


// typedef enum {
//     VCDP_TUNNEL_VXLAN_DUMMY_L2,
//     VCDP_TUNNEL_GENEVE_L3,
// } vcdp_tunnel_method_t;
typedef vl_api_vcdp_tunnel_method_t vcdp_tunnel_method_t;

typedef struct {
    char tunnel_id[36];
    u32 tenant_id;
    vcdp_tunnel_method_t method;
    ip_address_t src; // duplicate with session?
    ip_address_t dst;
    u16 sport;
    u16 dport;
    u16 mtu;
} vcdp_tunnel_t;

typedef struct {
  u16 msg_id_base;        // api message index base
  vcdp_tunnel_t *tunnels;  // pool of tunnels
} vcdp_tunnel_main_t;

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cache0);
  vcdp_session_ip4_key_t key;
  // service chain bitmap
  u32 bitmaps[VCDP_FLOW_F_B_N];
  // array of index to services using this session (subblock)
  u32 services[1];
  u16 tenant_idx;
  u64 session_id;
} vcdp_session2_t;

typedef struct {
  vlib_log_class_t log_default;
  vcdp_session2_t *sessions;
  clib_bihash_24_8_t table4;
} vcdp_main2_t;

#define vcdp_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, vcdp_main2.log_default, __VA_ARGS__)
#define vcdp_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, vcdp_main2.log_default, __VA_ARGS__)
#define vcdp_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, vcdp_main2.log_default, __VA_ARGS__)
#define vcdp_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, vcdp_main2.log_default, __VA_ARGS__)



extern vcdp_main2_t vcdp_main2;
extern vcdp_tunnel_main_t vcdp_tunnel_main;

clib_error_t *vcdp_tunnel_init(vlib_main_t *vm);
vcdp_tunnel_t *vcdp_tunnel_lookup(char *);
int vcdp_tunnel_create(char *tunnel_id, u32 tenant, vcdp_tunnel_method_t method,
                   ip_address_t *src, ip_address_t *dst, u16 sport, u16 dport,
                   u16 mtu);
int vcdp_session_static_lookup(u32 context_id, ip4_address_t src, ip4_address_t dst,
                           u8 proto, u16 sport, u16 dport, u64 *value);
int vcdp_tunnel_delete(char *tunnel_id);
int vcdp_tunnel_enable_disable_input(u32 sw_if_index, bool is_enable);

#endif