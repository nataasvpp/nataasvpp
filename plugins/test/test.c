/* Copyright(c) 2022 Cisco Systems, Inc. */

#include <stdio.h>
#include "gateway/tunnel/tunnel.h"
#include <assert.h>
#include <vcdp/service.h>
#include <arpa/inet.h>

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.c>

#include "test_stubs.h"

#define log_info(M, ...) fprintf(stderr, "\033[32;1m[OK] " M "\033[0m\n", ##__VA_ARGS__)
#define log_error(M, ...)                                                                                              \
  fprintf(stderr, "\033[31;1m[ERROR] (%s:%d:) " M "\033[0m\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define test_assert_log(A, M, ...)                                                                                     \
  if (!(A)) {                                                                                                          \
    log_error(M, ##__VA_ARGS__);                                                                                       \
    assert(A);                                                                                                         \
  } else {                                                                                                             \
    log_info(M, ##__VA_ARGS__);                                                                                        \
  }
#define test_assert(A, M, ...)                                                                                         \
  if (!(A)) {                                                                                                          \
    log_error(M, ##__VA_ARGS__);                                                                                       \
    assert(A);                                                                                                         \
  }

vnet_feature_main_t feature_main;
vcdp_service_main_t vcdp_service_main;
vcdp_main_t vcdp_main;

int
session_walk(clib_bihash_kv_16_8_t *kvp, void *arg)
{
  printf("Walking sessions table %lx\n", kvp->value);
  return 1;
}

/* Synthetic value for vnet_feature_next  */
u16 NEXT_PASSTHROUGH = 4242;

u32 *results_bi = 0; /* global vector of result buffers */
u16 *results_next = 0;

static int
fill_packets(vlib_main_t *vm, vlib_buffer_t *b, int n, char *test)
{
  b->flags |= VLIB_BUFFER_IS_TRACED;

  ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current(b);

  memcpy(ip, test, n);

  /* Do the work of SVR */
  vnet_buffer(b)->ip.reass.l4_src_port = 0;
  vnet_buffer(b)->ip.reass.l4_dst_port = 0;
  b->current_length = n;

  if (ip4_is_fragment(ip))
    return 0;
  if (ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = ip4_next_header(ip);
    vnet_buffer(b)->ip.reass.l4_src_port = udp->src_port;
    vnet_buffer(b)->ip.reass.l4_dst_port = udp->dst_port;
  } else if (ip->protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = ip4_next_header(ip);
    vnet_buffer(b)->ip.reass.l4_src_port = tcp->src_port;
    vnet_buffer(b)->ip.reass.l4_dst_port = tcp->dst_port;
  }
  return 0;
}

struct buffers {
  u8 data[2048];
};
struct buffers buffers[256];
struct buffers expected[256];
u32 *buffers_vector = 0;

/*
 * Register nodes
 */
vlib_node_runtime_t *node;
extern vlib_node_registration_t vcdp_tunnel_input_node;
extern vlib_node_registration_t vcdp_handoff_node;
extern vlib_node_registration_t vcdp_timer_expire_node;

int
vcdp_tunnel_input_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame);
static u32 *
buffer_init(u32 *vector, int count)
{
  int i;
  for (i = 0; i < count; i++) {
    vec_add1(vector, i);
  }
  return vector;
}
#include "test_node_macros.h"

typedef struct {
  char *name;
  int nsend;
  char *send;
  int nexpect;
  char *expect;
  u32 expect_next_index;
} test_t;
#include "test_packets.h"

vcdp_tunnel_trace_t trace = {0};
#define vlib_add_trace test_vlib_add_trace
void *test_vlib_add_trace(vlib_main_t *vm, vlib_node_runtime_t *r,
                          vlib_buffer_t *b, u32 n_data_bytes) {
    return &trace;
}

/* Must be included here to allow the above functions to override */
#include "gateway/tunnel/node.h"


void
validate_packet(vlib_main_t *vm, char *name, u32 bi, vlib_buffer_t *expected_b)
{
  vlib_buffer_t *b = test_vlib_get_buffer(bi);
  assert(b);

  ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current(b);
  ip4_header_t *expected_ip = (ip4_header_t *) vlib_buffer_get_current(expected_b);

#if 0
    if (ip->protocol == IP_PROTOCOL_UDP || ip->protocol == IP_PROTOCOL_TCP) {
        u32 flags = ip4_tcp_udp_validate_checksum(vm, b);
        test_assert((flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0, "%s",
                    name);
        flags = ip4_tcp_udp_validate_checksum(vm, expected_b);
        test_assert((flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0, "%s",
                    name);
    }
#endif
  test_assert(b->current_length == expected_b->current_length, "%s %d vs %d", name, b->current_length,
              expected_b->current_length);

  if (memcmp(ip, expected_ip, b->current_length) != 0) {
    if (ip->protocol == IP_PROTOCOL_UDP) {
      udp_header_t *udp = ip4_next_header(ip);
      clib_warning("Received: IP: %U UDP: %U", format_ip4_header, ip, sizeof(*ip), format_udp_header, udp,
                   sizeof(*udp));
      udp = ip4_next_header(expected_ip);
      clib_warning("%U", format_hexdump, ip, b->current_length);
      clib_warning("Expected: IP: %U UDP: %U", format_ip4_header, expected_ip, sizeof(*ip), format_udp_header, udp,
                   sizeof(*udp));
      clib_warning("%U", format_hexdump, expected_ip, expected_b->current_length);
    } else if (ip->protocol == IP_PROTOCOL_TCP) {
      tcp_header_t *tcp = ip4_next_header(ip);
      clib_warning("Received IP: %U TCP: %U", format_ip4_header, ip, sizeof(*ip), format_tcp_header, tcp, sizeof(*tcp));
      tcp = ip4_next_header(expected_ip);
      clib_warning("Expected IP: %U TCP: %U", format_ip4_header, expected_ip, sizeof(*ip), format_tcp_header, tcp,
                   sizeof(*tcp));
    } else {
      clib_warning("Received: IP: %U", format_ip4_header, ip, sizeof(*ip));
      clib_warning("Expected: IP: %U", format_ip4_header, expected_ip, sizeof(*ip));
    }
    test_assert_log(0, "%s", name);
  } else {
    test_assert_log(1, "%s", name);
  }
}

static void
test_table(test_t *t, int no_tests)
{
  // walk through table of tests
  int i;
  vlib_main_init();
  vlib_main_t *vm = vlib_get_first_main();
  u32 node_index = vlib_register_node(vm, &vcdp_tunnel_input_node, "%s", vcdp_tunnel_input_node.name);
  node = vlib_node_get_runtime(vm, node_index);
  assert(node);
  /* Generate packet data */
  for (i = 0; i < no_tests; i++) {
    // create input buffer(s)
    fill_packets(vm, (vlib_buffer_t *) &buffers[i], t[i].nsend, t[i].send);
    fill_packets(vm, (vlib_buffer_t *) &expected[i], t[i].nexpect, t[i].expect);
  }

  /* send packets through graph node */
  vlib_frame_t frame = {.n_vectors = no_tests};
  node->flags |= VLIB_NODE_FLAG_TRACE;

  vcdp_tunnel_input_node_inline(vm, node, &frame);

  /* verify tests */
  for (i = 0; i < no_tests; i++) {
    test_assert(t[i].expect_next_index == results_next[i], "%s", t[i].name);
    //validate_packet(vm, t[i].name, results_bi[i], (vlib_buffer_t *) &expected[i]);
  }
  vec_free(results_next);
  vec_free(results_bi);
}

void
test_packets(void)
{
#if 0
    pnat_main_t *pm = &pnat_main;
    int i;
    for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        add_translation(&rules[i]);
    }
    assert(pool_elts(pm->translations) == sizeof(rules) / sizeof(rules[0]));
#endif
  test_table(tests_packets, sizeof(tests_packets) / sizeof(tests_packets[0]));
#if 0
    for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
        del_translation(&rules[i]);
    }
    assert(pool_elts(pm->translations) == 0);
    assert(pool_elts(pm->interfaces) == 0);
#endif
}

clib_error_t *vlib_stats_init(vlib_main_t *vm);
clib_error_t *vcdp_init(vlib_main_t *vm);

ip_csum_t (*vnet_incremental_checksum_fp) (ip_csum_t, void *, uword);

void checksum_init(void) {
  vnet_incremental_checksum_fp = 0;
}

/*
 * Init VPP infrastructure
 */
static void init(void)
{
  clib_mem_init(0, 3ULL << 30);
  vlib_main_init(); 
  vlib_main_t *vm = vlib_get_first_main();
  assert(vlib_node_main_init(vm) == 0);
  vlib_thread_main_t *tm = &vlib_thread_main;
  tm->n_vlib_mains = 1;
  clib_error_t *err = vlib_stats_init(vm);
  if (err) {
    exit(-1);
  }

  /* Initialise hand-off node */
  u32 node_index = vlib_register_node(vm, &vcdp_handoff_node, "%s", vcdp_handoff_node.name);
  node = vlib_node_get_runtime(vm, node_index);
  assert(node);

  node_index = vlib_register_node(vm, &vcdp_timer_expire_node, "%s", vcdp_timer_expire_node.name);
  node = vlib_node_get_runtime(vm, node_index);
  assert(node);

  /* Set VCDP default data structure sizes */
  vcdp_cfg_main.no_nat_instances = 1 << 10; // 1024
  vcdp_cfg_main.no_sessions_per_thread = 1 << 20; // 1M
  vcdp_cfg_main.no_tenants = 1 << 10; // 1024
  vcdp_cfg_main.no_tunnels = 1 << 20; // 1M;
  vcdp_cfg_main.no_tunnels = 1000;
  vcdp_init(vm);

  vcdp_tunnel_init(0);

}

int test_tcp_state(void);
int
main(int argc, char **argv)
{
  init();

  vcdp_tunnel_t *t = vcdp_tunnel_lookup_by_uuid("foobar");
  assert(t == 0 && "lookup on empty table");
  buffers_vector = buffer_init(buffers_vector, 256);
  // Create tunnel
  ip_address_t src = {.version = AF_IP4, .ip.ip4 = {{1}}};
  ip_address_t dst = {.version = AF_IP4, .ip.ip4 = {{1}}};
  int rv = vcdp_tunnel_add("tunnel1", 1, VCDP_TUNNEL_VXLAN_DUMMY_L2, &src, &dst, 0, 4278, 0, 0, 0);

  assert(rv == 0 && "creating tunnel");
  t = vcdp_tunnel_lookup_by_uuid("tunnel1");
  assert(t != 0 && "lookup on table");
  printf("Found a tunnel: %s\n", t->tunnel_id);

  u64 value;
  rv = vcdp_tunnel_lookup(0, src.ip.ip4, dst.ip.ip4, 17, 0, htons(4278), &value);

  assert(rv == 0 && "Lookup by session parameters");

  rv = vcdp_tunnel_add("tunnel2", 1, VCDP_TUNNEL_VXLAN_DUMMY_L2, &src, &dst, 0, 4278, 0, 0, 0);
  assert(rv == -6 && "creating duplicate tunnel");

  rv = vcdp_tunnel_add("tunnel2", 1, VCDP_TUNNEL_VXLAN_DUMMY_L2, &src, &dst, 0, 4279, 0, 0, 0);

  assert(rv == 0 && "creating tunnel 2");

  rv = vcdp_tunnel_remove("tunnel1");
  assert(rv == 0 && "delete tunnel");
  t = vcdp_tunnel_lookup_by_uuid("tunnel1");
  assert(t == 0 && "verify tunnel deleted");

  // dump session table
  clib_bihash_foreach_key_value_pair_16_8(&vcdp_tunnel_main.tunnels_hash, session_walk, 0);

  // test_tunnel_input(vm);

  test_packets();


  test_tcp_state();

  _Exit(0);

}
