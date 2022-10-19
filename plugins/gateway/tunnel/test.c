// Copyright(c) 2022 Cisco Systems, Inc.

#include <stdio.h>
#include "tunnel.h"
#include <assert.h>
#include <vcdp/service.h>
#include <arpa/inet.h>

vnet_feature_main_t feature_main;
vcdp_service_main_t vcdp_service_main;
vcdp_main_t vcdp_main;

static int
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
vlib_node_runtime_t *node;
extern vlib_node_registration_t vcdp_tunnel_input_node;

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

/* Gather output packets */
#define vlib_buffer_enqueue_to_next test_vlib_buffer_enqueue_to_next
void
test_vlib_buffer_enqueue_to_next(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u16 *nexts, uword count)
{
  vec_add(results_next, nexts, count);
  vec_add(results_bi, buffers, count);
}

#define vlib_get_buffers test_vlib_get_buffers
void
test_vlib_get_buffers(vlib_main_t *vm, u32 *bi, vlib_buffer_t **b, int count)
{
  int i;
  for (i = 0; i < count; i++) {
    b[i] = (vlib_buffer_t *) &buffers[bi[i]];
  }
}

vlib_buffer_t *
test_vlib_get_buffer(u32 bi)
{
  return (vlib_buffer_t *) &buffers[bi];
}
/* Must be included here to allow the above functions to override */
#include "node.h"

// Test tunnel-input
int
test_tunnel_input(vlib_main_t *vm)
{
  u32 node_index = vlib_register_node(vm, &vcdp_tunnel_input_node, "%s", vcdp_tunnel_input_node.name);
  node = vlib_node_get_runtime(vm, node_index);
  assert(node);

  // Configuration

  // Generate packet(s)
  fill_packets(vm, (vlib_buffer_t *) &buffers[0], 1, "tunnel-input");

  // Send packets
  vlib_frame_t frame = {.n_vectors = 1};
  node->flags |= VLIB_NODE_FLAG_TRACE;
  vcdp_tunnel_input_node_inline(vm, node, &frame);

  // Validate results
  return 0;
}
clib_error_t *
vlib_stats_init(vlib_main_t *vm);

int
main(int argc, char **argv)
{
  clib_mem_init(0, 3ULL << 30);
  vlib_main_init();
  vlib_main_t *vm = vlib_get_first_main();
  assert(vlib_node_main_init(vm) == 0);
  vlib_stats_init(vm);
  vcdp_tunnel_init(0);

  vcdp_tunnel_t *t = vcdp_tunnel_lookup_by_uuid("foobar");
  assert(t == 0 && "lookup on empty table");
  buffers_vector = buffer_init(buffers_vector, 256);
  // Create tunnel
  ip_address_t src = {.version = AF_IP4, .ip.ip4 = {{1}}};
  ip_address_t dst = {.version = AF_IP4, .ip.ip4 = {{1}}};
  int rv = vcdp_tunnel_create("tunnel1", 1, VCDP_TUNNEL_VXLAN_DUMMY_L2, &src, &dst, 0, 4278, 0);

  assert(rv == 0 && "creating tunnel");
  t = vcdp_tunnel_lookup_by_uuid("tunnel1");
  assert(t != 0 && "lookup on table");
  printf("Found a tunnel: %s\n", t->tunnel_id);

  u64 value;
  rv = vcdp_tunnel_lookup(0, src.ip.ip4, dst.ip.ip4, 17, htons(4278), 0, &value);

  assert(rv == 0 && "Lookup by session parameters");

  rv = vcdp_tunnel_create("tunnel2", 1, VCDP_TUNNEL_VXLAN_DUMMY_L2, &src, &dst, 0, 4278, 0);

  assert(rv == -1 && "creating duplicate tunnel");

  rv = vcdp_tunnel_create("tunnel2", 1, VCDP_TUNNEL_VXLAN_DUMMY_L2, &src, &dst, 0, 4279, 0);

  assert(rv == 0 && "creating tunnel 2");

  rv = vcdp_tunnel_delete("tunnel1");
  assert(rv == 0 && "delete tunnel");
  t = vcdp_tunnel_lookup_by_uuid("tunnel1");
  assert(t == 0 && "verify tunnel deleted");

  // dump session table
  clib_bihash_foreach_key_value_pair_16_8(&vcdp_tunnel_main.tunnels_hash, session_walk, 0);

  // test_tunnel_input(vm);

  return 0;
}
