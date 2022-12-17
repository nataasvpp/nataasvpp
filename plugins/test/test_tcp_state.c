/* Copyright(c) 2022 Cisco Systems, Inc. */

#include <stdio.h>
#include "gateway/tunnel/tunnel.h"
#include <assert.h>
#include <vcdp/service.h>
#include <arpa/inet.h>

// #include <vppinfra/bihash_16_8.h>
// #include <vppinfra/bihash_template.c>

// #include "test_stubs.h"

/*
 * Create a session. Verifiy initial state
 * Send a client -> server packet. Verify state
 * Send a server -> client packet. Verify state
 * Verify session close state machine.
 *
 * Try init session with traditional 3-way handshake and with midstream start.
 * Verify TCP reset
 * Verify last ACK
 */

struct buffers {
  u8 data[2048];
};
static struct buffers buffers[256];
// static struct buffers expected[256];

static u32 *buffers_vector = 0;
static u16 *results_next = 0;
static u32 *results_bi = 0; /* global vector of result buffers */

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
#include <vcdp_services/tcp-check-lite/node.h>

int
vcdp_create_session_v4(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_tenant_t *tenant, u16 tenant_idx,
                       u32 thread_index, f64 time_now, vcdp_session_ip4_key_t *k, u32 rx_id, u64 *lookup_val);

extern vlib_node_registration_t vcdp_tcp_check_lite_node;

clib_error_t *vcdp_tcp_check_lite_init(vlib_main_t *vm);
void
init (void)
{
  vlib_main_t *vm = vlib_get_main();
  assert(vm);

  clib_error_t *err = vcdp_tcp_check_lite_init(vm);
  assert(err == 0);

  buffers_vector = buffer_init(buffers_vector, 1);
}
int
test_tcp_state(void)
{
  init();
  vcdp_main_t *vcdp = &vcdp_main;
  vlib_main_t *vm = vlib_get_main();
  u32 thread_index = 0;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  u16 tenant_idx = 0;
  f64 now = vlib_time_now(vm);

  /* Create tenant */
  clib_error_t *err = vcdp_tenant_add_del(vcdp, 0, 0, 0, 1);
  assert(err == 0);

  vcdp_tenant_t *tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
  f64 time_now = vlib_time_now(vm);
  u64 lookup_val;
  u32 rx_id = 0;
  
  /* Create session(s) */
  vcdp_session_ip4_key_t k = {.src = 0x01020304, .dst = 0x04030201, .proto = 6, .dport = 80, .sport = 12345};
  int rv = vcdp_create_session_v4(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, &k, rx_id, &lookup_val);
  assert(rv == 0);
  clib_warning("Created session %U", format_vcdp_session_key, &k);
  clib_warning("Created session %U", format_vcdp_session_detail, ptd, 0, now);
  printf("Created a session: %d\n", rv);

  /* Send packet through matching session */
  vlib_buffer_t *b = (vlib_buffer_t *)&buffers[0];

  ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current(b);
  tcp_header_t *tcp = ip4_next_header(ip);
  vcdp_buffer(b)->service_bitmap = 0x1;
  b->flow_id = 0;

  tcp->flags = 0x1;
  /* send packets through graph node */
  vlib_node_runtime_t *node;
  u32 node_index = vlib_register_node(vm, &vcdp_tcp_check_lite_node, "%s", vcdp_tcp_check_lite_node.name);
  node = vlib_node_get_runtime(vm, node_index);
  assert(node);

  vlib_frame_t frame = {.n_vectors = 1};
  node->flags |= VLIB_NODE_FLAG_TRACE;

  vcdp_tcp_check_lite_node_inline(vm, node, &frame);



  return 0;
}
