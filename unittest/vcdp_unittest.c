#include <arpa/inet.h>
#include <assert.h>
#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vcdp/vcdp_funcs.h>
#include <vcdp/service.h>
#include "scapy.h"
#include <vcdp_services/nat/nat_inlines.h>
#include <vppinfra/time.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/pool.h>
#include <vcdp/vcdp.h>
#include <vcdp_services/nat/nat.h>
#include <vcdp_services/nat/nat_inlines.h>

/*
 * Test approaches
 * 1. Test a single node
 * 2.Test a chain of nodes
 */

// Send a buffer to the vcdp-input node
VLIB_NODE_FN(test_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  clib_warning("Test expected node");
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;

  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;

  while (n_left > 0) {
    ip4_header_t *ip = vcdp_get_ip4_header(b[0]);
    clib_warning("IP4 header: %U", format_ip4_header, ip, sizeof(ip4_header_t));

    // Validate the TCP checksum
    tcp_header_t *tcp = (tcp_header_t *) (ip + 1);
    clib_warning("TCP header: %U", format_tcp_header, tcp, sizeof(tcp_header_t));
    u16 checksum = tcp->checksum;
    clib_warning("TCP checksum: %x", checksum);
    u16 calculated_checksum = ip4_tcp_udp_compute_checksum(vm, b[0], ip);
    clib_warning("Calculated TCP checksum: %x", calculated_checksum);
    // assert(checksum == 0);
    b++;
    n_left--;
  }

  vlib_buffer_free(vm, from, frame->n_vectors);

  return 0;
}

VLIB_REGISTER_NODE(test_node) = {
  .name = "test-output",
  .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 0,
};

VCDP_SERVICE_DEFINE(test_output) = {.node_name = "test-output",
                                    .runs_before = VCDP_SERVICES(0),
                                    .runs_after = VCDP_SERVICES("vcdp-drop", "vcdp-l4-lifecycle", "vcdp-tcp-lite-check",
                                                                "vcdp-nat-late-rewrite", "vcdp-nat-early-rewrite"),
                                    .is_terminal = 1};

vlib_buffer_t *
build_packet(char *packetdef, u32 *bi)
{
  vlib_main_t *vm = vlib_get_main();
  assert(vlib_buffer_alloc(vm, bi, 1) == 1);
  vlib_buffer_t *b = vlib_get_buffer(vm, bi[0]);
  size_t len;
  u8 *pkt = scapy_build_packet(packetdef, &len);
  assert(pkt);
  clib_memcpy(b->data, pkt, len);
  b->current_length = len;
  b->total_length_not_including_first_buffer = 0;
  free(pkt);

  return b;
}

vlib_buffer_t *
build_packet_with_node(vlib_node_runtime_t *node, char *packetdef, u32 *bi)
{
  vlib_main_t *vm = vlib_get_main();
  vlib_buffer_t *b = build_packet(packetdef, bi);

  int rv = vlib_trace_buffer(vm, node, 0 /* next_index */, b, 0 /* follow chain */);
  assert(rv == 1);

  return b;
}

// Write a test that tests how the port allocation workd under stress.
// static void
// test_port_allocation(vlib_node_runtime_t *node, vlib_frame_t *frame, u32 sw_if_index)
// {

// }

// Test hairpinning
// How does NAT-ED bindings look like for the hairpinning case?
// Combine with port-forwarding.
// So an internal host reaching another via the port-forwarding binding.
static u32
test_hairpinning(vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 bi;
  u32 sw_if_index = 1;
  vlib_buffer_t *b = build_packet_with_node(
    node, "Ether(src='01:02:03:04:05:06',dst='06:05:04:03:02:01')/IP(dst='8.8.8.8')/TCP(sport=1000,dport=443)", &bi);
  vnet_buffer(b)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer(b)->sw_if_index[VLIB_TX] = 0;

  vlib_buffer_advance(b, 14);

  ip4_header_t *ip4 = vlib_buffer_get_current(b);
  clib_warning("IP4 header: %U", format_ip4_header, ip4, 20);
  tcp_header_t *tcp = (tcp_header_t *) (ip4 + 1);
  clib_warning("TCP header: %U", format_tcp_header, tcp, sizeof(tcp_header_t));
  u16 checksum = tcp->checksum;
  clib_warning("TCP checksum: %x", checksum);
  u16 calculated_checksum = ip4_tcp_udp_compute_checksum(vlib_get_main(), b, ip4);
  clib_warning("Calculated TCP checksum: %x", calculated_checksum);

  u32 *to_next = vlib_frame_vector_args(frame);
  to_next[0] = bi;
  frame->n_vectors = 1;
  return bi;
  // vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);
}

// void scapy_performance_test(void);

// static void
// test_scapy_performance(vlib_buffer_t *b)
// {
//   scapy_performance_test();
// }

// static void
// test_no_tenant_overflow(vlib_buffer_t *b)
// {
//   vnet_buffer(b)->sw_if_index[VLIB_RX] = 100000;
// }
// Table of pointers to test functions
typedef struct {
  u32 (*test_fn)(vlib_node_runtime_t *, vlib_frame_t *);
  u32 sw_if_index;
  char *input_node;
  u32 output_node_index;
} vcdp_test_t;

vcdp_test_t test_functions[] = {
  {.test_fn = test_hairpinning, .sw_if_index = 1, .input_node = "vcdp-input-out", .output_node_index = ~0},
  // {
  //   .test_fn = test_no_tenant_overflow,
  //   .sw_if_index = 100000,
  //   .input_node = "vcdp-input",
  //   .output_node_index = ~0
  // },
  // {
  //   .test_fn = test_scapy_performance,
  //   .sw_if_index = 0,
  //   .input_node = "vcdp-input",
  //   .output_node_index = ~0
  // }
};

static void
test_packets(u32 test_id)
{
  vlib_main_t *vm = vlib_get_main();
  vcdp_main_t *vcdp = &vcdp_main;
  int no_tests = sizeof(test_functions) / sizeof(test_functions[0]);

  for (int i = 0; i < no_tests; i++) {
    if (test_id != ~0 && test_id != i) {
      continue;
    }
    // Prepare frame
    vlib_node_t *node = vlib_get_node_by_name(vm, (u8 *) test_functions[i].input_node);
    vlib_frame_t *frame = vlib_get_frame_to_node(vm, node->index);
    vlib_node_runtime_t *node_runtime = vlib_node_get_runtime(vm, node->index);

    // Run test function
    u32 bi = test_functions[i].test_fn(node_runtime, frame);

    clib_warning("Sending buffer to node: %s", test_functions[i].input_node);
    // vlib_put_frame_to_node(vm, node->index, frame);
    u32 buffers[1] = {bi};
    u16 thread_indices[1] = {2};
    u32 n_packets = 1;
    u32 n_remote_enq =
      vlib_buffer_enqueue_to_thread(vm, node_runtime, vcdp->frame_queue_index, buffers, thread_indices, n_packets, 1);
    clib_warning("Enqueued to thread: %d %d", thread_indices[0], n_remote_enq);
    vlib_process_suspend(vm, 1.0);
  }
}

static int
create_session(u32 src, u16 sport, int *n_retries, int *n_expired)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_session_key_t k = {
    .src.ip4.as_u32 = htonl(src),
    .dst.ip4.as_u32 = htonl(0x08080808), // 8.8.8.8
    .sport = htons(sport),
    .dport = htons(443),
    .proto = 6,
    .context_id = 0,
  };
  u32 flow_index = 0;
  int rv = 0;

  // Check if the session already exists
  vcdp_session_t *session = vcdp_create_session(0, &k, 0, false, &flow_index);
  if (session) {
    // Allocate a port
    u32 thread_index = vlib_get_thread_index();

    vcdp_session_key_t secondary_key = {
      .dport = k.sport,
      .proto = k.proto,
      .src = k.dst,
      .sport = k.dport,
      .context_id = k.context_id,
    };
    secondary_key.dst.ip4.as_u32 = htonl(0x01010101); // 1.1.1.1
    u32 session_index = session - vcdp->sessions;
    u32 pseudo_flow_index = (session_index << 1) | 0x1; // Always 1, since this is always the return flow
    rv = nat_try_port_allocation(vcdp, thread_index, pseudo_flow_index, &k, &secondary_key, n_retries, n_expired);
    if (rv) {
      vcdp_session_remove(vcdp, session, thread_index, session_index);
      goto done;
    }
  } else {
    rv = -1;
  }
done:
  return rv;
}
#if 0
static void
test_checksum_neutral_port()
{
  u32 bi;
  // vlib_buffer_t *b = build_packet("Ether()/IP(src='198.19.249.25',dst='8.8.8.8')/TCP(sport=1000,dport=443)", &bi);
  vlib_buffer_t *b = build_packet("Ether(src='01:02:03:04:05:06',dst='06:05:04:03:02:01')/IP(src='123.2.3.43',dst='8.8.8.8')/TCP(sport=1000,dport=443)", &bi);
  vlib_buffer_advance(b, 14);
  ip4_header_t *ip4 = vlib_buffer_get_current(b);
  tcp_header_t *tcp = (tcp_header_t *) (ip4 + 1);
  u16 calculated_checksum = ip4_tcp_udp_compute_checksum(vlib_get_main(), b, ip4);
  if (calculated_checksum != 0) {
    clib_warning("*** Checksum is incorrect");
  }

  // u32 new_ip = htonl(0x01010101);
  u32 new_ip = htonl(0x0a000001);
  u32 old_ip = ip4->src_address.as_u32;
  ip4->src_address.as_u32 = new_ip;
  // ip4->checksum = ip4_header_checksum(ip4);
  u16 old_port = tcp->src_port;
  u16 new_port = find_checksum_neutral_port(old_ip, old_port, new_ip);
  tcp->src_port = new_port;
  clib_warning("New port: %d %d", new_port, ntohs(new_port));
  clib_warning("IP4 header: %U", format_ip4_header, ip4, 40);

  calculated_checksum = ip4_tcp_udp_compute_checksum(vlib_get_main(), b, ip4);
  clib_warning("Calculated TCP checksum: %0x", calculated_checksum);
  if (calculated_checksum != 0) {
    clib_warning("*** Checksum is incorrect");
  }
}
#endif

static void
test_runner_function()
{
  u32 src = 0xc0a80101;
  for (int i = 0; i < 10; i++) {
    int n_retries = 0, n_expired = 0;
    create_session(src + i, 1000 + i, &n_retries, &n_expired);
    clib_warning("Retries: %d, Expired: %d", n_retries, n_expired);
  }
  // case 1:
  //   test_checksum_neutral_port();
  //   break;
}

static clib_error_t *
test_vcdp_packets_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_warning("Starting tests");
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  u32 test_id = ~0;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "%d", &test_id))
      ;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }
  if (test_id == ~0) {
    err = clib_error_return(0, "missing test id");
    goto done;
  }

  test_packets(test_id);
  clib_warning("Test finished");
  return 0;

done:
  unformat_free(line_input);
  return err;
}

VLIB_CLI_COMMAND(test_vcdp_packets_command, static) = {
  .path = "test vcdp packets",
  .short_help = "vcdp packet unit test",
  .function = test_vcdp_packets_command_fn,
};

typedef struct {
  u32 total_allocations;
  u32 failed_allocations;
  u32 total_retries;
  f64 time_taken;
  u32 total_expired;
} nat_test_stats_t;

static void
nat_run_performance_test(vcdp_main_t *vcdp, int n_attempts)
{
  nat_test_stats_t stats = {0};

  vcdp_session_key_t org_key = {0};
  int n_retries = 0, n_expired = 0;

  clib_warning("Running port allocation test with %u attempts...", n_attempts);
  f64 start_time = vlib_time_now(vlib_get_main());

  for (u32 i = 0; i < n_attempts; i++) {
    // Setup test keys with random values
    org_key.src.ip4.as_u32 = random_u32(&nat_main.random_seed);
    org_key.sport = random_u32(&nat_main.random_seed) % 65535;
    // new_key.ip4.dst = random_u32(&nat_main.random_seed);
    if (create_session(org_key.src.ip4.as_u32, org_key.sport, &n_retries, &n_expired)) {
      stats.failed_allocations++;
    } else {
      stats.total_retries += n_retries;
      stats.total_allocations++;
    }
    stats.total_expired += n_expired;
  }

  stats.time_taken = vlib_time_now(vlib_get_main()) - start_time;

  f64 alloc_rate = stats.total_allocations / stats.time_taken;
  f64 failure_rate = (f64) stats.failed_allocations / n_attempts * 100;
  f64 avg_retries = (f64) stats.total_retries / stats.total_allocations;
  f64 avg_expired = (f64) stats.total_expired / n_attempts;
  clib_warning("Results:");
  clib_warning("  Total allocations: %d", stats.total_allocations);
  clib_warning("  Failed allocations: %d", stats.failed_allocations);
  clib_warning("  Total retries: %d", stats.total_retries);
  clib_warning("  Total expired: %d", stats.total_expired);
  clib_warning("  Allocation rate: %.2f allocs/sec", alloc_rate);
  clib_warning("  Success rate: %.2f%%", 100.0 - failure_rate);
  clib_warning("  Average retries per success: %.2f", avg_retries);
  clib_warning("  Average expired per allocation: %.2f", avg_expired);
}

static clib_error_t *
test_vcdp_function_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_warning("Starting tests");
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  u32 test_id = ~0, n_attempts = 100000;

  if (!unformat_user(input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(line_input, "%d", &test_id))
      ;
    else if (unformat(line_input, "attempts %d", &n_attempts))
      ;
    else {
      err = unformat_parse_error(line_input);
      goto done;
    }
  }

  switch (test_id) {
  case 0:
    nat_run_performance_test(&vcdp_main, n_attempts);
    break;
  case 1:
    test_runner_function();
    break;
  default:
    err = clib_error_return(0, "invalid test id");
    goto done;
  }
  clib_warning("Test finished");
  return 0;

done:
  unformat_free(line_input);
  return err;
}

VLIB_CLI_COMMAND(test_vcdp_function_command, static) = {
  .path = "test vcdp function",
  .short_help = "vcdp function unit test",
  .function = test_vcdp_function_command_fn,
};

clib_error_t *
vcdp_unittest_init(vlib_main_t *vm)
{
  clib_warning("VCDP Unit testing");

  vlib_node_t *input_node = vlib_get_node_by_name(vm, (u8 *) "vcdp-input");
  input_node->flags |= VLIB_NODE_FLAG_TRACE;
  input_node->flags |= VLIB_NODE_FLAG_TRACE_SUPPORTED;

  // vlib_node_t *test_node = vlib_get_node_by_name(vm, (u8 *)"test-node");
  // vlib_node_t *output_node = vlib_get_node_by_name(vm, (u8 *)"vcdp-output");
  // vlib_node_add_next_with_slot(vm, output_node->index, test_node->index, 0);
  // vlib_node_add_next_with_slot(vm, output_node->index, test_node->index, 1);
  // vlib_node_add_next_with_slot(vm, output_node->index, test_node->index, 2);
  // clib_warning("Next index: %d", next_index);
  // input_node->next_nodes[0] = test_node->index;

  assert(scapy_start() == 0);

  return 0;
}

VLIB_INIT_FUNCTION(vcdp_unittest_init) = {
  .runs_after = VLIB_INITS("vcdp_init"),
};
