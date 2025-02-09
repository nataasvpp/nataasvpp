// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <stdio.h>
#include <cbor.h>
#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>
#include "vcdp.h"
#include "service.h"
#include "timer_lru.h"

/*
 * This file contains functions to export the VCDP session database to a CBOR file.
 * Future improvement is to send request to worker threads and have the snapshot
 * generated locally by each worker.
 */

static cbor_item_t *
cbor_build_ip4(u32 addr)
{
  return cbor_build_tag(52, cbor_build_bytestring((const unsigned char *) &addr, 4));
}

static cbor_item_t *
cbor_build_ip6(ip6_address_t *addr)
{
  return cbor_build_tag(54, cbor_build_bytestring((const unsigned char *) addr, 16));
}

static cbor_item_t *
cbor_build_ip46(ip46_address_t *addr)
{
  if (ip46_address_is_ip4(addr))
    return cbor_build_ip4(addr->ip4.as_u32);
  else
    return cbor_build_ip6(&addr->ip6);
}

static cbor_item_t *
cbor_build_bitmap(u32 bitmap)
{
  vcdp_service_main_t *sm = &vcdp_service_main;
  int i;
  int n = count_set_bits(bitmap);
  cbor_item_t *b = cbor_new_definite_array(n);
  vec_foreach_index (i, sm->services) {
    if (bitmap & sm->services[i]->service_mask[0]) {
      if (!cbor_array_push(b, cbor_build_string(sm->services[i]->node_name))) {
        cbor_decref(&b);
        b = 0;
        break;
      }
    }
  }
  return b;
}
#define VCDP_CBOR_TAG_5TUPLE 32768

static cbor_item_t *
cbor_build_session_key(vcdp_session_key_t *k)
{
  cbor_item_t *cbor = cbor_new_definite_array(6);
  if (!cbor)
    return 0;
  if ((!cbor_array_push(cbor, cbor_move(cbor_build_uint32(k->context_id))) ||
       !cbor_array_push(cbor, cbor_move(cbor_build_ip46(&k->src))) ||
       !cbor_array_push(cbor, cbor_move(cbor_build_uint16(ntohs(k->sport)))) ||
       !cbor_array_push(cbor, cbor_move(cbor_build_uint8(k->proto))) ||
       !cbor_array_push(cbor, cbor_move(cbor_build_ip46(&k->dst))) ||
       !cbor_array_push(cbor, cbor_move(cbor_build_uint16(ntohs(k->dport)))))) {
    cbor_decref(&cbor);
    return 0;
  }
  return cbor_build_tag(VCDP_CBOR_TAG_5TUPLE, cbor);
}

static cbor_item_t *
cbor_build_counters(vcdp_session_t *session)
{
  cbor_item_t *counters = cbor_new_definite_array(6);

  for (int i = 0; i < VCDP_FLOW_F_B_N; i++) {
    if (!cbor_array_push(counters, cbor_move(cbor_build_uint64(session->bytes[i]))) ||
        !cbor_array_push(counters, cbor_move(cbor_build_uint32(session->pkts[i])))) {
      cbor_decref(&counters);
      counters = 0;
      break;
    }
  }
  return counters;
}

static cbor_item_t *session_states[4];
static void
init_session_states(void)
{
  session_states[VCDP_SESSION_STATE_FSOL] = cbor_build_string("FSOL");
  session_states[VCDP_SESSION_STATE_ESTABLISHED] = cbor_build_string("ESTABLISHED");
  session_states[VCDP_SESSION_STATE_TIME_WAIT] = cbor_build_string("TIME_WAIT");
  session_states[VCDP_SESSION_STATE_STATIC] = cbor_build_string("STATIC");
}

static cbor_item_t *
cbor_build_session_state(u8 state)
{
  return session_states[state];
}

// Function to encode a nat_session_t as a CBOR array and write it to a file
static cbor_item_t *
vcdp_session_to_cbor(vcdp_session_t *session)
{
  init_session_states();
  vcdp_tenant_t *tenant = vcdp_tenant_at_index(&vcdp_main, session->tenant_idx);
  cbor_item_t *s = cbor_new_definite_array(11);

  f64 remaining_time = vcdp_session_remaining_time(session, vlib_time_now(vlib_get_main()));
  if (!cbor_array_push(s, cbor_move(cbor_build_uint32(tenant->tenant_id))) ||
      !cbor_array_push(s, cbor_move(cbor_build_uint64(session->session_id))) ||
      !cbor_array_push(s, cbor_move(cbor_build_session_state(session->state))) ||
      !cbor_array_push(s, cbor_move(cbor_build_uint32(session->rx_id))) ||
      !cbor_array_push(s, cbor_move(cbor_build_session_key(&session->keys[VCDP_SESSION_KEY_PRIMARY]))) ||
      !cbor_array_push(s, cbor_move(cbor_build_session_key(&session->keys[VCDP_SESSION_KEY_SECONDARY]))) ||
      !cbor_array_push(s, cbor_build_tag(1, cbor_move(cbor_build_float8(session->created)))) ||
      !cbor_array_push(s, cbor_build_tag(1, cbor_move(cbor_build_float8(remaining_time)))) ||
      !cbor_array_push(s, cbor_move(cbor_build_bitmap(session->bitmaps[VCDP_FLOW_FORWARD]))) ||
      !cbor_array_push(s, cbor_move(cbor_build_bitmap(session->bitmaps[VCDP_FLOW_REVERSE]))) ||
      !cbor_array_push(s, cbor_move(cbor_build_counters(session)))) {
    cbor_decref(&s);
    s = 0;
  }
  return s;
}

size_t
vcdp_sessions_serialize(unsigned char **buffer, u32 *no_sessions)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_session_t *session;
  cbor_item_t *spt;
  *no_sessions = 0;

  spt = cbor_new_definite_array(pool_elts(vcdp->sessions));
  pool_foreach (session, vcdp->sessions) {
    if (!cbor_array_push(spt, vcdp_session_to_cbor(session))) {
      cbor_decref(&spt);
      return 0;
    }
  }

  // Encode the CBOR array into a byte buffer
  size_t buffer_size, length = cbor_serialize_alloc(spt, buffer, &buffer_size);
  cbor_decref(&spt);
  if (spt) {
    clib_warning("Dangling reference somwhere %d", cbor_refcount(spt));
  }
  return length;
}

int
vcdp_sessions_to_file(const char *filename)
{
  unsigned char *buffer;
  u32 no_sessions;
  size_t length = vcdp_sessions_serialize(&buffer, &no_sessions);
  if (length == 0) {
    clib_warning("Failed to serialize sessions, length %d", length);
    return -1; // Failed to serialize
  }
  // Write the CBOR byte buffer to the file
  FILE *fp = fopen(filename, "wb");
  if (fp == NULL) {
    clib_mem_free(buffer);
    return -1; // Failed to open file
  }

  size_t written = fwrite(buffer, sizeof(unsigned char), length, fp);
  fclose(fp);

  // Clean up CBOR object and buffer
  clib_mem_free(buffer);
  clib_warning("written %d bytes per session: %d", written, written / no_sessions);
  if (written == length) {
    return 0; // Success
  } else {
    return -2; // Failed to write all bytes
  }
}

static clib_error_t *
vcdp_dump_sessions_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  clib_error_t *err = 0;
  char *filename = 0;

  if (unformat_user(input, unformat_line_input, line_input)) {
    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
      if (unformat(line_input, "%s", &filename))
        ;
      else {
        err = unformat_parse_error(line_input);
        break;
      }
    }
    unformat_free(line_input);
  }
  if (err)
    return err;

  /* Ask workers to do snapshot */
  vcdp_sessions_to_file(filename);

  return err;
}

VLIB_CLI_COMMAND(dump_vcdp_session_command, static) = {
  .path = "dump vcdp session",
  .short_help = "dump vcdp session <filename>",
  .function = vcdp_dump_sessions_command_fn,
};
