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

/*
 * This file contains functions to export the VCDP session database to a CBOR file.
 * Future improvement is to send request to worker threads and have the snapshot
 * generated locally by each worker.
*/

static cbor_item_t *
cbor_build_ip4(u32 addr)
{
  return cbor_build_tag(52, cbor_build_bytestring((const unsigned char *)&addr, 4));
}

static cbor_item_t *
cbor_build_ip6(ip6_address_t *addr)
{
  return cbor_build_tag(54, cbor_build_bytestring((const unsigned char *)addr, 16));
}

static cbor_item_t *
cbor_build_bitmap(u32 bitmap)
{
  vcdp_service_main_t *sm = &vcdp_service_main;
  int i;
  int n = count_set_bits(bitmap);
  cbor_item_t *b = cbor_new_definite_array(n);
  vec_foreach_index(i, sm->services) {
    if (bitmap & sm->services[i]->service_mask[0]) {
      cbor_array_push(b, cbor_build_string(sm->services[i]->node_name));
    }
  }
  return b;
}

static cbor_item_t *
cbor_build_session_key(vcdp_session_key_flag_t flag, vcdp_session_key_t *key)
{
  if (flag & VCDP_SESSION_KEY_IP4) {
    vcdp_session_ip4_key_t *k = &key->ip4;
    cbor_item_t *cbor = cbor_new_definite_array(6);
    cbor_array_push(cbor, cbor_move(cbor_build_uint32(k->context_id)));
    cbor_array_push(cbor, cbor_move(cbor_build_ip4(k->src)));
    cbor_array_push(cbor, cbor_move(cbor_build_uint16(ntohs(k->sport))));
    cbor_array_push(cbor, cbor_move(cbor_build_uint8(k->proto)));
    cbor_array_push(cbor, cbor_move(cbor_build_ip4(k->dst)));
    cbor_array_push(cbor, cbor_move(cbor_build_uint16(ntohs(k->dport))));
    return cbor;
  }
  if (flag & VCDP_SESSION_KEY_IP6) {
    vcdp_session_ip6_key_t *k = &key->ip6;
    cbor_item_t *cbor = cbor_new_definite_array(6);
    cbor_array_push(cbor, cbor_move(cbor_build_uint32(k->context_id)));
    cbor_array_push(cbor, cbor_move(cbor_build_ip6(&k->src)));
    cbor_array_push(cbor, cbor_move(cbor_build_uint16(ntohs(k->sport))));
    cbor_array_push(cbor, cbor_move(cbor_build_uint8(k->proto)));
    cbor_array_push(cbor, cbor_move(cbor_build_ip6(&k->dst)));
    cbor_array_push(cbor, cbor_move(cbor_build_uint16(ntohs(k->dport))));
    return cbor;
  }
  return 0;
}

static cbor_item_t *
cbor_build_counters(vcdp_session_t *session)
{
  cbor_item_t *counters = cbor_new_definite_array(6);

  for (int i=0; i < VCDP_FLOW_F_B_N; i++) {
    cbor_array_push(counters, cbor_move(cbor_build_uint64(session->bytes[i])));
    cbor_array_push(counters, cbor_move(cbor_build_uint32(session->pkts[i])));
  }
  return counters;
}

static cbor_item_t *session_states[4];
static void
init_session_states(void) {
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

  f64 remaining_time = session->timer.next_expiration - vlib_time_now(vlib_get_main());

  cbor_array_push(s, cbor_move(cbor_build_uint32(tenant->tenant_id)));
  cbor_array_push(s, cbor_move(cbor_build_uint64(session->session_id)));
  cbor_array_push(s, cbor_move(cbor_build_session_state(session->state)));
  cbor_array_push(s, cbor_move(cbor_build_uint32(session->rx_id)));
  cbor_array_push(s, cbor_move(cbor_build_session_key(session->key_flags, &session->keys[VCDP_SESSION_KEY_PRIMARY])));
  cbor_array_push(s, cbor_move(cbor_build_session_key(session->key_flags, &session->keys[VCDP_SESSION_KEY_SECONDARY])));
  cbor_array_push(s, cbor_build_tag(1, cbor_move(cbor_build_float8(session->created))));
  cbor_array_push(s, cbor_build_tag(1, cbor_move(cbor_build_float8(remaining_time))));
  cbor_array_push(s, cbor_move(cbor_build_bitmap(session->bitmaps[VCDP_FLOW_FORWARD])));
  cbor_array_push(s, cbor_move(cbor_build_bitmap(session->bitmaps[VCDP_FLOW_REVERSE])));
  cbor_array_push(s, cbor_move(cbor_build_counters(session)));
  return s;
}

int
vcdp_sessions_to_file(const char *filename)
{
  vcdp_main_t *vcdp = &vcdp_main;
  vcdp_per_thread_data_t *ptd;
  vcdp_session_t *session;
  vcdp_tenant_t *tenant;
  u32 thread_index = ~0;
  u32 tenant_id = ~0;
  cbor_item_t *spt;
  cbor_item_t *root = cbor_new_definite_map(vec_len(vcdp->per_thread_data));

  int no_sessions = 0;
  vec_foreach_index (thread_index, vcdp->per_thread_data) {
    ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
    clib_warning("thread_index %d session elements: %d", thread_index, pool_elts(ptd->sessions));
    no_sessions += pool_elts(ptd->sessions);
    spt = cbor_new_definite_array(pool_elts(ptd->sessions));

    pool_foreach (session, ptd->sessions) {
      tenant = vcdp_tenant_at_index(vcdp, session->tenant_idx);
      if (tenant_id != ~0 && tenant_id != tenant->tenant_id)
        continue;
      cbor_array_push(spt, vcdp_session_to_cbor(session));

    }
    struct cbor_pair pair;
    pair.key = cbor_move(cbor_build_uint32(thread_index));
    pair.value = cbor_move(spt);
    cbor_map_add(root, pair);
  }

      // Encode the CBOR array into a byte buffer
    unsigned char *buffer;
    size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);

    // Write the CBOR byte buffer to the file
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        cbor_decref(&root);
        free(buffer);
        return -1; // Failed to open file
    }

    size_t written = fwrite(buffer, sizeof(unsigned char), length, fp);
    fclose(fp);

    // Clean up CBOR object and buffer
    cbor_decref(&root);
    if (root) {
      clib_warning("Dangling reference somwhere %d", cbor_refcount(root));
    }
    free(buffer);
    clib_warning("written %d bytes per session: %d", written, written/no_sessions);
    if (written == length) {
        return 0; // Success
    } else {
        return -2; // Failed to write all bytes
    }
    return 0;
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
