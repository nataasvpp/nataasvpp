// Copyright(c) 2022 Cisco Systems, Inc.

#include <stdio.h>
#include "tunnel.h"
#include <assert.h>

extern vcdp_main2_t vcdp_main2;

static int
session_walk (clib_bihash_kv_24_8_t *kvp, void *arg)
{
    printf("Walking sessions table %lx\n", kvp->value);
    return 1;
}

// STUBS
vlib_log_class_t vlib_log_register_class (char *vlass, char *subclass) { return 0; }
void
vlib_log(vlib_log_level_t level, vlib_log_class_t class, char *fmt, ...) {
  va_list ab;
  va_start(ab, fmt);
  u8 *s = va_format(0, fmt, &ab);
  fprintf(stdout, "%s\n", s);
  vec_free(s);
  va_end(ab);
}
int
vnet_feature_enable_disable (const char *arc_name, const char *node_name,
			     u32 sw_if_index, int enable_disable,
			     void *feature_config,
			     u32 n_feature_config_bytes)
{ return 0; }

vlib_global_main_t vlib_global_main;

int
main(int argc, char **argv)
{
    clib_mem_init(0, 3ULL << 30);

    vcdp_tunnel_init(0);

    vcdp_tunnel_t *t = vcdp_tunnel_lookup("foobar");
    assert(t == 0 && "lookup on empty table");

    // Create tunnel
    ip_address_t src = { .version = AF_IP4,
                         .ip.ip4 = {{1}}};
    ip_address_t dst = { .version = AF_IP4,
                         .ip.ip4 = {{1}}};
    int rv = vcdp_tunnel_create("tunnel1", 1,
                                VCDP_TUNNEL_VXLAN_DUMMY_L2, &src, &dst, 0, 4278, 0);

    assert(rv == 0 && "creating tunnel");
    t = vcdp_tunnel_lookup("tunnel1");
    assert(t != 0 && "lookup on table");
    printf("Found a tunnel: %s\n", t->tunnel_id);

    rv = vcdp_tunnel_create("tunnel2", 1,
                                VCDP_TUNNEL_VXLAN_DUMMY_L2, &src, &dst, 0, 4278, 0);

    assert(rv == -1 && "creating duplicate tunnel");

    rv = vcdp_tunnel_create("tunnel2", 1,
                                VCDP_TUNNEL_VXLAN_DUMMY_L2, &src, &dst, 0, 4279, 0);

    assert(rv == 0 && "creating tunnel 2");


    rv = vcdp_tunnel_delete("tunnel1");
    assert(rv == 0 && "delete tunnel");
    t = vcdp_tunnel_lookup("tunnel1");
    assert(t == 0 && "verify tunnel deleted");

    // dump session table
    vcdp_main2_t *vm = &vcdp_main2;

    clib_bihash_foreach_key_value_pair_24_8(&vm->table4, session_walk, 0);
    return 0;
}
