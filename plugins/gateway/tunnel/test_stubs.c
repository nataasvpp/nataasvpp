// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>

extern u16 NEXT_PASSTHROUGH;

// STUBS
vlib_log_class_t
vlib_log_register_class(char *vlass, char *subclass)
{
  return 0;
}
void
vlib_log(vlib_log_level_t level, vlib_log_class_t class, char *fmt, ...)
{
  va_list ab;
  va_start(ab, fmt);
  u8 *s = va_format(0, fmt, &ab);
  fprintf(stdout, "%s\n", s);
  vec_free(s);
  va_end(ab);
}
int
vnet_feature_enable_disable(const char *arc_name, const char *node_name, u32 sw_if_index, int enable_disable,
                            void *feature_config, u32 n_feature_config_bytes)
{
  return 0;
}
#include <vnet/feature/feature.h>
#define vnet_feature_next_u16 test_vnet_feature_next_u16
void
vnet_feature_next_u16(u16 *next0, vlib_buffer_t *b0)
{
  *next0 = NEXT_PASSTHROUGH;
}
void
classify_get_trace_chain(void){};
vlib_global_main_t vlib_global_main;
void
os_exit(int code)
{
}

/* Format an IP4 address. */
u8 *
format_ip4_address(u8 *s, va_list *args)
{
  u8 *a = va_arg(*args, u8 *);
  return format(s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

vcdp_tenant_t *
vcdp_tenant_get_by_id(u32 tenant_id, u16 *tenant_idx)
{
  return 0;
}

ip4_main_t ip4_main;
vnet_main_t *vnet_get_main (void) { return 0;}

#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_template.c>

u8 *format_vnet_sw_if_index_name (u8 * s, va_list * args) { return 0; }
u8 *format_ip_protocol (u8 * s, va_list * args) { return 0; }
