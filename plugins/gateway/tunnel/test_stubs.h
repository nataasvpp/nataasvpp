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

u8 *format_tcp_header(u8 *s, va_list *args) {
    tcp_header_t *tcp = va_arg(*args, tcp_header_t *);
    u32 max_header_bytes = va_arg(*args, u32);
    u32 header_bytes;
    u32 indent;

    /* Nothing to do. */
    if (max_header_bytes < sizeof(tcp[0]))
        return format(s, "TCP header truncated");

    indent = format_get_indent(s);
    indent += 2;
    header_bytes = tcp_header_bytes(tcp);

    s = format(s, "TCP: %d -> %d", clib_net_to_host_u16(tcp->src),
               clib_net_to_host_u16(tcp->dst));

    s = format(s, "\n%Useq. 0x%08x ack 0x%08x", format_white_space, indent,
               clib_net_to_host_u32(tcp->seq_number),
               clib_net_to_host_u32(tcp->ack_number));

    s = format(s, "\n%Utcp header: %d bytes", format_white_space, indent,
               tcp->flags, header_bytes);

    s = format(s, "\n%Uwindow %d, checksum 0x%04x", format_white_space, indent,
               clib_net_to_host_u16(tcp->window),
               clib_net_to_host_u16(tcp->checksum));
    return s;
}
/* Format UDP header. */
u8 *format_udp_header(u8 *s, va_list *args) {
    udp_header_t *udp = va_arg(*args, udp_header_t *);
    u32 max_header_bytes = va_arg(*args, u32);
    u32 indent;

    /* Nothing to do. */
    if (max_header_bytes < sizeof(udp[0]))
        return format(s, "UDP header truncated");

    indent = format_get_indent(s);
    indent += 2;

    s = format(s, "UDP: %d -> %d", clib_net_to_host_u16(udp->src_port),
               clib_net_to_host_u16(udp->dst_port));

    s = format(s, "\n%Ulength %d, checksum 0x%04x", format_white_space, indent,
               clib_net_to_host_u16(udp->length),
               clib_net_to_host_u16(udp->checksum));

    return s;
}

/* Format an IP4 header. */
u8 *format_ip4_header(u8 *s, va_list *args) {
    ip4_header_t *ip = va_arg(*args, ip4_header_t *);
    u32 max_header_bytes = va_arg(*args, u32);
    u32 ip_version, header_bytes;
    u32 indent;

    /* Nothing to do. */
    if (max_header_bytes < sizeof(ip[0]))
        return format(s, "IP header truncated");

    indent = format_get_indent(s);
    indent += 2;

    ip_version = (ip->ip_version_and_header_length >> 4);
    header_bytes = (ip->ip_version_and_header_length & 0xf) * sizeof(u32);

    s = format(s, "%d: %U -> %U", ip->protocol, format_ip4_address,
               ip->src_address.data, format_ip4_address, ip->dst_address.data);

    /* Show IP version and header length only with unexpected values. */
    if (ip_version != 4 || header_bytes != sizeof(ip4_header_t))
        s = format(s, "\n%Uversion %d, header length %d", format_white_space,
                   indent, ip_version, header_bytes);

    s = format(s, "\n%Utos 0x%02x, ttl %d, length %d, checksum 0x%04x",
               format_white_space, indent, ip->tos, ip->ttl,
               clib_net_to_host_u16(ip->length),
               clib_net_to_host_u16(ip->checksum));

    /* Check and report invalid checksums. */
    {
        if (!ip4_header_checksum_is_valid(ip))
            s = format(s, " (should be 0x%04x)",
                       clib_net_to_host_u16(ip4_header_checksum(ip)));
    }

    {
        u32 f = clib_net_to_host_u16(ip->flags_and_fragment_offset);
        u32 o;

        s = format(s, "\n%Ufragment id 0x%04x", format_white_space, indent,
                   clib_net_to_host_u16(ip->fragment_id));

        /* Fragment offset. */
        o = 8 * (f & 0x1fff);
        f ^= f & 0x1fff;
        if (o != 0)
            s = format(s, " offset %d", o);

        if (f != 0) {
            s = format(s, ", flags ");
#define _(l)                                                                   \
    if (f & IP4_HEADER_FLAG_##l)                                               \
        s = format(s, #l);
            _(MORE_FRAGMENTS);
            _(DONT_FRAGMENT);
            _(CONGESTION);
#undef _
        }
        /* Fragment packet but not the first. */
        if (o != 0)
            return s;
    }

    return s;
}
