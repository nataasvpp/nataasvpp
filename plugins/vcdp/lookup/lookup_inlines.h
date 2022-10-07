// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_lookup_inlines_h
#define included_lookup_inlines_h
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4.h>
#include <vcdp/vcdp.h>
#include <vcdp/common.h>

#ifdef __SSE4_1__
#define u32x4_insert(v, x, i) (u32x4) _mm_insert_epi32((__m128i) (v), x, i)
#else
static_always_inline u32x4
u32x4_insert(u32x4 v, u32 x, int i) {
  u32x4 tmp = v;
  tmp[i] = x;
  return tmp;
}
#endif

#ifdef __SSE3__
#define u8x8_shuffle(v, i) (u8x8) _mm_shuffle_pi8((__m64) (v), (__m64) i)
#elif defined(__clang__)
static_always_inline u8x8
u8x8_shuffle(u8x8 v, u8x8 i) {
  u8x8 tmp = {0};
  u16x8 tmp2;
  tmp[0] = v[i[0] & 0x7];
  tmp[1] = v[i[1] & 0x7];
  tmp[2] = v[i[2] & 0x7];
  tmp[3] = v[i[3] & 0x7];
  tmp[4] = v[i[4] & 0x7];
  tmp[5] = v[i[5] & 0x7];
  tmp[6] = v[i[6] & 0x7];
  tmp[7] = v[i[7] & 0x7];
  tmp2 = __builtin_convertvector(i, u16x8);
  tmp2 &= (u16x8){128, 128, 128, 128, 128, 128, 128, 128};
  tmp2 <<= 1;
  tmp2 -= 1;
  tmp2 = ~tmp2;
  tmp &= __builtin_convertvector(tmp2, u8x8);
  return tmp;
}
#else
#define u8x8_shuffle(v, i) __builtin_shuffle((u8x8) v, (u8x8) i)
#endif

#ifndef CLIB_HAVE_VEC256
#define u32x8_splat(i) ((u32) (i) & (u32x8){~0, ~0, ~0, ~0, ~0, ~0, ~0, ~0})
#endif

#ifndef SHUFFLE
#if defined(__clang__)
#define SHUFFLE(v1, v2, i) __builtin_shufflevector((v1), (v2), (i))
#elif defined(__GNUC__)
#define SHUFFLE(v1, v2, i) __builtin_shuffle((v1), (v2), (i))
#endif
#endif

#define u8x16_SHUFFLE(v1, v2, i)                                               \
  (u8x16) SHUFFLE((u8x16) (v1), (u8x16) (v2), (u8x16) (i))
#define u32x8_SHUFFLE(v1, v2, i)                                               \
  (u32x8) SHUFFLE((u32x8) (v1), (u32x8) (v2), (u32x8) (i))

#ifdef __SSE3__
#define u8x16_shuffle_dynamic(v, i)                                            \
  (u8x16) _mm_shuffle_epi8((__m128i) v, (__m128i) i)
#elif defined(__clang__)
static_always_inline u8x16
u8x16_shuffle_dynamic(u8x16 v, u8x16 i) {
  u8x16 tmp = {0};
  u16x16 tmp2;
  tmp[0] = v[i[0] & 0xf];
  tmp[1] = v[i[1] & 0xf];
  tmp[2] = v[i[2] & 0xf];
  tmp[3] = v[i[3] & 0xf];
  tmp[4] = v[i[4] & 0xf];
  tmp[5] = v[i[5] & 0xf];
  tmp[6] = v[i[6] & 0xf];
  tmp[7] = v[i[7] & 0xf];
  tmp[8] = v[i[8] & 0xf];
  tmp[9] = v[i[9] & 0xf];
  tmp[10] = v[i[10] & 0xf];
  tmp[11] = v[i[11] & 0xf];
  tmp[12] = v[i[12] & 0xf];
  tmp[13] = v[i[13] & 0xf];
  tmp[14] = v[i[14] & 0xf];
  tmp[15] = v[i[15] & 0xf];
  tmp2 = __builtin_convertvector(i, u16x16);
  tmp2 &= (u16x16){128, 128, 128, 128, 128, 128, 128, 128,
                   128, 128, 128, 128, 128, 128, 128, 128};
  tmp2 <<= 1;
  tmp2 -= 1;
  tmp2 = ~tmp2;
  tmp &= __builtin_convertvector(tmp2, u8x16);
  return tmp;
}
#else
#define u8x16_shuffle_dynamic(v, i) __builtin_shuffle((u8x16) v, (u8x16) i)
#endif

#ifdef __AVX2__
#define u32x8_shuffle_dynamic(v, i)                                            \
  (u32x8) _mm256_permutevar8x32_epi32((__m256i) v, (__m256i) i)
#elif defined(__clang__)
static_always_inline u32x8
u32x8_shuffle_dynamic(u32x8 v, u32x8 i) {
  u32x8 tmp = {0};
  tmp[0] = v[i[0] & 0x7];
  tmp[1] = v[i[1] & 0x7];
  tmp[2] = v[i[2] & 0x7];
  tmp[3] = v[i[3] & 0x7];
  tmp[4] = v[i[4] & 0x7];
  tmp[5] = v[i[5] & 0x7];
  tmp[6] = v[i[6] & 0x7];
  tmp[7] = v[i[7] & 0x7];
  return tmp;
}
#else
#define u32x8_shuffle_dynamic(v, i) __builtin_shuffle((u32x8) v, (u32x8) i)
#endif

static const u8 l4_mask_bits[256] = {
  [IP_PROTOCOL_ICMP] = 16,     [IP_PROTOCOL_IGMP] = 8,
  [IP_PROTOCOL_ICMP6] = 16,    [IP_PROTOCOL_TCP] = 32,
  [IP_PROTOCOL_UDP] = 32,      [IP_PROTOCOL_IPSEC_ESP] = 32,
  [IP_PROTOCOL_IPSEC_AH] = 32,
};

/* L4 data offset to copy into session */
static const u8 l4_offset_32w[256] = {
  [IP_PROTOCOL_ICMP] = 1, [IP_PROTOCOL_ICMP6] = 1};

/* TODO: add ICMP, ESP, and AH (+ additional
 * branching or lookup for different
 * shuffling mask) */
static const u64 tcp_udp_bitmask =
  ((1 << IP_PROTOCOL_TCP) | (1 << IP_PROTOCOL_UDP));
static const u64 icmp4_type_ping_bitmask =
  (1ULL << ICMP4_echo_request) | (1ULL << ICMP4_echo_reply);

static const u64 icmp4_type_errors_bitmask =
  (1ULL << ICMP4_destination_unreachable) | (1ULL << ICMP4_redirect) |
  (1ULL << ICMP4_time_exceeded);

/*ICMP echo and reply are types 128 & 129 */
static const u64 icmp6_type_ping_bitmask_128off =
  (1ULL << (ICMP6_echo_request - 128)) | (1ULL << (ICMP6_echo_reply - 128));

static const u64 icmp6_type_errors_bitmask =
  (1ULL << ICMP6_destination_unreachable) | (1ULL << ICMP6_time_exceeded);

static const u64 icmp6_type_errors_bitmask_128off =
  (1ULL << (ICMP6_redirect - 128));

#define KEY_IP4_SHUFF_NO_NORM                                                  \
  0, 1, 2, 3, -1, 5, -1, -1, 8, 9, 10, 11, 12, 13, 14, 15

#define KEY_IP4_SHUFF_NORM                                                     \
  2, 3, 0, 1, -1, 5, -1, -1, 12, 13, 14, 15, 8, 9, 10, 11

#define KEY_IP6_SHUFF_NO_NORM_A 0, 1, 2, 3, -1, -1, 6, -1
#define KEY_IP6_SHUFF_NORM_A    2, 3, 0, 1, -1, -1, 6, -1
#define KEY_IP6_SHUFF_NO_NORM_B 0, 1, 2, 3, 4, 5, 6, 7
#define KEY_IP6_SHUFF_NORM_B    4, 5, 6, 7, 0, 1, 2, 3
#define SRC_IP4_BYTESWAP_X2                                                    \
  11, 10, 9, 8, 16, 16, 16, 16, 11, 10, 9, 8, 16, 16, 16, 16
#define DST_IP4_BYTESWAP_X2                                                    \
  15, 14, 13, 12, 16, 16, 16, 16, 15, 14, 13, 12, 16, 16, 16, 16
#define IP6_BYTESWAP 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
#define KEY_IP4_SWAP_ICMP                                                      \
  2, 3, 0, 1, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16
#define KEY_IP6_SWAP_ICMP 2, 3, 0, 1, -1, -1, -1, -1

#define IP4_REASS_NEEDED_FLAGS                                                 \
  ((u16) IP4_HEADER_FLAG_MORE_FRAGMENTS | (u16) ((1 << 13) - 1))

#define VCDP_LV_TO_SP ((u64) 0x1 << 63)
static const u8x16 key_ip4_shuff_no_norm = {KEY_IP4_SHUFF_NO_NORM};

static const u8x16 key_ip4_shuff_norm = {KEY_IP4_SHUFF_NORM};

static const u8x8 key_ip6_shuff_no_norm_A = {KEY_IP6_SHUFF_NO_NORM_A};
static const u8x8 key_ip6_shuff_norm_A = {KEY_IP6_SHUFF_NORM_A};
static const u32x8 key_ip6_shuff_no_norm_B = {KEY_IP6_SHUFF_NO_NORM_B};
static const u32x8 key_ip6_shuff_norm_B = {KEY_IP6_SHUFF_NORM_B};
static const u8x8 key_ip6_swap_icmp = {KEY_IP6_SWAP_ICMP};

// TODO: Side effects galore!
static_always_inline u8
calc_key_v4(vlib_buffer_t *b, u32 context_id, vcdp_session_ip4_key_t *skey,
            u64 *lookup_val, u64 *h, i16 *l4_hdr_offset, u8 slow_path) {
  u8 pr;
  i64x2 norm, zero = {};
  u8x16 k, swap;
  u32 l4_hdr;
  void *next_header;
  ip4_header_t *ip = vlib_buffer_get_current(b);
  u8 slowpath_needed;
  u8 reass_needed;
  u8 l4_from_reass = 0;
  u8 tcp_or_udp;
  u8 unknown_protocol;
  /* load last 16 bytes of ip header into 128-bit register */
  k = *(u8x16u *) ((u8 *) ip + 4);
  pr = ip->protocol;
  next_header = ip4_next_header(ip);
  l4_hdr_offset[0] = (u8 *) next_header - b->data;

  reass_needed = !!(ip->flags_and_fragment_offset &
                    clib_host_to_net_u16(IP4_REASS_NEEDED_FLAGS));
  tcp_or_udp = pr == IP_PROTOCOL_TCP || pr == IP_PROTOCOL_UDP;
  unknown_protocol = !tcp_or_udp && pr != IP_PROTOCOL_ICMP;
  slowpath_needed = !tcp_or_udp || reass_needed;

  if (slow_path && reass_needed &&
      vcdp_buffer2(b)->flags & VCDP_BUFFER_FLAG_REASSEMBLED) {
    /* This packet comes back from shallow virtual reassembly */
    l4_from_reass = 1;
  } else if (slow_path && reass_needed) {
    /* Reassembly is needed and has not been done yet */
    lookup_val[0] = (u64) VCDP_SP_NODE_IP4_REASS << 32 | VCDP_LV_TO_SP;
    return slowpath_needed;
  }

  /* non TCP, UDP or ICMP packets are going to slowpath */
  if (slow_path && unknown_protocol) {
    lookup_val[0] = (u64) VCDP_SP_NODE_IP4_UNKNOWN_PROTO << 32 | VCDP_LV_TO_SP;
    return slowpath_needed;
  }

  /* byteswap src and dst ip and splat into all 4 elts of u32x4, then
   * compare so result will hold all ones if we need to swap src and dst
   * signed vector type is used as */
  norm = (((i64x2) u8x16_shuffle2(k, zero, SRC_IP4_BYTESWAP_X2)) >
          ((i64x2) u8x16_shuffle2(k, zero, DST_IP4_BYTESWAP_X2)));

  if (slow_path && pr == IP_PROTOCOL_ICMP) {
    u8 type;
    i64 x, y;
    if (l4_from_reass)
      type = vnet_buffer(b)->ip.reass.icmp_type_or_tcp_flags;
    else {
      icmp46_header_t *icmp = next_header;
      type = icmp->type;
    }
    x = (1ULL << type) & icmp4_type_ping_bitmask;
    y = (1ULL << type) & icmp4_type_errors_bitmask;
    if (x == 0) {
      /* If it's an known ICMP error, treat in the specific slowpath (with
         a lookup on inner packet), otherwise, it's an unknown protocol */
      lookup_val[0] =
        y ? (u64) VCDP_SP_NODE_IP4_ICMP4_ERROR << 32 | VCDP_LV_TO_SP :
            (u64) VCDP_SP_NODE_IP4_UNKNOWN_PROTO << 32 | VCDP_LV_TO_SP;
      return slowpath_needed;
    }
    norm &= i64x2_splat(x) != zero;
  } else {
    norm &= i64x2_splat((1ULL << pr) & tcp_udp_bitmask) != zero;
  }
  swap = key_ip4_shuff_no_norm;
  /* if norm is zero, we don't need to normalize so nothing happens here */
  swap += (key_ip4_shuff_norm - key_ip4_shuff_no_norm) & (u8x16) norm;

  /* overwrite first 4 bytes with first 0 - 4 bytes of l4 header */
  if (slow_path && l4_from_reass) {
    u16 src_port, dst_port;
    src_port = vnet_buffer(b)->ip.reass.l4_src_port;
    dst_port = vnet_buffer(b)->ip.reass.l4_dst_port;
    l4_hdr = dst_port << 16 | src_port;
    /* Mask seqnum field out for ICMP */
    if (pr == IP_PROTOCOL_ICMP)
      l4_hdr &= 0xff;
  } else if (slow_path)
    l4_hdr = ((u32 *) next_header + l4_offset_32w[pr])[0] &
             pow2_mask(l4_mask_bits[pr]);
  else
    l4_hdr = *(u32 *) next_header & pow2_mask(l4_mask_bits[pr]);
  k = (u8x16) u32x4_insert((u32x4) k, l4_hdr, 0);

  k = u8x16_shuffle_dynamic(k, swap);

  /* Reshuffle for ICMP
     TODO: merge with fast path? */
  if (slow_path && pr == IP_PROTOCOL_ICMP)
    k += u8x16_shuffle2(k, zero, KEY_IP4_SWAP_ICMP);
  lookup_val[0] = ((u32x4) norm)[0] & 0x1;

  /* extract tcp flags */
  if (slow_path && l4_from_reass && pr == IP_PROTOCOL_TCP)
    vcdp_buffer2(b)->tcp_flags =
      vnet_buffer(b)->ip.reass.icmp_type_or_tcp_flags;
  else if (pr == IP_PROTOCOL_TCP)
    vcdp_buffer(b)->tcp_flags = *(u8 *) next_header + 13;
  else
    vcdp_buffer(b)->tcp_flags = 0;

  /* store key */
  skey->ip4_key.as_u8x16 = k;
  skey->context_id = context_id;
  clib_memset(skey->zeros, 0, sizeof(skey->zeros));
  /* calculate hash */
  h[0] = clib_bihash_hash_24_8((clib_bihash_kv_24_8_t *) (skey));

  if (slow_path && l4_from_reass) {
    /* Restore vcdp_buffer */
    /* TODO: optimise save/restore ? */
    vcdp_buffer(b)->flags = vcdp_buffer2(b)->flags;
    vcdp_buffer(b)->service_bitmap = vcdp_buffer2(b)->service_bitmap;
    vcdp_buffer(b)->tcp_flags = vcdp_buffer2(b)->tcp_flags;
    vcdp_buffer(b)->tenant_index = vcdp_buffer2(b)->tenant_index;

    /*Clear*/
    vcdp_buffer2(b)->flags = 0;
    vcdp_buffer2(b)->service_bitmap = 0;
    vcdp_buffer2(b)->tcp_flags = 0;
    vcdp_buffer2(b)->tenant_index = 0;
  }

  /* If slowpath needed == 1, we may have done a lot of useless work that will
   be overwritten, but we avoid too much branching in fastpath */
  return slowpath_needed;
}

static_always_inline u32x2
u32x2_insert(u32x2 x, u32 y, uword idx) {
  u32x2 tmp = x;
  tmp[idx] = y;
  return tmp;
}

static_always_inline u8
calc_key_v6(vlib_buffer_t *b, u32 context_id, vcdp_session_ip6_key_t *skey,
            u64 *lookup_val, u64 *h, i16 *l4_hdr_offset, u8 slow_path) {
  u8 pr;
  i64x2 norm, norm_reverse, zero = {};
  union {
    struct {
      u32x2u as_u32x2;
      u32x8u as_u32x8;
    };
    struct {
      u8x8u as_u8x8;
      u8x16u as_u8x16[2];
    };
    struct {
      u64 as_u64;
      u64x4u as_u64x4;
    };
  } k;
  u8x8 swap_A;
  u32x8 swap_B;
  STATIC_ASSERT_SIZEOF(k, 40);
  u8x16 src_ip6, dst_ip6;
  u32 l4_hdr;
  void *next_header;
  u8 *data = vlib_buffer_get_current(b);
  ip6_header_t *ip = (void *) data;
  int slowpath_needed;
  u8 ext_hdr = 0;
  u8 l4_from_reass = 0;
  u8 tcp_or_udp;
  u8 unknown_protocol;

  /* loads 40 bytes of ip6 header */
  k.as_u32x2 = *(u32x2u *) data;
  k.as_u32x8 = *(u32x8u *) (data + 8);
  pr = ip->protocol;
  ext_hdr = ip6_ext_hdr(pr);

  tcp_or_udp = pr == IP_PROTOCOL_TCP || pr == IP_PROTOCOL_UDP;
  slowpath_needed = !tcp_or_udp;

  /* byteswap src and dst ip and splat into all 4 elts of u32x4, then
   * compare so result will hold all ones if we need to swap src and dst
   * signed vector type is used as */
  src_ip6 = u8x16_shuffle2(k.as_u8x16[0], zero, IP6_BYTESWAP);
  dst_ip6 = u8x16_shuffle2(k.as_u8x16[1], zero, IP6_BYTESWAP);
  norm = (u64x2) src_ip6 > (u64x2) dst_ip6;
  norm_reverse = (u64x2) src_ip6 < (u64x2) dst_ip6;
  norm = i64x2_splat(norm[1] | (~norm_reverse[1] & norm[0]));

  next_header = ip6_next_header(ip);

  if (slow_path && vcdp_buffer2(b)->flags & VCDP_BUFFER_FLAG_REASSEMBLED) {
    /* This packet comes back from shallow virtual reassembly */
    l4_from_reass = 1;
  }
  if (slow_path && ext_hdr) {
    /* Parse the extension header chain and look for fragmentation */
    ip6_ext_hdr_chain_t chain;
    int res =
      ip6_ext_header_walk(b, ip, IP_PROTOCOL_IPV6_FRAGMENTATION, &chain);
    if (!l4_from_reass && res >= 0 &&
        chain.eh[res].protocol == IP_PROTOCOL_IPV6_FRAGMENTATION) {
      /* Reassembly is needed and has not been done yet */
      lookup_val[0] = (u64) VCDP_SP_NODE_IP6_REASS << 32 | VCDP_LV_TO_SP;
      return slowpath_needed;
    } else {
      next_header =
        ip6_ext_next_header_offset(ip, chain.eh[chain.length - 1].offset);
      pr = chain.eh[chain.length - 1].protocol;
      tcp_or_udp = pr == IP_PROTOCOL_TCP || pr == IP_PROTOCOL_UDP;
    }
  }
  l4_hdr_offset[0] = (u8 *) next_header - b[0].data;
  unknown_protocol = !tcp_or_udp && pr != IP_PROTOCOL_ICMP6;

  if (slow_path && unknown_protocol) {
    lookup_val[0] = (u64) VCDP_SP_NODE_IP6_UNKNOWN_PROTO << 32 | VCDP_LV_TO_SP;
    return slowpath_needed;
  }

  if (slow_path && pr == IP_PROTOCOL_ICMP6) {
    u8 type;
    i64 x, y, t, t128;
    if (l4_from_reass)
      type = vnet_buffer(b)->ip.reass.icmp_type_or_tcp_flags;
    else {
      icmp46_header_t *icmp = next_header;
      type = icmp->type;
    }
    t = (1ULL << type);
    t128 = (1ULL << ((u8) (type - 128)));
    x = t128 & icmp6_type_ping_bitmask_128off;
    y = t & icmp6_type_errors_bitmask;
    y |= t128 & icmp6_type_errors_bitmask_128off;
    if (x == 0) {
      /* If it's an known ICMP error, treat in the specific slowpath (with
     a lookup on inner packet), otherwise, it's an unknown protocol */
      lookup_val[0] =
        y ? (u64) VCDP_SP_NODE_IP6_ICMP6_ERROR << 32 | VCDP_LV_TO_SP :
            (u64) VCDP_SP_NODE_IP6_UNKNOWN_PROTO << 32 | VCDP_LV_TO_SP;
      return slowpath_needed;
    }
    norm &= i64x2_splat(x) != zero;
  } else {
    norm &= i64x2_splat((1ULL << pr) & tcp_udp_bitmask) != zero;
  }
  swap_A = key_ip6_shuff_no_norm_A;
  swap_B = key_ip6_shuff_no_norm_B;

  /* if norm is zero, we don't need to normalize so nothing happens here */
  swap_A += (key_ip6_shuff_norm_A - key_ip6_shuff_no_norm_A) & (u8x8) norm[0];
  swap_B +=
    (key_ip6_shuff_norm_B - key_ip6_shuff_no_norm_B) & u32x8_splat(norm[0]);

  /* overwrite first 4 bytes with first 0 - 4 bytes of l4 header */
  if (slow_path && l4_from_reass) {
    u16 src_port, dst_port;
    src_port = vnet_buffer(b)->ip.reass.l4_src_port;
    dst_port = vnet_buffer(b)->ip.reass.l4_dst_port;
    l4_hdr = dst_port << 16 | src_port;
    /* Mask seqnum field out for ICMP */
    if (pr == IP_PROTOCOL_ICMP6)
      l4_hdr &= 0xff;
  } else if (slow_path)
    l4_hdr = ((u32 *) next_header + l4_offset_32w[pr])[0] &
             pow2_mask(l4_mask_bits[pr]);
  else
    l4_hdr = *(u32 *) next_header & pow2_mask(l4_mask_bits[pr]);

  k.as_u32x2 = u32x2_insert(k.as_u32x2, l4_hdr, 0);

  k.as_u8x8 = u8x8_shuffle(k.as_u8x8, swap_A);
  k.as_u32x8 = u32x8_shuffle_dynamic(k.as_u32x8, swap_B);
  /* Reshuffle for ICMP
     TODO: merge with fast path? */
  if (slow_path && pr == IP_PROTOCOL_ICMP6)
    k.as_u8x8 += u8x8_shuffle(k.as_u8x8, key_ip6_swap_icmp);
  lookup_val[0] = ((u32x4) norm)[0] & 0x1;

  /* extract tcp flags */
  if (slow_path && l4_from_reass && pr == IP_PROTOCOL_TCP)
    vcdp_buffer2(b)->tcp_flags =
      vnet_buffer(b)->ip.reass.icmp_type_or_tcp_flags;
  else if (pr == IP_PROTOCOL_TCP)
    vcdp_buffer(b)->tcp_flags = *(u8 *) next_header + 13;
  else
    vcdp_buffer(b)->tcp_flags = 0;

  /* store key */
  skey->ip6_key.as_u64 = k.as_u64;
  skey->ip6_key.as_u64x4 = k.as_u64x4;
  skey->context_id = context_id;
  clib_memset(skey->zeros, 0, sizeof(skey->zeros));
  /* calculate hash */
  h[0] = clib_bihash_hash_48_8((clib_bihash_kv_48_8_t *) (skey));
  if (slow_path && l4_from_reass) {
    /* Restore vcdp_buffer */
    /* TODO: optimise save/restore ? */
    vcdp_buffer(b)->flags = vcdp_buffer2(b)->flags;
    vcdp_buffer(b)->service_bitmap = vcdp_buffer2(b)->service_bitmap;
    vcdp_buffer(b)->tcp_flags = vcdp_buffer2(b)->tcp_flags;
    vcdp_buffer(b)->tenant_index = vcdp_buffer2(b)->tenant_index;

    /*Clear*/
    vcdp_buffer2(b)->flags = 0;
    vcdp_buffer2(b)->service_bitmap = 0;
    vcdp_buffer2(b)->tcp_flags = 0;
    vcdp_buffer2(b)->tenant_index = 0;
  }
  /* If slowpath needed == 1, we may have done a lot of useless work that will
   be overwritten, but we avoid too much branching in fastpath */
  return slowpath_needed;
}

#endif /* included_lookup_inlines_h */