// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vcdp/common.h>
#include <vcdp/service.h>
#include <vcdp/vcdp_funcs.h>

#define foreach_vcdp_lookup_error                                             \
  _ (MISS, "flow miss")                                                       \
  _ (LOCAL, "local flow")                                                     \
  _ (REMOTE, "remote flow")                                                   \
  _ (COLLISION, "hash add collision")                                         \
  _ (CON_DROP, "handoff drop")

#define foreach_vcdp_lookup_error                                                                                      \
  _(MISS, "flow miss")                                                                                                 \
  _(LOCAL, "local flow")                                                                                               \
  _(REMOTE, "remote flow")                                                                                             \
  _(COLLISION, "hash add collision")                                                                                   \
  _(CON_DROP, "handoff drop")

typedef enum {
#define _(sym, str) VCDP_LOOKUP_ERROR_##sym,
  foreach_vcdp_lookup_error
#undef _
    VCDP_LOOKUP_N_ERROR,
} vcdp_lookup_error_t;

static char *vcdp_lookup_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_lookup_error
#undef _
};

#define foreach_vcdp_handoff_error _(NOERROR, "no error")

typedef enum {
#define _(sym, str) VCDP_LOOKUP_ERROR_##sym,
  foreach_vcdp_handoff_error
#undef _
    VCDP_HANDOFF_N_ERROR,
} vcdp_handoff_error_t;

static char *vcdp_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_vcdp_handoff_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u64 hash;
  u32 flow_id;
  union
  {
    vcdp_session_ip4_key_t k4;
    vcdp_session_ip6_key_t k6;
  };
  u8 is_ip6;
} vcdp_lookup_trace_t;

typedef struct {
  u32 next_index;
  u32 flow_id;
} vcdp_handoff_trace_t;

#ifdef __SSE4_1__
#define u32x4_insert(v, x, i) (u32x4) _mm_insert_epi32 ((__m128i) (v), x, i)
#else
static_always_inline u32x4
u32x4_insert (u32x4 v, u32 x, int i)
{
  u32x4 tmp = v;
  tmp[i] = x;
  return tmp;
}
#endif

#ifdef __SSE3__
#define u8x8_shuffle(v, i) (u8x8) _mm_shuffle_pi8 ((__m64) (v), (__m64) i)
#elif defined(__clang__)
static_always_inline u8x8
u8x8_shuffle (u8x8 v, u8x8 i)
{
  u8x8 tmp = { 0 };
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
  tmp2 &= (u16x8){ 128, 128, 128, 128, 128, 128, 128, 128 };
  tmp2 <<= 1;
  tmp2 -= 1;
  tmp2 = ~tmp2;
  tmp &= __builtin_convertvector(tmp2, u8x8);
  return tmp;
}
#else
#define u8x8_shuffle(v, i) __builtin_shuffle ((u8x8) v, (u8x8) i)
#endif

#ifndef CLIB_HAVE_VEC256
#define u32x8_splat(i) ((u32) (i) & (u32x8){ ~0, ~0, ~0, ~0, ~0, ~0, ~0, ~0 })
#endif

#ifndef SHUFFLE
#if defined(__clang__)
#define SHUFFLE(v1, v2, i) __builtin_shufflevector ((v1), (v2), (i))
#elif defined(__GNUC__)
#define SHUFFLE(v1, v2, i) __builtin_shuffle ((v1), (v2), (i))
#endif
#endif

#define u8x16_SHUFFLE(v1, v2, i)                                              \
  (u8x16) SHUFFLE ((u8x16) (v1), (u8x16) (v2), (u8x16) (i))
#define u32x8_SHUFFLE(v1, v2, i)                                              \
  (u32x8) SHUFFLE ((u32x8) (v1), (u32x8) (v2), (u32x8) (i))

#ifdef __SSE3__
#define u8x16_shuffle_dynamic(v, i)                                           \
  (u8x16) _mm_shuffle_epi8 ((__m128i) v, (__m128i) i)
#elif defined(__clang__)
static_always_inline u8x16
u8x16_shuffle_dynamic (u8x16 v, u8x16 i)
{
  u8x16 tmp = { 0 };
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
  tmp2 &= (u16x16){ 128, 128, 128, 128, 128, 128, 128, 128,
		    128, 128, 128, 128, 128, 128, 128, 128 };
  tmp2 <<= 1;
  tmp2 -= 1;
  tmp2 = ~tmp2;
  tmp &= __builtin_convertvector(tmp2, u8x16);
  return tmp;
}
#else
#define u8x16_shuffle_dynamic(v, i) __builtin_shuffle ((u8x16) v, (u8x16) i)
#endif

#ifdef __AVX2__
#define u32x8_shuffle_dynamic(v, i)                                           \
  (u32x8) _mm256_permutevar8x32_epi32 ((__m256i) v, (__m256i) i)
#elif defined(__clang__)
static_always_inline u32x8
u32x8_shuffle_dynamic (u32x8 v, u32x8 i)
{
  u32x8 tmp = { 0 };
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
#define u32x8_shuffle_dynamic(v, i) __builtin_shuffle ((u32x8) v, (u32x8) i)
#endif

static const u8 l4_mask_bits[256] = {
  [IP_PROTOCOL_ICMP] = 16,     [IP_PROTOCOL_IGMP] = 8,
  [IP_PROTOCOL_ICMP6] = 16,    [IP_PROTOCOL_TCP] = 32,
  [IP_PROTOCOL_UDP] = 32,      [IP_PROTOCOL_IPSEC_ESP] = 32,
  [IP_PROTOCOL_IPSEC_AH] = 32,
};

/* L4 data offset to copy into session */
static const u8 l4_offset_32w[256] = {
  [IP_PROTOCOL_ICMP] = 1, [IP_PROTOCOL_ICMP6] = 1
};

/* TODO: add ICMP, ESP, and AH (+ additional
 * branching or lookup for different
 * shuffling mask) */
static const u64 tcp_udp_bitmask =
  ((1 << IP_PROTOCOL_TCP) | (1 << IP_PROTOCOL_UDP));
static const u64 icmp4_type_bitmask =
  (1ULL << ICMP4_echo_request) | (1ULL << ICMP4_echo_reply);

/*ICMP echo and reply are types 128 & 129 */
static const u64 icmp6_type_bitmask_128off = 0x3;

#define KEY_IP4_SHUFF_NO_NORM                                                 \
  0, 1, 2, 3, -1, 5, -1, -1, 8, 9, 10, 11, 12, 13, 14, 15

#define KEY_IP4_SHUFF_NORM                                                    \
  2, 3, 0, 1, -1, 5, -1, -1, 12, 13, 14, 15, 8, 9, 10, 11

#define KEY_IP6_SHUFF_NO_NORM_A 0, 1, 2, 3, -1, -1, 6, -1
#define KEY_IP6_SHUFF_NORM_A	2, 3, 0, 1, -1, -1, 6, -1
#define KEY_IP6_SHUFF_NO_NORM_B 0, 1, 2, 3, 4, 5, 6, 7
#define KEY_IP6_SHUFF_NORM_B	4, 5, 6, 7, 0, 1, 2, 3
#define SRC_IP4_BYTESWAP_X2                                                   \
  11, 10, 9, 8, 16, 16, 16, 16, 11, 10, 9, 8, 16, 16, 16, 16
#define DST_IP4_BYTESWAP_X2                                                   \
  15, 14, 13, 12, 16, 16, 16, 16, 15, 14, 13, 12, 16, 16, 16, 16
#define IP6_BYTESWAP 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
#define KEY_IP4_SWAP_ICMP                                                     \
  2, 3, 0, 1, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16
#define KEY_IP6_SWAP_ICMP 2, 3, 0, 1, -1, -1, -1, -1

#define IP4_REASS_NEEDED_FLAGS                                                \
  ((u16) IP4_HEADER_FLAG_MORE_FRAGMENTS | (u16) ((1 << 13) - 1))

#define VCDP_LV_TO_SP ((u64) 0x1 << 63)
static const u8x16 key_ip4_shuff_no_norm = { KEY_IP4_SHUFF_NO_NORM };

static const u8x16 key_ip4_shuff_norm = { KEY_IP4_SHUFF_NORM };

static const u8x8 key_ip6_shuff_no_norm_A = { KEY_IP6_SHUFF_NO_NORM_A };
static const u8x8 key_ip6_shuff_norm_A = { KEY_IP6_SHUFF_NORM_A };
static const u32x8 key_ip6_shuff_no_norm_B = { KEY_IP6_SHUFF_NO_NORM_B };
static const u32x8 key_ip6_shuff_norm_B = { KEY_IP6_SHUFF_NORM_B };
static const u8x8 key_ip6_swap_icmp = { KEY_IP6_SWAP_ICMP };

static_always_inline u8
calc_key_v4 (vlib_buffer_t *b, u32 context_id, vcdp_session_ip4_key_t *skey,
	     u64 *lookup_val, u64 *h, u8 slow_path)
{
  u8 pr;
  i64x2 norm, zero = {};
  u8x16 k, swap;
  u32 l4_hdr;
  void *next_header;
  ip4_header_t *ip = vlib_buffer_get_current (b);
  u8 slowpath_needed;
  u8 reass_needed;
  u8 l4_from_reass = 0;

  /* load last 16 bytes of ip header into 128-bit register */
  k = *(u8x16u *) ((u8 *) ip + 4);
  pr = ip->protocol;
  next_header = ip4_next_header (ip);
  reass_needed = !!(ip->flags_and_fragment_offset &
		    clib_host_to_net_u16 (IP4_REASS_NEEDED_FLAGS));
  slowpath_needed = pr == IP_PROTOCOL_ICMP || reass_needed;

  if (slow_path && reass_needed &&
      vcdp_buffer2 (b)->flags & VCDP_BUFFER_FLAG_REASSEMBLED)
    {
      /* This packet comes back from shallow virtual reassembly */
      l4_from_reass = 1;
    }
  else if (slow_path && reass_needed)
    {
      /* Reassembly is needed and has not been done yet */
      lookup_val[0] = (u64) VCDP_SP_NODE_IP4_REASS << 32 | VCDP_LV_TO_SP;
      return slowpath_needed;
    }

  /* byteswap src and dst ip and splat into all 4 elts of u32x4, then
   * compare so result will hold all ones if we need to swap src and dst
   * signed vector type is used as */
  norm = (((i64x2) u8x16_shuffle2 (k, zero, SRC_IP4_BYTESWAP_X2)) >
	  ((i64x2) u8x16_shuffle2 (k, zero, DST_IP4_BYTESWAP_X2)));

  /* we only normalize tcp and udp, for other cases we
   * reset all bits to 0 */
  if (slow_path && pr == IP_PROTOCOL_ICMP && l4_from_reass)
    {
      u8 type = vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
      norm &= i64x2_splat ((1ULL << type) & icmp4_type_bitmask) != zero;
    }
  else if (slow_path && pr == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = next_header;
      u8 type = icmp->type;
      norm &= i64x2_splat ((1ULL << type) & icmp4_type_bitmask) != zero;
    }
  else
    {
      norm &= i64x2_splat ((1ULL << pr) & tcp_udp_bitmask) != zero;
    }
  swap = key_ip4_shuff_no_norm;
  /* if norm is zero, we don't need to normalize so nothing happens here */
  swap += (key_ip4_shuff_norm - key_ip4_shuff_no_norm) & (u8x16) norm;

  /* overwrite first 4 bytes with first 0 - 4 bytes of l4 header */
  next_header = ip4_next_header (ip);
  if (slow_path && l4_from_reass)
    {
      u16 src_port, dst_port;
      src_port = vnet_buffer (b)->ip.reass.l4_src_port;
      dst_port = vnet_buffer (b)->ip.reass.l4_dst_port;
      l4_hdr = dst_port << 16 | src_port;
      /* Mask seqnum field out for ICMP */
      if (pr == IP_PROTOCOL_ICMP)
	l4_hdr &= 0xff;
    }
  else if (slow_path)
    l4_hdr = ((u32 *) next_header + l4_offset_32w[pr])[0] &
	     pow2_mask (l4_mask_bits[pr]);
  else
    l4_hdr = *(u32 *) next_header & pow2_mask (l4_mask_bits[pr]);
  k = (u8x16) u32x4_insert (k, l4_hdr, 0);

  k = u8x16_shuffle_dynamic (k, swap);

  /* Reshuffle for ICMP
     TODO: merge with fast path? */
  if (slow_path && pr == IP_PROTOCOL_ICMP)
    k += u8x16_shuffle2 (k, zero, KEY_IP4_SWAP_ICMP);
  lookup_val[0] = ((u32x4) norm)[0] & 0x1;

  /* extract tcp flags */
  if (slow_path && l4_from_reass && pr == IP_PROTOCOL_TCP)
    vcdp_buffer2 (b)->tcp_flags =
      vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
  else if (pr == IP_PROTOCOL_TCP)
    vcdp_buffer (b)->tcp_flags = *(u8 *) next_header + 13;
  else
    vcdp_buffer (b)->tcp_flags = 0;

  /* store key */
  skey->ip4_key.as_u8x16 = k;
  skey->context_id = context_id;
  clib_memset (skey->zeros, 0, sizeof (skey->zeros));
  /* calculate hash */
  h[0] = clib_bihash_hash_24_8 ((clib_bihash_kv_24_8_t *) (skey));

  if (slow_path && l4_from_reass)
    {
      /* Restore vcdp_buffer */
      /* TODO: optimise save/restore ? */
      vcdp_buffer (b)->flags = vcdp_buffer2 (b)->flags;
      vcdp_buffer (b)->service_bitmap = vcdp_buffer2 (b)->service_bitmap;
      vcdp_buffer (b)->tcp_flags = vcdp_buffer2 (b)->tcp_flags;
      vcdp_buffer (b)->tenant_index = vcdp_buffer2 (b)->tenant_index;

      /*Clear*/
      vcdp_buffer2 (b)->flags = 0;
      vcdp_buffer2 (b)->service_bitmap = 0;
      vcdp_buffer2 (b)->tcp_flags = 0;
      vcdp_buffer2 (b)->tenant_index = 0;
    }

  /* If slowpath needed == 1, we may have done a lot of useless work that will
   be overwritten, but we avoid too much branching in fastpath */
  return slowpath_needed;
}

static_always_inline u32x2
u32x2_insert (u32x2 x, u32 y, uword idx)
{
  u32x2 tmp = x;
  tmp[idx] = y;
  return tmp;
}

static_always_inline u8
calc_key_v6 (vlib_buffer_t *b, u32 context_id, vcdp_session_ip6_key_t *skey,
	     u64 *lookup_val, u64 *h, u8 slow_path)
{
  u8 pr;
  i64x2 norm, norm_reverse, zero = {};
  union
  {
    struct
    {
      u32x2u as_u32x2;
      u32x8u as_u32x8;
    };
    struct
    {
      u8x8u as_u8x8;
      u8x16u as_u8x16[2];
    };
    struct
    {
      u64 as_u64;
      u64x4u as_u64x4;
    };
  } k;
  u8x8 swap_A;
  u32x8 swap_B;
  STATIC_ASSERT_SIZEOF (k, 40);
  u8x16 src_ip6, dst_ip6;
  u32 l4_hdr;
  void *next_header;
  u8 *data = vlib_buffer_get_current (b);
  ip6_header_t *ip = (void *) data;
  int slowpath_needed;
  u8 ext_hdr = 0;
  u8 l4_from_reass = 0;

  /* loads 40 bytes of ip6 header */
  k.as_u32x2 = *(u32x2u *) data;
  k.as_u32x8 = *(u32x8u *) (data + 8);
  pr = ip->protocol;
  ext_hdr = ip6_ext_hdr (pr);
  next_header = ip6_next_header (ip);

  slowpath_needed = pr == IP_PROTOCOL_ICMP6 || ext_hdr;

  /* byteswap src and dst ip and splat into all 4 elts of u32x4, then
   * compare so result will hold all ones if we need to swap src and dst
   * signed vector type is used as */
  src_ip6 = u8x16_shuffle2 (k.as_u8x16[0], zero, IP6_BYTESWAP);
  dst_ip6 = u8x16_shuffle2 (k.as_u8x16[1], zero, IP6_BYTESWAP);
  norm = (u64x2) src_ip6 > (u64x2) dst_ip6;
  norm_reverse = (u64x2) src_ip6 < (u64x2) dst_ip6;
  norm = i64x2_splat (norm[1] | (~norm_reverse[1] & norm[0]));

  next_header = ip6_next_header (ip);

  if (slow_path && vcdp_buffer2 (b)->flags & VCDP_BUFFER_FLAG_REASSEMBLED)
    {
      /* This packet comes back from shallow virtual reassembly */
      l4_from_reass = 1;
    }
  if (slow_path && ext_hdr)
    {
      /* Parse the extension header chain and look for fragmentation */
      ip6_ext_hdr_chain_t chain;
      int res =
	ip6_ext_header_walk (b, ip, IP_PROTOCOL_IPV6_FRAGMENTATION, &chain);
      if (!l4_from_reass && res >= 0 &&
	  chain.eh[res].protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
	{
	  /* Reassembly is needed and has not been done yet */
	  lookup_val[0] = (u64) VCDP_SP_NODE_IP6_REASS << 32 | VCDP_LV_TO_SP;
	  return slowpath_needed;
	}
      else
	{
	  next_header =
	    ip6_ext_next_header_offset (ip, chain.eh[chain.length - 1].offset);
	  pr = chain.eh[chain.length - 1].protocol;
	}
    }

  /* we only normalize tcp and udp, for other cases we
   * reset all bits to 0 */
  if (slow_path && pr == IP_PROTOCOL_ICMP6 && l4_from_reass)
    {
      u8 type = vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
      norm &= i64x2_splat ((1ULL << (type - 128)) &
			   icmp6_type_bitmask_128off) != zero;
    }
  else if (slow_path && pr == IP_PROTOCOL_ICMP6)
    {
      icmp46_header_t *icmp = next_header;
      u8 type = icmp->type;
      norm &= i64x2_splat ((1ULL << (type - 128)) &
			   icmp6_type_bitmask_128off) != zero;
    }
  else
    {
      norm &= i64x2_splat ((1ULL << pr) & tcp_udp_bitmask) != zero;
    }
  swap_A = key_ip6_shuff_no_norm_A;
  swap_B = key_ip6_shuff_no_norm_B;

  /* if norm is zero, we don't need to normalize so nothing happens here */
  swap_A += (key_ip6_shuff_norm_A - key_ip6_shuff_no_norm_A) & (u8x8) norm[0];
  swap_B +=
    (key_ip6_shuff_norm_B - key_ip6_shuff_no_norm_B) & u32x8_splat (norm[0]);

  /* overwrite first 4 bytes with first 0 - 4 bytes of l4 header */
  if (slow_path && l4_from_reass)
    {
      u16 src_port, dst_port;
      src_port = vnet_buffer (b)->ip.reass.l4_src_port;
      dst_port = vnet_buffer (b)->ip.reass.l4_dst_port;
      l4_hdr = dst_port << 16 | src_port;
      /* Mask seqnum field out for ICMP */
      if (pr == IP_PROTOCOL_ICMP6)
	l4_hdr &= 0xff;
    }
  else if (slow_path)
    l4_hdr = ((u32 *) next_header + l4_offset_32w[pr])[0] &
	     pow2_mask (l4_mask_bits[pr]);
  else
    l4_hdr = *(u32 *) next_header & pow2_mask (l4_mask_bits[pr]);

  k.as_u32x2 = u32x2_insert (k.as_u32x2, l4_hdr, 0);

  k.as_u8x8 = u8x8_shuffle (k.as_u8x8, swap_A);
  k.as_u32x8 = u32x8_shuffle_dynamic (k.as_u32x8, swap_B);
  /* Reshuffle for ICMP
     TODO: merge with fast path? */
  if (slow_path && pr == IP_PROTOCOL_ICMP6)
    k.as_u8x8 += u8x8_shuffle (k.as_u8x8, key_ip6_swap_icmp);
  lookup_val[0] = ((u32x4) norm)[0] & 0x1;

  /* extract tcp flags */
  if (slow_path && l4_from_reass && pr == IP_PROTOCOL_TCP)
    vcdp_buffer2 (b)->tcp_flags =
      vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
  else if (pr == IP_PROTOCOL_TCP)
    vcdp_buffer (b)->tcp_flags = *(u8 *) next_header + 13;
  else
    vcdp_buffer (b)->tcp_flags = 0;

  /* store key */
  skey->ip6_key.as_u64 = k.as_u64;
  skey->ip6_key.as_u64x4 = k.as_u64x4;
  skey->context_id = context_id;
  clib_memset (skey->zeros, 0, sizeof (skey->zeros));
  /* calculate hash */
  h[0] = clib_bihash_hash_48_8 ((clib_bihash_kv_48_8_t *) (skey));
  if (slow_path && l4_from_reass)
    {
      /* Restore vcdp_buffer */
      /* TODO: optimise save/restore ? */
      vcdp_buffer (b)->flags = vcdp_buffer2 (b)->flags;
      vcdp_buffer (b)->service_bitmap = vcdp_buffer2 (b)->service_bitmap;
      vcdp_buffer (b)->tcp_flags = vcdp_buffer2 (b)->tcp_flags;
      vcdp_buffer (b)->tenant_index = vcdp_buffer2 (b)->tenant_index;

      /*Clear*/
      vcdp_buffer2 (b)->flags = 0;
      vcdp_buffer2 (b)->service_bitmap = 0;
      vcdp_buffer2 (b)->tcp_flags = 0;
      vcdp_buffer2 (b)->tenant_index = 0;
    }
  /* If slowpath needed == 1, we may have done a lot of useless work that will
   be overwritten, but we avoid too much branching in fastpath */
  return slowpath_needed;
}

static_always_inline int
vcdp_create_session_v4(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_tenant_t *tenant, u16 tenant_idx,
                       u32 thread_index, f64 time_now, void *k, u64 *h, u64 *lookup_val, u32 rx_id)
{
  return vcdp_create_session_inline(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, k, h, lookup_val, 0, rx_id);
}

static_always_inline int
vcdp_create_session_v6(vcdp_main_t *vcdp, vcdp_per_thread_data_t *ptd, vcdp_tenant_t *tenant, u16 tenant_idx,
                       u32 thread_index, f64 time_now, void *k, u64 *h, u64 *lookup_val)
{
  return vcdp_create_session_inline(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, k, h, lookup_val, 1,
                                    0 /* NO v6 */);
}

static_always_inline u8
vcdp_lookup_four_v4 (vlib_buffer_t **b, vcdp_session_ip4_key_t *k,
		     u64 *lookup_val, u64 *h, int prefetch_buffer_stride,
		     u8 slowpath)
{
  vlib_buffer_t **pb = b + prefetch_buffer_stride;
  u8 slowpath_needed = 0;
  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[0]);
    clib_prefetch_load(pb[0]->data);
  }

  slowpath_needed |=
    calc_key_v4 (b[0], b[0]->flow_id, k + 0, lookup_val + 0, h + 0, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[1]);
    clib_prefetch_load(pb[1]->data);
  }

  slowpath_needed |=
    calc_key_v4 (b[1], b[1]->flow_id, k + 1, lookup_val + 1, h + 1, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[2]);
    clib_prefetch_load(pb[2]->data);
  }

  slowpath_needed |=
    calc_key_v4 (b[2], b[2]->flow_id, k + 2, lookup_val + 2, h + 2, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[3]);
    clib_prefetch_load(pb[3]->data);
  }

  slowpath_needed |=
    calc_key_v4 (b[3], b[3]->flow_id, k + 3, lookup_val + 3, h + 3, slowpath);
  return slowpath_needed;
}

static_always_inline u8
vcdp_lookup_four_v6 (vlib_buffer_t **b, vcdp_session_ip6_key_t *k,
		     u64 *lookup_val, u64 *h, int prefetch_buffer_stride,
		     u8 slowpath)
{
  vlib_buffer_t **pb = b + prefetch_buffer_stride;
  u8 slowpath_needed = 0;
  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[0]);
    clib_prefetch_load(pb[0]->data);
  }

  slowpath_needed |=
    calc_key_v6 (b[0], b[0]->flow_id, k + 0, lookup_val + 0, h + 0, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[1]);
    clib_prefetch_load(pb[1]->data);
  }

  slowpath_needed |= calc_key_v6 (b[1], b[1]->flow_id, k + 1, lookup_val + 1,
				  h + 1, l4_hdr_offset + 1, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[2]);
    clib_prefetch_load(pb[2]->data);
  }

  slowpath_needed |= calc_key_v6 (b[2], b[2]->flow_id, k + 2, lookup_val + 2,
				  h + 2, l4_hdr_offset + 2, slowpath);

  if (prefetch_buffer_stride) {
    clib_prefetch_load(pb[3]);
    clib_prefetch_load(pb[3]->data);
  }

  slowpath_needed |= calc_key_v6 (b[3], b[3]->flow_id, k + 3, lookup_val + 3,
				  h + 3, l4_hdr_offset + 3, slowpath);
  return slowpath_needed;
}

static_always_inline void
vcdp_prepare_all_keys_v4_slow (vlib_buffer_t **b, vcdp_session_ip4_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset,
			       u32 n_left);

static_always_inline void
vcdp_prepare_all_keys_v6_slow (vlib_buffer_t **b, vcdp_session_ip6_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset,
			       u32 n_left);

static_always_inline uword
vcdp_prepare_all_keys_v4 (vlib_buffer_t **b, vcdp_session_ip4_key_t *k,
			  u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left,
			  u8 slowpath)
{
  /* main loop - prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  while (n_left >= 8)
    {
      if (vcdp_lookup_four_v4 (b, k, lv, h, l4_hdr_offset, 4, slowpath) &&
	  !slowpath)
	return n_left;

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      l4_hdr_offset += 4;
      n_left -= 4;
    }

  /* last 4 packets - dont prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  if (n_left >= 4)
    {
      if (vcdp_lookup_four_v4 (b, k, lv, h, l4_hdr_offset, 0, slowpath) &&
	  !slowpath)
	return n_left;

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      l4_hdr_offset += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      if (calc_key_v4 (b[0], b[0]->flow_id, k + 0, lv + 0, h + 0,
		       l4_hdr_offset + 0, slowpath) &&
	  !slowpath)
	return n_left;

      b += 1;
      k += 1;
      lv += 1;
      h += 1;
      n_left -= 1;
    }
  return 0;
}

static_always_inline uword
vcdp_prepare_all_keys_v6 (vlib_buffer_t **b, vcdp_session_ip6_key_t *k,
			  u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left,
			  u8 slowpath)
{
  /* main loop - prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  while (n_left >= 8)
    {
      if (vcdp_lookup_four_v6 (b, k, lv, h, l4_hdr_offset, 4, slowpath) &&
	  !slowpath)
	return n_left;

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      l4_hdr_offset += 4;
      n_left -= 4;
    }

  /* last 4 packets - dont prefetch next 4 buffers,
   * prefetch previous 4 buckets */
  if (n_left >= 4)
    {
      if (vcdp_lookup_four_v6 (b, k, lv, h, l4_hdr_offset, 0, slowpath) &&
	  !slowpath)
	return n_left;

      b += 4;
      k += 4;
      lv += 4;
      h += 4;
      l4_hdr_offset += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      if (calc_key_v6 (b[0], b[0]->flow_id, k + 0, lv + 0, h + 0,
		       l4_hdr_offset, slowpath) &&
	  !slowpath)
	return n_left;

      b += 1;
      k += 1;
      lv += 1;
      h += 1;
      l4_hdr_offset += 1;
      n_left -= 1;
    }
  return 0;
}

static_always_inline void
vcdp_prepare_all_keys_v4_slow (vlib_buffer_t **b, vcdp_session_ip4_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left)
{
  vcdp_prepare_all_keys_v4 (b, k, lv, h, l4_hdr_offset, n_left, 1);
}
static_always_inline uword
vcdp_prepare_all_keys_v4_fast (vlib_buffer_t **b, vcdp_session_ip4_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left)
{
  return vcdp_prepare_all_keys_v4 (b, k, lv, h, l4_hdr_offset, n_left, 0);
}

static_always_inline void
vcdp_prepare_all_keys_v6_slow (vlib_buffer_t **b, vcdp_session_ip6_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left)
{
  vcdp_prepare_all_keys_v6 (b, k, lv, h, l4_hdr_offset, n_left, 1);
}

static_always_inline uword
vcdp_prepare_all_keys_v6_fast (vlib_buffer_t **b, vcdp_session_ip6_key_t *k,
			       u64 *lv, u64 *h, i16 *l4_hdr_offset, u32 n_left)
{
  return vcdp_prepare_all_keys_v6 (b, k, lv, h, l4_hdr_offset, n_left, 0);
}

static_always_inline uword
vcdp_lookup_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, u8 is_ipv6)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vcdp_bihash_kv46_t kv = {};
  vcdp_tenant_t *tenant;
  vcdp_session_t *session;
  u32 session_index;
  u32 *bi, *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u32 to_local[VLIB_FRAME_SIZE], n_local = 0;
  u32 to_remote[VLIB_FRAME_SIZE], n_remote = 0;
  u32 to_sp[VLIB_FRAME_SIZE], n_to_sp = 0;
  u16 thread_indices[VLIB_FRAME_SIZE];
  u16 local_next_indices[VLIB_FRAME_SIZE];
  u32 sp_node_indices[VLIB_FRAME_SIZE];
  vlib_buffer_t *local_bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t *to_sp_bufs[VLIB_FRAME_SIZE];
  u32 local_flow_indices[VLIB_FRAME_SIZE];
  VCDP_SESSION_IP46_KEYS_TYPE(VLIB_FRAME_SIZE) keys;

  vcdp_session_ip4_key_t *k4 = keys.keys4;
  vcdp_session_ip6_key_t *k6 = keys.keys6;

  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  u32 lengths[VLIB_FRAME_SIZE], *len = lengths;
  f64 time_now = vlib_time_now (vm);
  /* lookup_vals contains:
   * - (Phase 1) to_slow_path_node (1bit)
                  ||| slow_path_node_index (31bits)
   *              ||| zeros(31bits)
   *              |||
   *              ||| packet_dir (1bit)
   *
   * - (Phase 2) thread_index (32bits)||| flow_index (32bits)
      OR same as Phase 1 if slow path
      ASSUMPTION: thread index < 2^31 */
  u64 __attribute__((aligned(32))) lookup_vals[VLIB_FRAME_SIZE], *lv = lookup_vals;
  u16 hit_count = 0;
  uword n_left_slow_keys;

  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  ptd->current_time = time_now;
  vcdp_expire_timers(&ptd->wheel, time_now);
  vcdp_session_index_iterate_expired(ptd, session_index)
    vcdp_session_remove_or_rearm(vcdp, ptd, thread_index, session_index);

  if (is_ipv6)
    {
      if (PREDICT_FALSE ((n_left_slow_keys = vcdp_prepare_all_keys_v6_fast (
			    b, k6, lv, h, l4o, n_left))))
	{
	  uword n_done = n_left - n_left_slow_keys;
	  vcdp_prepare_all_keys_v6_slow (b + n_done, k6 + n_done, lv + n_done,
					 h + n_done, l4o + n_done,
					 n_left_slow_keys);
	}
    }
  else
    {
      if (PREDICT_FALSE ((n_left_slow_keys = vcdp_prepare_all_keys_v4_fast (
			    b, k4, lv, h, l4o, n_left))))
	{
	  uword n_done = n_left - n_left_slow_keys;
	  vcdp_prepare_all_keys_v4_slow (b + n_done, k4 + n_done, lv + n_done,
					 h + n_done, l4o + n_done,
					 n_left_slow_keys);
	}
    }

  if (is_ipv6)
    while (n_left) {
      if (PREDICT_TRUE(n_left > 8))
        clib_bihash_prefetch_bucket_48_8(&vcdp->table6, h[8]);

      if (PREDICT_TRUE(n_left > 1))
        vlib_prefetch_buffer_header(b[1], STORE);

      if (PREDICT_FALSE(lv[0] & VCDP_LV_TO_SP))
        goto next_pkt6;

      clib_memcpy_fast(&kv.kv6.key, k6, 48);
      if (clib_bihash_search_inline_with_hash_48_8(&vcdp->table6, h[0], &kv.kv6)) {
        u16 tenant_idx = vcdp_buffer(b[0])->tenant_index;
        tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
        /* if there is collision, we just reiterate */
        if (vcdp_create_session_v6(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, k6, h, lv)) {
          vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_COLLISION, 1);
          continue;
        }
      } else {
        lv[0] ^= kv.kv6.value;
        hit_count++;
      }

	b[0]->flow_id = lv[0] & (~(u32) 0);
	len[0] = vlib_buffer_length_in_chain (vm, b[0]);

      next_pkt6:
	b += 1;
	n_left -= 1;
	k6 += 1;
	h += 1;
	lv += 1;
	len += 1;
      }
  else
    while (n_left) {
      if (PREDICT_TRUE(n_left > 8))
        clib_bihash_prefetch_bucket_24_8(&vcdp->table4, h[8]);

      if (PREDICT_TRUE(n_left > 1))
        vlib_prefetch_buffer_header(b[1], STORE);

      if (PREDICT_FALSE(lv[0] & VCDP_LV_TO_SP))
        goto next_pkt4;

      clib_memcpy_fast(&kv.kv4.key, k4, 24);
      if (clib_bihash_search_inline_with_hash_24_8(&vcdp->table4, h[0], &kv.kv4)) {
        u16 tenant_idx = vcdp_buffer(b[0])->tenant_index;
        tenant = vcdp_tenant_at_index(vcdp, tenant_idx);
        /* if there is collision, we just reiterate */
        if (tenant->flags & VCDP_TENANT_FLAG_NO_CREATE) {
          clib_warning("OLE: Trying to create session from outside");
          goto next_pkt4;
        }
        if (vcdp_create_session_v4(vcdp, ptd, tenant, tenant_idx, thread_index, time_now, k4, h, lv,
                                   vcdp_buffer(b[0])->rx_id)) {
          vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_COLLISION, 1);
          continue;
        }
      } else {
        lv[0] ^= kv.kv4.value;
        hit_count++;
      }

	b[0]->flow_id = lv[0] & (~(u32) 0);
	len[0] = vlib_buffer_length_in_chain (vm, b[0]);

      next_pkt4:
	b += 1;
	n_left -= 1;
	k4 += 1;
	h += 1;
	lv += 1;
	len += 1;
      }

  n_left = frame->n_vectors;
  lv = lookup_vals;
  b = bufs;
  bi = from;
  len = lengths;
  while (n_left) {
    u32 flow_thread_index;
    u32 flow_index;
    vlib_combined_counter_main_t *vcm;

      if (lv[0] & VCDP_LV_TO_SP)
	{
	  to_sp[n_to_sp] = bi[0];
	  sp_node_indices[n_to_sp] = (lv[0] & ~(VCDP_LV_TO_SP)) >> 32;
	  to_sp_bufs[n_to_sp] = b[0];
	  n_to_sp++;
	  goto next_packet2;
	}

    flow_thread_index = vcdp_thread_index_from_lookup(lv[0]);
    flow_index = lv[0] & (~(u32) 0);
    vcm = &vcdp->per_thread_data[flow_thread_index].per_session_ctr[VCDP_FLOW_COUNTER_LOOKUP];
    vlib_increment_combined_counter(vcm, thread_index, flow_index, 1, len[0]);
    if (flow_thread_index == thread_index) {
      /* known flow which belongs to this thread */
      to_local[n_local] = bi[0];
      local_flow_indices[n_local] = flow_index;
      local_bufs[n_local] = b[0];
      n_local++;
    } else {
      /* known flow which belongs to remote thread */
      to_remote[n_remote] = bi[0];
      thread_indices[n_remote] = flow_thread_index;
      n_remote++;
    }
  next_packet2:
    n_left -= 1;
    lv += 1;
    b += 1;
    bi += 1;
    len += 1;
  }

  /* handover buffers to remote node */
  if (n_remote) {
    u32 n_remote_enq;
    n_remote_enq =
      vlib_buffer_enqueue_to_thread(vm, node, vcdp->frame_queue_index, to_remote, thread_indices, n_remote, 1);
    vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_REMOTE, n_remote_enq);
    vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_CON_DROP, n_remote - n_remote_enq);
  }

  /* enqueue local */
  if (n_local) {
    u16 *current_next = local_next_indices;
    u32 *local_flow_index = local_flow_indices;
    b = local_bufs;
    n_left = n_local;

    /* TODO: prefetch session and buffer + 4 loop */
    while (n_left) {
      session_index = local_flow_index[0] >> 1;
      session = vcdp_session_at_index(ptd, session_index);
      u32 pbmp = session->bitmaps[vcdp_direction_from_flow_index(local_flow_index[0])];
      vcdp_buffer(b[0])->service_bitmap = pbmp;

      /* The tenant of the buffer is the tenant of the session */
      vcdp_buffer(b[0])->tenant_index = session->tenant_idx;

      vcdp_next(b[0], current_next);

      local_flow_index += 1;
      current_next += 1;
      b += 1;
      n_left -= 1;
    }
    vlib_buffer_enqueue_to_next(vm, node, to_local, local_next_indices, n_local);
    vlib_node_increment_counter(vm, node->node_index, VCDP_LOOKUP_ERROR_LOCAL, n_local);
  }

  if (n_to_sp)
    {
      vlib_frame_t *f = NULL;
      u32 *current_next_slot = NULL;
      u32 current_left_to_next = 0;
      u32 *current_to_sp = to_sp;
      u32 *sp_node_index = sp_node_indices;
      u32 last_node_index = VLIB_INVALID_NODE_INDEX;

    b = to_sp_bufs;
    n_left = n_to_sp;

    while (n_left) {
      u32 node_index;
      u16 tenant_idx;
      vcdp_tenant_t *tenant;

	  tenant_idx = vcdp_buffer (b[0])->tenant_index;
	  tenant = vcdp_tenant_at_index (vcdp, tenant_idx);
	  node_index = tenant->sp_node_indices[sp_node_index[0]];

      if (PREDICT_FALSE(node_index != last_node_index) || current_left_to_next == 0) {
        if (f != NULL)
          vlib_put_frame_to_node(vm, last_node_index, f);
        f = vlib_get_frame_to_node(vm, node_index);
        f->frame_flags |= node->flags & VLIB_NODE_FLAG_TRACE;
        current_next_slot = vlib_frame_vector_args(f);
        current_left_to_next = VLIB_FRAME_SIZE;
        last_node_index = node_index;
      }

      current_next_slot[0] = current_to_sp[0];

	  f->n_vectors += 1;
	  current_to_sp += 1;
	  b += 1;
	  sp_node_index += 1;
	  current_next_slot += 1;

      current_left_to_next -= 1;
      n_left -= 1;
    }
    vlib_put_frame_to_node(vm, last_node_index, f);
  }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      bi = from;
      h = hashes;
      u32 *in_local = to_local;
      u32 *in_remote = to_remote;

      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      vcdp_lookup_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->flow_id = b[0]->flow_id;
	      t->hash = h[0];
	      if (bi[0] == in_local[0])
		{
		  t->next_index = local_next_indices[(in_local++) - to_local];
		}
	      else
		{
		  t->next_index = ~0;
		  in_remote++;
		}
	      if ((t->is_ip6 = is_ipv6))
		clib_memcpy (&t->k6, &keys.keys6[i], sizeof (t->k6));
	      else
		clib_memcpy (&t->k4, &keys.keys4[i], sizeof (t->k4));
	      bi++;
	      b++;
	      h++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_NODE_FN(vcdp_lookup_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return vcdp_lookup_inline(vm, node, frame, 0); }

VLIB_NODE_FN(vcdp_lookup_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return vcdp_lookup_inline(vm, node, frame, 1); }

VLIB_NODE_FN(vcdp_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vcdp_main_t *vcdp = &vcdp_main;
  u32 thread_index = vm->thread_index;
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  f64 time_now = vlib_time_now(vm);

  ptd->current_time = time_now;

  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  /*TODO: prefetch, quad or octo loop...*/
  while (n_left) {
    u32 flow_index = b[0]->flow_id;
    u32 session_index = flow_index >> 1;
    vcdp_session_t *session = vcdp_session_at_index(ptd, session_index);
    u32 pbmp = session->bitmaps[vcdp_direction_from_flow_index(flow_index)];
    vcdp_buffer(b[0])->service_bitmap = pbmp;
    vcdp_next(b[0], current_next);

    current_next += 1;
    b += 1;
    n_left -= 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    current_next = next_indices;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_handoff_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->next_index = current_next[0];
        b++;
        current_next++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}

static u8 *
format_vcdp_lookup_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  vcdp_lookup_trace_t *t = va_arg (*args, vcdp_lookup_trace_t *);

  s = format (s,
	      "vcdp-lookup: sw_if_index %d, next index %d hash 0x%x "
	      "flow-id %u (session %u, %s) key 0x%U",
	      t->sw_if_index, t->next_index, t->hash, t->flow_id,
	      t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward",
	      format_hex_bytes_no_wrap,
	      t->is_ip6 ? (u8 *) &t->k6 : (u8 *) &t->k4,
	      t->is_ip6 ? sizeof (t->k6) : sizeof (t->k4));
  return s;
}

static u8 *
format_vcdp_handoff_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  vcdp_handoff_trace_t *t = va_arg(*args, vcdp_handoff_trace_t *);

  s = format(s,
             "vcdp-handoff: next index %d "
             "flow-id %u (session %u, %s)",
             t->next_index, t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(vcdp_lookup_ip4_node) = {
  .name = "vcdp-lookup-ip4",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_lookup_error_strings),
  .error_strings = vcdp_lookup_error_strings,
};

VLIB_REGISTER_NODE(vcdp_lookup_ip6_node) = {
  .name = "vcdp-lookup-ip6",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_lookup_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_lookup_error_strings),
  .error_strings = vcdp_lookup_error_strings,
};

VLIB_REGISTER_NODE(vcdp_handoff_node) = {
  .name = "vcdp-handoff",
  .vector_size = sizeof(u32),
  .format_trace = format_vcdp_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(vcdp_handoff_error_strings),
  .error_strings = vcdp_handoff_error_strings,

  .sibling_of = "vcdp-lookup-ip4",

};
