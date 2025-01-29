#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint16_t u16;

#if 0
u32
get_bin(u32 packet_size)
{
  u32 bin = 0;
  packet_size >>= 6;
  while (packet_size > 0) {
    packet_size >>= 1;
    bin++;
  }
  return bin;
}
#endif
// histogram: value to bin
#if 0
u32 value_to_bin(u32 value, u32 *bins, u32 n_bins)
{
  u32 bin = 0;
  while (value > bins[bin] && bin < n_bins)
    bin++;
  return bin;
}
#endif
u16 value_to_bin(u16 value)
{
    value >>= 7;
    return value > 15 ? 15 : value;
}

typedef struct {
  u32 *bins;
  u32 n_bins;
} histogram_t;

void histogram_init(histogram_t *h, u32 *bins, u32 n_bins)
{
  h->bins = bins;
  h->n_bins = n_bins;
}

void histogram_add(histogram_t *h, u32 value)
{
//   u32 bin = value_to_bin(value, h->bins, h->n_bins);
  u32 bin = value_to_bin(value);
  h->bins[bin]++;
    printf("bin = %u %u\n", bin, value);
}


int main(int argc, char **argv)
{
  histogram_t h;
  u32 bins[16];
  histogram_init(&h, bins, 16);

  histogram_add(&h, 0);
  histogram_add(&h, 40);
  histogram_add(&h, 128);
  histogram_add(&h, 512);
  histogram_add(&h, 1000);
  histogram_add(&h, 1500);
  histogram_add(&h, 9000);

  return 0;
}