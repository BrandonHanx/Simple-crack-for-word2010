#ifndef _HASH_FUNC_H_
#define _HASH_FUNC_H_

typedef unsigned char u8;
typedef unsigned int u32;
void sha1_transform (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[5]);

#define SHA1_F0(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA1_F1(x,y,z)  ((x) ^ (y) ^ (z))
#define SHA1_F2(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA1_F0o(x,y,z) (SHA1_F0 ((x), (y), (z)))
#define SHA1_F2o(x,y,z) (SHA1_F2 ((x), (y), (z)))

#define SHA1_STEP_S(f,a,b,c,d,e,x)  \
{                                   \
  e += K;                           \
  e += x;                           \
  e += f (b, c, d);                 \
  e += rotl32_S (a,  5u);           \
  b  = rotl32_S (b, 30u);           \
}

#define SHA1_STEP(f,a,b,c,d,e,x)    \
{                                   \
  e += K;                           \
  e += x;                           \
  e += f (b, c, d);                 \
  e += rotl32 (a,  5u);             \
  b  = rotl32 (b, 30u);             \
}

#define SHA1_STEP0(f,a,b,c,d,e,x)   \
{                                   \
  e += K;                           \
  e += f (b, c, d);                 \
  e += rotl32 (a,  5u);             \
  b  = rotl32 (b, 30u);             \
}

#define SHA1_STEPX(f,a,b,c,d,e,x)   \
{                                   \
  e += x;                           \
  e += f (b, c, d);                 \
  e += rotl32 (a,  5u);             \
  b  = rotl32 (b, 30u);             \
}

#define SHA1_STEP_PE(f,a,b,c,d,e,x) \
{                                   \
  e += x;                           \
  e += f (b, c, d);                 \
  e += rotl32 (a,  5u);             \
}

#define SHA1_STEP_PB(f,a,b,c,d,e,x) \
{                                   \
  e += K;                           \
  b  = rotl32 (b, 30u);             \
}

#define SHIFT_RIGHT_32(x,n) ((x) >> (n))

#define rotl32(x, n)  (((x) << (n)) | ((x) >> (32 - (n))))


typedef enum sha1_constants
{
  SHA1M_A=0x67452301,
  SHA1M_B=0xefcdab89,
  SHA1M_C=0x98badcfe,
  SHA1M_D=0x10325476,
  SHA1M_E=0xc3d2e1f0,

  SHA1C00=0x5a827999,
  SHA1C01=0x6ed9eba1,
  SHA1C02=0x8f1bbcdc,
  SHA1C03=0xca62c1d6u

} sha1_constants_t;

#endif
