/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef AIROHA_NPU_CRYPTO_PROFILE_H
#define AIROHA_NPU_CRYPTO_PROFILE_H
/* The final 256 bytes of each 64 KiB bounce slot are reserved for profiling. */
#define AIROHA_PROFILE_OFFSET 65280
#define AIROHA_PROFILE_FLAG 0x40
#define AIROHA_PROFILE_FIELDS(X) \
 X(total) X(input_copy) X(output_copy) X(clear) \
 X(chacha) X(chacha_leader) X(chacha_wait) \
 X(poly) X(poly_leader) X(poly_wait)
struct airoha_profile_sample {
#define AIROHA_PROFILE_MEMBER(name) u32 name;
 AIROHA_PROFILE_FIELDS(AIROHA_PROFILE_MEMBER)
#undef AIROHA_PROFILE_MEMBER
};
#endif
