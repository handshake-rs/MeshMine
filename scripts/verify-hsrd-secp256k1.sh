#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VENDOR="$ROOT/hsrd/vendor/secp256k1"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/smoke.c" <<'C_EOF'
#include <stdio.h>
#include <string.h>
#include "secp256k1.h"

int main(void) {
  static const unsigned char public_key_bytes[33] = {
    0x02,0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,
    0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,
    0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98
  };
  static const unsigned char signature_bytes[64] = {
    0x91,0xc5,0xbd,0x51,0xba,0x17,0x51,0x34,0xee,0x4a,0x66,0x34,0xa9,
    0x3c,0x2f,0x5c,0xc3,0xae,0x8f,0xc9,0xba,0xc3,0xc9,0x8b,0x89,0x60,
    0x55,0xbf,0x0e,0x5c,0xf7,0x1c,0x44,0xf3,0xbb,0x8f,0x35,0xcd,0x8e,
    0x27,0x04,0xc3,0x63,0x0a,0xb1,0xa3,0xa9,0x24,0x75,0x50,0x23,0x16,
    0xd2,0x5c,0xb8,0xc1,0x66,0xd7,0x7b,0xda,0xd9,0xf3,0xa6,0xc9
  };
  unsigned char message[32];
  secp256k1_pubkey public_key;
  secp256k1_ecdsa_signature signature;
  secp256k1_context *context;

  memset(message, 0x42, sizeof(message));
  context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
  if (context == NULL)
    return 1;
  if (!secp256k1_ec_pubkey_parse(
        context,
        &public_key,
        public_key_bytes,
        sizeof(public_key_bytes)))
    return 2;
  if (!secp256k1_ecdsa_signature_parse_compact(
        context,
        &signature,
        signature_bytes))
    return 3;
  if (secp256k1_ecdsa_signature_normalize(context, NULL, &signature) != 0)
    return 4;
  if (!secp256k1_ecdsa_verify(context, &signature, message, &public_key))
    return 5;

  message[0] ^= 1;
  if (secp256k1_ecdsa_verify(context, &signature, message, &public_key))
    return 6;

  secp256k1_context_destroy(context);
  puts("vendored libsecp256k1 verification smoke passed");
  return 0;
}
C_EOF

cc \
  "$TMP/smoke.c" \
  "$VENDOR/src/secp256k1.c" \
  -I"$VENDOR" \
  -I"$VENDOR/include" \
  -I"$VENDOR/src" \
  -DUSE_NUM_NONE=1 \
  -DUSE_FIELD_INV_BUILTIN=1 \
  -DUSE_SCALAR_INV_BUILTIN=1 \
  -DECMULT_WINDOW_SIZE=15 \
  -DECMULT_GEN_PREC_BITS=4 \
  -DUSE_ENDOMORPHISM=1 \
  -DUSE_FORCE_WIDEMUL_INT128=1 \
  -std=c89 \
  -fvisibility=hidden \
  -Wno-unused-function \
  -o "$TMP/secp256k1-smoke"

"$TMP/secp256k1-smoke"
