#include <basic/basic.c>
#include <sha256/sha256.c>
#include <hmac_sha256/hmac_sha256.c>
#include <hkdf_sha256/hkdf_sha256.c>
#include <curve25519/curve25519.c>
#include <chacha20_poly1305/chacha20_poly1305.c>
#include <ecdsa_secp256r1_sha256/ecdsa_secp256r1_sha256.c>
#include "tls.c"

struct client_ctx {
    tls_ctx tls;
};

#include "windows.c"

#define client_capacity 10
#define cargo_capacity 8192 
#define port "443" 