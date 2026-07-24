// Copyright (c) MongoDB, Inc.
// SPDX-License-Identifier: SSPL-1.0

#include "mongo/crypto/hash_block.h"

#if defined(MONGO_CONFIG_SSL) && (MONGO_CONFIG_SSL_PROVIDER == MONGO_CONFIG_SSL_PROVIDER_OPENSSL) && \
    OPENSSL_VERSION_NUMBER > 0x30000000L
#include "mongo/util/assert_util.h"

#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

namespace mongo {
#if defined(MONGO_CONFIG_SSL) && MONGO_CONFIG_SSL_PROVIDER == MONGO_CONFIG_SSL_PROVIDER_OPENSSL && \
    OPENSSL_VERSION_NUMBER < 0x10100000L
namespace {
HMAC_CTX* HMAC_CTX_new() {
    void* ctx = OPENSSL_malloc(sizeof(HMAC_CTX));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(HMAC_CTX));
    }
    return static_cast<HMAC_CTX*>(ctx);
}

void HMAC_CTX_free(HMAC_CTX* ctx) {
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}
}  // namespace
#endif
#if defined(MONGO_CONFIG_SSL) && (MONGO_CONFIG_SSL_PROVIDER == MONGO_CONFIG_SSL_PROVIDER_OPENSSL)

#if OPENSSL_VERSION_NUMBER > 0x30000000L

namespace {
// Fetch the "HMAC" EVP_MAC once and leak it for the process lifetime, mirroring the
// EVP_MD singletons in sha_block_openssl.cpp.  EVP_MAC_fetch performs a provider
// lookup and HMAC is computed in tight loops (e.g. SCRAM's PBKDF2 iteration), so it
// must not be fetched per operation.
EVP_MAC* getHmacMac() {
    // The fetch and its check run once, on first use.  A NULL result means the active
    // OpenSSL provider does not supply HMAC (e.g. a FIPS provider is enforced but not
    // installed); fail with a clear message instead of a later NULL-pointer dereference
    // in EVP_MAC_init, mirroring OpenSSLHashLoader's diagnostic in sha_block_openssl.cpp.
    static EVP_MAC* mac = [] {
        EVP_MAC* m = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        fassert(11319401,
                Status(m ? ErrorCodes::OK : ErrorCodes::InternalError,
                       "Failed to fetch OpenSSL HMAC implementation. This may be caused by "
                       "running in an environment where FIPS mode is enforced but the OpenSSL "
                       "library in use does not have a FIPS provider installed."));
        return m;
    }();
    return mac;
}
}  // namespace

int HmacContext::hmacCtxInitFn(const EVP_MD* md, const uint8_t* key, size_t keyLen) {
    int ret;
    if (getReuseKey() && useCount() >= 1) {
        // A NULL key and NULL params reuse the previously set key and digest.
        ret = EVP_MAC_init(get(), nullptr, 0, nullptr);
    } else {
        // EVP_MAC selects the digest by name; bridge the caller's fetched EVP_MD to its
        // name.  Only needed on the keyed init, not the reuse path above.
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST, const_cast<char*>(EVP_MD_get0_name(md)), 0);
        params[1] = OSSL_PARAM_construct_end();
        ret = EVP_MAC_init(get(), key, keyLen, params);
    }
    if (getReuseKey()) {
        use++;
    }
    return ret;
}

HmacContext::HmacContext() {
    hmac_ctx = EVP_MAC_CTX_new(getHmacMac());
}

HmacContext::~HmacContext() {
    EVP_MAC_CTX_free(hmac_ctx);
}

EVP_MAC_CTX* HmacContext::get() {
    return hmac_ctx;
}

#else  // OPENSSL_VERSION_NUMBER > 0x30000000L

int HmacContext::hmacCtxInitFn(const EVP_MD* md, const uint8_t* key, size_t keyLen) {
    int ret;
    if (getReuseKey() && useCount() >= 1) {
        ret = HMAC_Init_ex(get(), nullptr, 0, md, nullptr);
    } else {
        ret = HMAC_Init_ex(get(), key, keyLen, md, nullptr);
    }
    if (getReuseKey()) {
        use++;
    }
    return ret;
}

HmacContext::HmacContext() {
    hmac_ctx = HMAC_CTX_new();
};

HmacContext::~HmacContext() {
    HMAC_CTX_free(hmac_ctx);
}

HMAC_CTX* HmacContext::get() {
    return hmac_ctx;
}

#endif  // OPENSSL_VERSION_NUMBER > 0x30000000L

HashContext::HashContext() {
    _digestCtx = EVP_MD_CTX_new();
}

HashContext::~HashContext() {
    EVP_MD_CTX_free(_digestCtx);
}

EVP_MD_CTX* HashContext::get() {
    return _digestCtx;
}
#endif

void HmacContext::resetCount() {
    use = 0;
}

int HmacContext::useCount() {
    return use;
}

void HmacContext::setReuseKey(bool val) {
    _reuseKey = val;
    if (val == false) {
        resetCount();
    }
}

bool HmacContext::getReuseKey() {
    return _reuseKey;
}

}  // namespace mongo
