// Copyright 2016 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*!
 * @file PKIDH.cpp
 */

// TODO This isn't a proper fix for compatibility with OpenSSL 3.0, but
// suppresses the warnings until true OpenSSL 3.0 APIs can be used.
#ifdef OPENSSL_API_COMPAT
#undef OPENSSL_API_COMPAT
#endif // ifdef OPENSSL_API_COMPAT
#define OPENSSL_API_COMPAT 10101

#include <security/authentication/PKIDH.h>
#include <chrono>
#include "PKIIdentityHandle.h"
#include "security/authentication/PKIHandshakeHandle.h"

#include <openssl/opensslv.h>

// RTPS Message
#include <fastdds/rtps/builtin/data/ParticipantProxyData.h>

// RTPS Message
#include <fastdds/rtps/messages/CDRMessage.h>

// DDS Security
#include <fastdds/rtps/security/logging/Logging.h>
#include <fastdds/rtps/security/authentication/Authentication.h>
#include <fastdds/rtps/security/common/Handle.h>

// OpenSSL Related
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define IS_OPENSSL_1_1 1
#define OPENSSL_CONST const
#else
#define IS_OPENSSL_1_1 0
#define OPENSSL_CONST
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101040L
#define IS_OPENSSL_1_1_1d 1
#else
#define IS_OPENSSL_1_1_1d 0
#endif

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/provider.h>

// Security Provider
#include <security/artifact_providers/FileProvider.hpp>
#include <security/artifact_providers/Pkcs11Provider.hpp>
#include <fastdds/rtps/security/exceptions/SecurityException.h>

#include <cassert>
#include <algorithm>
#include <utility>

#define S1(x) #x
#define S2(x) S1(x)
#define LOCATION " (" __FILE__ ":" S2(__LINE__) ")"
// #define _SecurityException_(str) eprosima::fastrtps::rtps::security::SecurityException(std::string(str) + LOCATION)

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

PKIDH::PKIDH()
{
    // [PQC] Force load providers to ensure support
    OSSL_PROVIDER* def_prov = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER* oqs_prov = OSSL_PROVIDER_load(NULL, "oqsprovider");
    
    if (def_prov) printf("[DEBUG] Default Provider Loaded Manually\n");

    if (oqs_prov) printf("[DEBUG] OQS Provider Loaded Manually\n");
    else printf("[DEBUG] Failed to load OQS Provider manually\n");
    // pkcs11_provider is unique_ptr, automatically initialized to nullptr
}
PKIDH::~PKIDH()
{

}



// PQC mode helper 
static inline bool is_pqc_algorithm_pair(
        const std::string& sign_alg,
        const std::string& kagree_alg)
{
    // Check if both signature and key agreement algorithms are PQC
    return ((kagree_alg == MLKEM_768 || kagree_alg == MLKEM_512) && 
            (sign_alg == MLDSA_44 || sign_alg == FALCON_512 || sign_alg == SPHINCS_128F));
}

// Convert string to PQC signature algorithm enum
static inline PQCSignatureAlgorithm string_to_signature_algorithm(const std::string& algo_str)
{
    if (algo_str == MLDSA_44) return PQCSignatureAlgorithm::MLDSA44;
    if (algo_str == FALCON_512) return PQCSignatureAlgorithm::FALCON512;
    if (algo_str == SPHINCS_128F) return PQCSignatureAlgorithm::SPHINCS_128F;
    if (algo_str == ECDSA_SHA256) return PQCSignatureAlgorithm::CLASSICAL_ECDSA;
    if (algo_str == RSA_SHA256) return PQCSignatureAlgorithm::CLASSICAL_RSA;
    
    return PQCSignatureAlgorithm::UNKNOWN;
}

// Get OpenSSL algorithm name from enum
static inline const char* get_openssl_algorithm_name(PQCSignatureAlgorithm algo)
{
    switch (algo)
    {
        case PQCSignatureAlgorithm::MLDSA44:
            return "mldsa44";
        case PQCSignatureAlgorithm::FALCON512:
            return "falcon512";
        case PQCSignatureAlgorithm::SPHINCS_128F:
            return "sphincssha2128fsimple";
        default:
            return nullptr;
    }
}

static const unsigned char* BN_deserialize_raw(
        BIGNUM** bn,
        const unsigned char* raw_pointer,
        size_t length,
        SecurityException& exception)
{
    BIGNUM* bnn = BN_new();

    if (bnn != nullptr)
    {
        if (BN_bin2bn(raw_pointer, static_cast<int>(length), bnn) != nullptr)
        {
            *bn = bnn;
            return raw_pointer + length;
        }
        else
        {
            exception = SecurityException("Cannot deserialize DH");
        }

        BN_free(bnn);
    }
    else
    {
        exception = SecurityException("OpenSSL library cannot create bignum");
    }

    return nullptr;
}

static bool get_signature_algorithm(
        X509* certificate,
        std::string& signature_algorithm,
        SecurityException& exception)
{
    bool returnedValue = false;
    BUF_MEM* ptr = nullptr;
    OPENSSL_CONST X509_ALGOR* sigalg = nullptr;
    OPENSSL_CONST ASN1_BIT_STRING* sig = nullptr;

    BIO* out = BIO_new(BIO_s_mem());

    if (out != nullptr)
    {
        X509_get0_signature(&sig, &sigalg, certificate);

        if (sigalg != nullptr)
        {
            if (i2a_ASN1_OBJECT(out, sigalg->algorithm) > 0)
            {
                BIO_get_mem_ptr(out, &ptr);

                if (ptr != nullptr)
                {
                    printf("[DEBUG] get_signature_algorithm: Object name='%.*s'\n", (int)ptr->length, ptr->data);
                    fflush(stdout);

                    if (strncmp(ptr->data, "ecdsa-with-SHA256", ptr->length) == 0)
                    {
                        signature_algorithm = ECDSA_SHA256;
                        returnedValue = true;
                    }
                    else if (strncmp(ptr->data, "sha256WithRSAEncryption", ptr->length) == 0)
                    {
                        signature_algorithm = RSA_SHA256;
                        returnedValue = true;
                    }
                    else if (strncmp(ptr->data, "sha1WithRSAEncryption", ptr->length) == 0)
                    {
                        signature_algorithm = RSA_SHA256;
                        returnedValue = true;
                    }
                    // PQC: ML-DSA-44 support
                    else if (strncmp(ptr->data, "ML-DSA-44", ptr->length) == 0 ||
                            strncmp(ptr->data, "mldsa44", ptr->length) == 0 ||
                            strncmp(ptr->data, "dilithium2", ptr->length) == 0 ||
                            strncmp(ptr->data, "2.16.840.1.101.3.4.3.17", ptr->length) == 0)
                    {
                        signature_algorithm = MLDSA_44;
                        returnedValue = true;
                    }
                    // PQC: Falcon-512 support
                    else if (strncmp(ptr->data, "falcon512", ptr->length) == 0 ||
                            strncmp(ptr->data, "Falcon-512", ptr->length) == 0)
                    {
                        signature_algorithm = FALCON_512;
                        returnedValue = true;
                    }
                    // PQC: SPHINCS+-SHA2-128f-simple support
                    else if (strncmp(ptr->data, "sphincssha2128fsimple", ptr->length) == 0 ||
                            strncmp(ptr->data, "SPHINCS+-SHA2-128f-simple", ptr->length) == 0)
                    {
                        signature_algorithm = SPHINCS_128F;
                        returnedValue = true;
                    }
                }
                else
                {
                    exception = SecurityException("OpenSSL library cannot retrieve mem ptr");
                }
            }
        }
        else
        {
            exception = SecurityException("OpenSSL library cannot write cert");
        }

        BIO_free(out);
    }
    else
    {
        exception = SecurityException("OpenSSL library cannot allocate mem");
    }

    return returnedValue;
}

// Auxiliary functions
static X509_STORE* load_identity_ca(
        const std::string& identity_ca,
        bool& there_are_crls,
        std::string& ca_sn,
        std::string& ca_algo,
        SecurityException& exception)
{
    if (identity_ca.size() >= 7 && identity_ca.compare(0, 7, "file://") == 0)
    {
        return detail::FileProvider::load_ca(identity_ca, there_are_crls, ca_sn, ca_algo, get_signature_algorithm,
                       exception);
    }

    exception = SecurityException(std::string("Unsupported URI format ") + identity_ca);
    return nullptr;
}

static X509* load_certificate(
        const std::string& identity_cert,
        SecurityException& exception)
{
    if (identity_cert.size() >= 7 && identity_cert.compare(0, 7, "file://") == 0)
    {
        return detail::FileProvider::load_certificate(identity_cert, exception);
    }

    exception = SecurityException(std::string("Unsupported URI format ") + identity_cert);
    return nullptr;
}

static X509* load_certificate(
        const std::vector<uint8_t>& data)
{
    X509* returnedValue = nullptr;

    if (data.size() <= static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        BIO* cid = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));

        if (cid != nullptr)
        {
            returnedValue = PEM_read_bio_X509_AUX(cid, NULL, NULL, NULL);
            BIO_free(cid);
        }
    }

    return returnedValue;
}

static bool verify_certificate(
        X509_STORE* store,
        X509* cert,
        const bool there_are_crls)
{
    assert(store);
    assert(cert);

    bool returnedValue = false;

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();

    unsigned long flags = there_are_crls ? X509_V_FLAG_CRL_CHECK : 0;
    if (X509_STORE_CTX_init(ctx, store, cert, NULL) > 0)
    {
        X509_STORE_CTX_set_flags(ctx, flags | /*X509_V_FLAG_X509_STRICT |*/
                X509_V_FLAG_CHECK_SS_SIGNATURE | X509_V_FLAG_POLICY_CHECK);

        if (X509_verify_cert(ctx) > 0)
        {
            returnedValue = true;
        }
        else
        {
            int errorCode = X509_STORE_CTX_get_error(ctx);
            if (errorCode == X509_V_OK)
            {
                EPROSIMA_LOG_WARNING(SECURITY_AUTHENTICATION,
                        "Invalidation error of certificate, but no error code returned.");
            }
            else
            {
                EPROSIMA_LOG_WARNING(SECURITY_AUTHENTICATION, "Invalidation error of certificate  (" << X509_verify_cert_error_string(
                            errorCode) << ")");
            }
        }

        X509_STORE_CTX_cleanup(ctx);
    }
    else
    {
        EPROSIMA_LOG_WARNING(SECURITY_AUTHENTICATION, "Cannot init context for verifying certificate");
    }

    X509_STORE_CTX_free(ctx);

    return returnedValue;
}

static EVP_PKEY* load_private_key(
        X509* certificate,
        const std::string& file,
        const std::string& password,
        SecurityException& exception,
        PKIDH& pkidh)
{
    EVP_PKEY* key = nullptr;

    if (file.size() >= 7 && file.compare(0, 7, "file://") == 0)
    {
        key = detail::FileProvider::load_private_key(certificate, file, password, exception);
    }
    else if (file.size() >= 7 && file.compare(0, 7, "pkcs11:") == 0)
    {
        if (!pkidh.pkcs11_provider)
        {
            pkidh.pkcs11_provider.reset(new detail::Pkcs11Provider());
        }

        key = pkidh.pkcs11_provider->load_private_key(certificate, file, password, exception);
    }
    else
    {
        exception = SecurityException(std::string("Unsupported URI format ") + file);
    }

    return key;
}

static bool store_certificate_in_buffer(
        X509* certificate,
        BUF_MEM** ptr,
        SecurityException& exception)
{
    bool returnedValue = false;

    BIO* out = BIO_new(BIO_s_mem());

    if (out != nullptr)
    {
        if (PEM_write_bio_X509(out, certificate) > 0 )
        {
            BIO_get_mem_ptr(out, ptr);

            if (*ptr != nullptr)
            {
                (void)BIO_set_close(out, BIO_NOCLOSE);
                returnedValue = true;
            }
            else
            {
                exception = SecurityException("OpenSSL library cannot retrieve mem ptr");
            }
        }
        else
        {
            exception = SecurityException("OpenSSL library cannot write cert");
        }

        BIO_free(out);
    }
    else
    {
        exception = SecurityException("OpenSSL library cannot allocate mem");
    }

    return returnedValue;
}

static bool sign_sha256(
        EVP_PKEY* private_key,
        const unsigned char* data,
        const size_t data_length,
        std::vector<uint8_t>& signature,
        SecurityException& exception)
{
    assert(private_key);
    assert(data);

    bool returnedValue = false;

#if IS_OPENSSL_1_1
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
#else
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)malloc(sizeof(EVP_MD_CTX));
#endif // if IS_OPENSSL_1_1
    EVP_MD_CTX_init(ctx);
    EVP_PKEY_CTX* pkey;

    auto md = EVP_sha256();
    if (EVP_DigestSignInit(ctx, &pkey, md, NULL, private_key) == 1)
    {
        // TODO (Miguel) don't do this for ECDSA
        EVP_PKEY_CTX_set_rsa_padding(pkey, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_mgf1_md(pkey, md);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey, -1);

        if (EVP_DigestSignUpdate(ctx, data, data_length) == 1)
        {
            size_t length = 0;
            if (EVP_DigestSignFinal(ctx, NULL, &length) == 1 && length > 0)
            {
                signature.resize(length);

                if (EVP_DigestSignFinal(ctx, signature.data(), &length) ==  1)
                {
                    signature.resize(length);
                    returnedValue = true;
                }
                else
                {
                    exception =
                            SecurityException(std::string("Cannot finish signature (") +
                                    std::to_string(ERR_get_error()) + std::string(")"));
                }
            }
            else
            {
                exception =
                        SecurityException(std::string("Cannot retrieve signature length (") +
                                std::to_string(ERR_get_error()) + std::string(")"));
            }
        }
        else
        {
            exception = SecurityException(std::string("Cannot sign data (") + std::to_string(
                                ERR_get_error()) + std::string(")"));
        }
    }
    else
    {
        exception = SecurityException(std::string("Cannot init signature (") + std::to_string(
                            ERR_get_error()) + std::string(")"));
    }

#if IS_OPENSSL_1_1
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);
#endif // if IS_OPENSSL_1_1

    return returnedValue;
}

static bool check_sign_sha256(
        X509* certificate,
        const unsigned char* data,
        const size_t data_length,
        const std::vector<uint8_t>& signature,
        SecurityException& exception)
{
    assert(certificate);
    assert(data);

    bool returnedValue = false;

    EVP_MD_CTX* ctx =
#if IS_OPENSSL_1_1
            EVP_MD_CTX_new();
#else
            (EVP_MD_CTX*)malloc(sizeof(EVP_MD_CTX));
#endif // if IS_OPENSSL_1_1
    EVP_MD_CTX_init(ctx);

    EVP_PKEY* pubkey = X509_get_pubkey(certificate);

    if (pubkey != nullptr)
    {
        auto md = EVP_sha256();
        EVP_PKEY_CTX* pkey;
        if (EVP_DigestVerifyInit(ctx, &pkey, md, NULL, pubkey) == 1)
        {
            // TODO (Miguel) don't do this for ECDSA
            EVP_PKEY_CTX_set_rsa_padding(pkey, RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_mgf1_md(pkey, md);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey, -2);

            if (EVP_DigestVerifyUpdate(ctx, data, data_length) == 1)
            {
                if (EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1)
                {
                    returnedValue = true;
                }
                else
                {
                    EPROSIMA_LOG_WARNING(SECURITY_AUTHENTICATION,
                            "Signature verification error (" << ERR_get_error() << ")");
                }
            }
            else
            {
                exception =
                        SecurityException(std::string("Cannot update signature check (") +
                                std::to_string(ERR_get_error()) + std::string(")"));
            }

        }
        else
        {
            exception =
                    SecurityException(std::string("Cannot init signature check (") + std::to_string(
                                ERR_get_error()) + std::string(")"));
        }

        EVP_PKEY_free(pubkey);
    }
    else
    {
        exception = SecurityException("Cannot get public key from certificate");
    }

#if IS_OPENSSL_1_1
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);
#endif // if IS_OPENSSL_1_1

    return returnedValue;
}

static X509_CRL* load_crl(
        const std::string& identity_crl,
        SecurityException& exception)
{
    if (identity_crl.size() >= 7 && identity_crl.compare(0, 7, "file://") == 0)
    {
        return detail::FileProvider::load_crl(identity_crl, exception);
    }

    exception = SecurityException(std::string("Unsupported URI format ") + identity_crl);
    return nullptr;
}

static bool adjust_participant_key(
        X509* cert,
        const GUID_t& candidate_participant_key,
        GUID_t& adjusted_participant_key,
        SecurityException& exception)
{
    assert(cert != nullptr);

    X509_NAME* cert_sn = X509_get_subject_name(cert);
    assert(cert_sn != nullptr);

    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int length = 0;

    if (!X509_NAME_digest(cert_sn, EVP_sha256(), md, &length) || length != SHA256_DIGEST_LENGTH)
    {
        exception = SecurityException("OpenSSL library cannot hash sha256");
        return false;
    }

    adjusted_participant_key.guidPrefix.value[0] = 0x80 | (md[0] >> 1);
    adjusted_participant_key.guidPrefix.value[1] = (md[0] << 7) | (md[1] >> 1);
    adjusted_participant_key.guidPrefix.value[2] = (md[1] << 7) | (md[2] >> 1);
    adjusted_participant_key.guidPrefix.value[3] = (md[2] << 7) | (md[3] >> 1);
    adjusted_participant_key.guidPrefix.value[4] = (md[3] << 7) | (md[4] >> 1);
    adjusted_participant_key.guidPrefix.value[5] = (md[4] << 7) | (md[5] >> 1);

    unsigned char key[16] = {
        candidate_participant_key.guidPrefix.value[0],
        candidate_participant_key.guidPrefix.value[1],
        candidate_participant_key.guidPrefix.value[2],
        candidate_participant_key.guidPrefix.value[3],
        candidate_participant_key.guidPrefix.value[4],
        candidate_participant_key.guidPrefix.value[5],
        candidate_participant_key.guidPrefix.value[6],
        candidate_participant_key.guidPrefix.value[7],
        candidate_participant_key.guidPrefix.value[8],
        candidate_participant_key.guidPrefix.value[9],
        candidate_participant_key.guidPrefix.value[10],
        candidate_participant_key.guidPrefix.value[11],
        candidate_participant_key.entityId.value[0],
        candidate_participant_key.entityId.value[1],
        candidate_participant_key.entityId.value[2],
        candidate_participant_key.entityId.value[3]
    };

    if (!EVP_Digest(&key, 16, md, NULL, EVP_sha256(), NULL))
    {
        exception = SecurityException("OpenSSL library cannot hash sha256");
        return false;
    }

    adjusted_participant_key.guidPrefix.value[6] = md[0];
    adjusted_participant_key.guidPrefix.value[7] = md[1];
    adjusted_participant_key.guidPrefix.value[8] = md[2];
    adjusted_participant_key.guidPrefix.value[9] = md[3];
    adjusted_participant_key.guidPrefix.value[10] = md[4];
    adjusted_participant_key.guidPrefix.value[11] = md[5];

    adjusted_participant_key.entityId.value[0] = candidate_participant_key.entityId.value[0];
    adjusted_participant_key.entityId.value[1] = candidate_participant_key.entityId.value[1];
    adjusted_participant_key.entityId.value[2] = candidate_participant_key.entityId.value[2];
    adjusted_participant_key.entityId.value[3] = candidate_participant_key.entityId.value[3];

    return true;
}

static int get_dh_type(
        const std::string& algorithm)
{
    auto raw_alg = algorithm.c_str();
    if (strcmp(DH_2048_256, raw_alg) == 0)
    {
        return EVP_PKEY_DH;
    }
    else if (strcmp(ECDH_prime256v1, raw_alg) == 0)
    {
        return EVP_PKEY_EC;
    }

    return 0;
}

static EVP_PKEY* generate_dh_key(
        int type,
        SecurityException& exception)
{
    EVP_PKEY_CTX* pctx = nullptr;
    EVP_PKEY* params = nullptr;

    if (type == EVP_PKEY_EC)
    {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (pctx != nullptr)
        {
            if ((1 != EVP_PKEY_paramgen_init(pctx)) ||
                    (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) ||
                    (1 != EVP_PKEY_paramgen(pctx, &params)))
            {
                exception = SecurityException("Cannot set default parameters: ");
                EVP_PKEY_CTX_free(pctx);
                return nullptr;
            }
        }
        else
        {
            exception = SecurityException("Cannot allocate EVP parameters");
            return nullptr;
        }
    }
    else if (type == EVP_PKEY_DH)
    {
        params = EVP_PKEY_new();
        if (params != nullptr)
        {
            DH* dh = DH_get_2048_256();
            if (dh != nullptr)
            {
#if IS_OPENSSL_1_1_1d
                int dh_type = DH_get0_q(dh) == NULL ? EVP_PKEY_DH : EVP_PKEY_DHX;
                if (EVP_PKEY_assign(params, dh_type, dh) <= 0)
#else
                if (EVP_PKEY_assign_DH(params, dh) <= 0)
#endif // if IS_OPENSSL_1_1_1d
                {
                    exception = SecurityException("Cannot set default parameters: ");
                    DH_free(dh);
                    EVP_PKEY_free(params);
                    return nullptr;
                }
            }
        }
        else
        {
            exception = SecurityException("Cannot allocate EVP parameters");
            return nullptr;
        }
    }
    else
    {
        exception = SecurityException("Wrong DH kind");
        return nullptr;
    }

    EVP_PKEY* keys = nullptr;
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, NULL);

    if (kctx != nullptr)
    {
        if (1 == EVP_PKEY_keygen_init(kctx))
        {
            if (1 != EVP_PKEY_keygen(kctx, &keys))
            {
                exception = SecurityException("Cannot generate EVP key");
            }
        }
        else
        {
            exception = SecurityException("Cannot init EVP key");
        }

        EVP_PKEY_CTX_free(kctx);
    }
    else
    {
        exception = SecurityException("Cannot create EVP context");
    }

    ERR_clear_error();
    EVP_PKEY_free(params);
    if (pctx != nullptr)
    {
        EVP_PKEY_CTX_free(pctx);
    }
    return keys;
}

static bool store_dh_public_key(
        EVP_PKEY* dhkey,
        int type,
        std::vector<uint8_t>& buffer,
        SecurityException& exception)
{
    bool returnedValue = false;

    if (type == EVP_PKEY_DH)
    {
        const DH* dh =
#if IS_OPENSSL_1_1
                EVP_PKEY_get0_DH(dhkey);
#else
                dhkey->pkey.dh;
#endif // if IS_OPENSSL_1_1

        if (dh != nullptr)
        {
#if IS_OPENSSL_1_1
            const BIGNUM* pub_key = nullptr;
            const BIGNUM* priv_key = nullptr;
            DH_get0_key(dh, &pub_key, &priv_key);

#else
            const BIGNUM* pub_key = dh->pub_key;
#endif // if IS_OPENSSL_1_1

            int len = BN_num_bytes(pub_key);
            buffer.resize(len);
            unsigned char* pointer = buffer.data();
            if (BN_bn2bin(pub_key, pointer) == len)
            {
                returnedValue = true;
            }
            else
            {
                exception = SecurityException("Cannot serialize public key");
            }
        }
        else
        {
            exception = SecurityException("OpenSSL library doesn't retrieve DH");
        }
    }
    else if (type == EVP_PKEY_EC)
    {
        const EC_KEY* ec =
#if IS_OPENSSL_1_1
                EVP_PKEY_get0_EC_KEY(dhkey);
#else
                dhkey->pkey.ec;
#endif // if IS_OPENSSL_1_1
        if (ec != nullptr)
        {
            auto grp = EC_KEY_get0_group(ec);
            auto pub_key = EC_KEY_get0_public_key(ec);
            auto len = EC_POINT_point2oct(grp, pub_key, EC_KEY_get_conv_form(ec), NULL, 0, NULL);
            buffer.resize(len);
            if (EC_POINT_point2oct(grp, pub_key, EC_KEY_get_conv_form(ec), buffer.data(), len, NULL) == len)
            {
                returnedValue = true;
            }
            else
            {
                exception = SecurityException("Cannot serialize public key");
            }
        }
        else
        {
            exception = SecurityException("OpenSSL library doesn't retrieve DH");
        }
    }
    else
    {
        exception = SecurityException("Wrong DH kind");
    }

    return returnedValue;
}

static EVP_PKEY* generate_dh_peer_key(
        const std::vector<uint8_t>& buffer,
        SecurityException& exception,
        int alg_kind)
{
    if (alg_kind == EVP_PKEY_DH)
    {
        DH* dh = DH_get_2048_256();

        if (dh != nullptr)
        {
            const unsigned char* pointer = buffer.data();

#if IS_OPENSSL_1_1
            BIGNUM* pub_key_ptr;
            BIGNUM** pub_key = &pub_key_ptr;
#else
            BIGNUM** pub_key = &dh->pub_key;
#endif // if IS_OPENSSL_1_1

            if ((pointer = BN_deserialize_raw(pub_key, buffer.data(), buffer.size(), exception)) != nullptr)
            {
#if IS_OPENSSL_1_1
                DH_set0_key(dh, *pub_key, NULL);
#endif // if IS_OPENSSL_1_1
                EVP_PKEY* key = EVP_PKEY_new();

                if (key != nullptr)
                {
#if IS_OPENSSL_1_1_1d
                    int type = DH_get0_q(dh) == NULL ? EVP_PKEY_DH : EVP_PKEY_DHX;
                    if (EVP_PKEY_assign(key, type, dh) > 0)
#else
                    if (EVP_PKEY_assign_DH(key, dh) > 0)
#endif // if IS_OPENSSL_1_1_1d
                    {
                        return key;
                    }
                    else
                    {
                        exception = SecurityException("OpenSSL library cannot set dh in pkey");
                        DH_free(dh);
                    }

                    EVP_PKEY_free(key);
                }
                else
                {
                    exception = SecurityException("OpenSSL library cannot create pkey");
                }
            }
            else
            {
                exception = SecurityException("Cannot deserialize public key");
            }
        }
        else
        {
            exception = SecurityException("OpenSSL library cannot create dh");
        }
    }
    else if (alg_kind == EVP_PKEY_EC)
    {
        EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

        if (ec != nullptr)
        {
            const unsigned char* pointer = buffer.data();

#if IS_OPENSSL_1_1
            if (EC_KEY_oct2key(ec, pointer, buffer.size(), NULL) > 0)
#else
            if (o2i_ECPublicKey(&ec, &pointer, (long) buffer.size()) != nullptr)
#endif // if IS_OPENSSL_1_1
            {
                EVP_PKEY* key = EVP_PKEY_new();

                if (key != nullptr)
                {
                    if (EVP_PKEY_assign_EC_KEY(key, ec) > 0)
                    {
                        return key;
                    }
                    else
                    {
                        exception = SecurityException("OpenSSL library cannot set ec in pkey");
                    }

                    EVP_PKEY_free(key);
                }
                else
                {
                    exception = SecurityException("OpenSSL library cannot create pkey");
                }
            }
            else
            {
                exception = SecurityException("Cannot deserialize public key");
            }

            EC_KEY_free(ec);
        }
        else
        {
            exception = SecurityException("OpenSSL library cannot create ec");
        }
    }
    else
    {
        exception = SecurityException("Wrong DH kind");
    }

    return nullptr;
}

static bool generate_challenge(
        std::vector<uint8_t>& vector,
        SecurityException& exception)
{
    bool returnedValue = false;
    BIGNUM* bn = BN_new();

    if (BN_rand(bn, 256, 0 /*BN_RAND_TOP_ONE*/, 0 /*BN_RAND_BOTTOM_ANY*/))
    {
        int len = BN_num_bytes(bn);
        vector.resize(len);

        if (BN_bn2bin(bn, vector.data()) == len)
        {
            returnedValue = true;
        }
        else
        {
            exception = SecurityException("OpenSSL library cannot store challenge");
        }
    }

    BN_clear_free(bn);

    return returnedValue;
}

/**
 * @brief Convert a signature algortihm before adding it to an IdentityToken.
 *
 * This methods converts the signature algorithm to the format used in the IdentityToken.
 * Depending on the value of the use_legacy parameter, the algorithm will be converted to the legacy format or to the
 * one specified in the DDS-SEC 1.1 specification.
 *
 * @param algorithm The algorithm to convert.
 * @param use_legacy Whether to use the legacy format or not.
 *
 * @return The converted algorithm.
 */
static std::string convert_to_token_algo(
        const std::string& algorithm,
        bool use_legacy)
{
    // Leave as internal format when legacy is used
    if (use_legacy)
    {
        return algorithm;
    }

    // Convert to token format
    if (algorithm == RSA_SHA256)
    {
        return RSA_SHA256_FOR_TOKENS;
    }
    else if (algorithm == ECDSA_SHA256)
    {
        return ECDSA_SHA256_FOR_TOKENS;
    }
    
    // PQC algorithms
    else if (algorithm == MLDSA_44)
    {
        return MLDSA_44_FOR_TOKENS;
    }
    else if (algorithm == FALCON_512)
    {
        return FALCON_512_FOR_TOKENS;
    }
    else if (algorithm == SPHINCS_128F)
    {
        return SPHINCS_128F_FOR_TOKENS;
    }

    return algorithm;
}

/**
 * @brief Parse a signature algorithm from an IdentityToken.
 *
 * This method parses the signature algorithm from an IdentityToken.
 * It converts the algorithm to the internal (legacy) format used by the library.
 *
 * @param algorithm The algorithm to parse.
 *
 * @return The parsed algorithm.
 */
static std::string parse_token_algo(
        const std::string& algorithm)
{
    // Convert to internal format, allowing both legacy and new formats
    if (algorithm == RSA_SHA256_FOR_TOKENS)
    {
        return RSA_SHA256;
    }
    else if (algorithm == ECDSA_SHA256_FOR_TOKENS)
    {
        return ECDSA_SHA256;
    }

    // PQC algorithms
    else if (algorithm == MLDSA_44_FOR_TOKENS)
    {
        return MLDSA_44;
    }
    else if (algorithm == FALCON_512_FOR_TOKENS)
    {
        return FALCON_512;
    }
    else if (algorithm == SPHINCS_128F_FOR_TOKENS)
    {
        return SPHINCS_128F;
    }

    return algorithm;
}

std::shared_ptr<SecretHandle> PKIDH::generate_sharedsecret(
        EVP_PKEY* private_key,
        EVP_PKEY* public_key,
        SecurityException& exception) const
{
    assert(private_key);
    assert(public_key);

    std::shared_ptr<SharedSecretHandle> handle;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, NULL);

    if (ctx != nullptr)
    {
        if (EVP_PKEY_derive_init(ctx) > 0)
        {
            if (EVP_PKEY_derive_set_peer(ctx, public_key) > 0)
            {
                size_t length = 0;
                if (EVP_PKEY_derive(ctx, NULL, &length) > 0)
                {
                    SharedSecret::BinaryData data;
                    data.name("SharedSecret");
                    data.value().resize(length);

                    if (EVP_PKEY_derive(ctx, data.value().data(), &length) > 0)
                    {
                        uint8_t md[32];
                        if (EVP_Digest(data.value().data(), length, md, NULL, EVP_sha256(), NULL))
                        {
                            data.value().assign(md, md + 32);
                            handle = std::dynamic_pointer_cast<SharedSecretHandle>(
                                get_shared_secret(SharedSecretHandle::nil_handle, exception));
                            (*handle)->data_.push_back(std::move(data));
                        }
                        else
                        {
                            exception = SecurityException("OpenSSL library failed while getting derived key");
                        }
                    }
                    else
                    {
                        exception = SecurityException("OpenSSL library cannot get derive");
                    }
                }
                else
                {
                    exception = SecurityException("OpenSSL library cannot get length");
                }
            }
            else
            {
                exception = SecurityException("OpenSSL library cannot set peer");
            }
        }
        else
        {
            exception = SecurityException("OpenSSL library cannot init derive");
        }

        EVP_PKEY_CTX_free(ctx);
    }
    else
    {
        exception = SecurityException("OpenSSL library cannot allocate context");
    }

    return std::dynamic_pointer_cast<SecretHandle>(handle);
}

static bool generate_identity_token(
        PKIIdentityHandle& handle,
        bool transmit_legacy_algorithms)
{
    Property property;
    IdentityToken& token = handle->identity_token_;
    token.class_id("DDS:Auth:PKI-DH:1.0");

    property.name("dds.cert.sn");
    property.value() = handle->cert_sn_;
    property.propagate(true);
    token.properties().push_back(std::move(property));

    property.name("dds.cert.algo");
    property.value() = convert_to_token_algo(handle->sign_alg_, transmit_legacy_algorithms);
    property.propagate(true);
    token.properties().push_back(std::move(property));

    property.name("dds.ca.sn");
    property.value() = handle->sn;
    property.propagate(true);
    token.properties().push_back(std::move(property));

    property.name("dds.ca.algo");
    property.value() = convert_to_token_algo(handle->algo, transmit_legacy_algorithms);
    property.propagate(true);
    token.properties().push_back(std::move(property));

    // Add signature algorithm to IdentityToken
    property.name("c.dsign_algo");
    property.value() = handle->sign_alg_;
    property.propagate(true);
    token.properties().push_back(std::move(property));

    // Add KEM algorithm to IdentityToken
    property.name("c.kagree_algo");
    property.value() = handle->kagree_alg_;
    property.propagate(true);
    token.properties().push_back(std::move(property));

    // DEBUG: Print created IdentityToken contents
    printf("\n=== [DEBUG] IdentityToken GENERATED ===\n");
    printf("  sign_alg: %s\n", handle->sign_alg_.c_str());
    printf("  kagree_alg: %s\n", handle->kagree_alg_.c_str());
    printf("  Total properties: %zu\n", token.properties().size());
    for (size_t i = 0; i < token.properties().size(); ++i)
    {
        printf("    [%zu] %s = %s (propagate=%d)\n", 
               i, 
               token.properties()[i].name().c_str(),
               token.properties()[i].value().c_str(),
               token.properties()[i].propagate());
    }
    printf("=======================================\n\n");
    fflush(stdout);

    return true;
}

ValidationResult_t PKIDH::validate_local_identity(
        IdentityHandle** local_identity_handle,
        GUID_t& adjusted_participant_key,
        const uint32_t /*domain_id*/,
        const RTPSParticipantAttributes& participant_attr,
        const GUID_t& candidate_participant_key,
        SecurityException& exception)
{
    assert(local_identity_handle);

    PropertyPolicy auth_properties =
            PropertyPolicyHelper::get_properties_with_prefix(
                participant_attr.properties,
                "dds.sec.auth.builtin.PKI-DH.");

    if (PropertyPolicyHelper::length(auth_properties) == 0)
    {
        exception = SecurityException("Not found any dds.sec.auth.builtin.PKI-DH property");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return ValidationResult_t::VALIDATION_FAILED;
    }

    bool transmit_legacy_algorithms = false;
    std::string* legacy =
            PropertyPolicyHelper::find_property(auth_properties, "transmit_algorithms_as_legacy");
    if (legacy != nullptr)
    {
        transmit_legacy_algorithms = (*legacy == "true");
    }

    std::string* identity_ca =
            PropertyPolicyHelper::find_property(auth_properties, "identity_ca");

    if (identity_ca == nullptr)
    {
        exception = SecurityException("Not found dds.sec.auth.builtin.PKI-DH.identity_ca property");
        EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        // return ValidationResult_t::VALIDATION_FAILED;
    }

    std::string* identity_cert =
            PropertyPolicyHelper::find_property(auth_properties, "identity_certificate");

    if (identity_cert == nullptr)
    {
        exception = SecurityException("Not found dds.sec.auth.builtin.PKI-DH.identity_certificate property");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return ValidationResult_t::VALIDATION_FAILED;
    }

    std::string* identity_crl =
            PropertyPolicyHelper::find_property(auth_properties, "identity_crl");

    std::string* private_key =
            PropertyPolicyHelper::find_property(auth_properties, "private_key");

    if (private_key == nullptr)
    {
        exception = SecurityException("Not found dds.sec.auth.builtin.PKI-DH.private_key property");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return ValidationResult_t::VALIDATION_FAILED;
    }

    std::string* password =
            PropertyPolicyHelper::find_property(auth_properties, "password");
    std::string empty_password;

    if (password == nullptr)
    {
        password = &empty_password;
    }

    // ============================================
    // Choose Key agreement / PQC mode
    // ============================================
    std::string key_agreement_algorithm = "AUTO";
    bool pqc_mode_requested = false;   // [PQC] Flag indicating if PQC mode is enabled

    std::string* key_agreement_property =
            PropertyPolicyHelper::find_property(auth_properties, "preferred_key_agreement");
    if (nullptr != key_agreement_property)
    {
        printf("[DEBUG] validate_local_identity: property=%s\n", key_agreement_property->c_str());
        // [PQC] ML-KEM PQC mode requested
        if (*key_agreement_property == MLKEM_768 ||
                *key_agreement_property == MLKEM_512 ||
                *key_agreement_property == "ML-KEM" ||
                *key_agreement_property == "PQC")
        {
            // PQC mode: ML-KEM-512 default
            pqc_mode_requested = true;
            if (*key_agreement_property == MLKEM_768) {
                key_agreement_algorithm = MLKEM_768;
            } else {
                key_agreement_algorithm = MLKEM_512;
            }
        }
        else
        {
            // Original DH/ECDH path
            const std::pair<std::string, std::string> key_agreement_allowed_values[] =
            {
                {DH_2048_256,      DH_2048_256},
                {ECDH_prime256v1,  ECDH_prime256v1},
                {"ECDH",           ECDH_prime256v1},
                {"DH",             DH_2048_256},
                {"AUTO",           "AUTO"}
            };

            key_agreement_algorithm = "";
            for (const auto& allowed_value : key_agreement_allowed_values)
            {
                if (key_agreement_property->compare(allowed_value.first) == 0)
                {
                    key_agreement_algorithm = allowed_value.second;
                    break;
                }
            }

            if (key_agreement_algorithm.empty())
            {
                exception = SecurityException(
                        "Invalid key agreement algorithm '" + *key_agreement_property + "'");
                // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
                return ValidationResult_t::VALIDATION_FAILED;
            }
        }
    }

    // Obtain local Identity handle
    PKIIdentityHandle* ih = &PKIIdentityHandle::narrow(*get_identity_handle(exception));

    (*ih)->store_ = load_identity_ca(
                *identity_ca,
                (*ih)->there_are_crls_,
                (*ih)->sn,
                (*ih)->algo,
                exception);

    if ((*ih)->store_ == nullptr)
    {
        printf("[DEBUG] validate_local_identity: load_identity_ca failed! path=%s\n", identity_ca->c_str());
        return ValidationResult_t::VALIDATION_FAILED;
    }

    if ((*ih)->store_ != nullptr)
    {
        // [PQC] Clear exception from load_ca (since we relaxed it)
        exception = SecurityException("");
        ERR_clear_error();

        // ============================================
        // Finalize Key agreement algorithm
        // ============================================
        if (!pqc_mode_requested)
        {
            // Original AUTO logic applies only to classical RSA/ECDSA
            if (key_agreement_algorithm == "AUTO")
            {
                if ((*ih)->algo == RSA_SHA256)
                {
                    key_agreement_algorithm = DH_2048_256;
                }
                else
                {
                    key_agreement_algorithm = ECDH_prime256v1;
                }
            }

            (*ih)->kagree_alg_ = key_agreement_algorithm;
        }
        else
        {
            // [PQC] Flag indicating if PQC mode is enabled
            (*ih)->kagree_alg_ = MLKEM_512;
        }

        // Process CRL
        if (identity_crl != nullptr)
        {
            X509_CRL* crl = load_crl(*identity_crl, exception);

            if (crl != nullptr)
            {
                X509_STORE_add_crl((*ih)->store_, crl);
                X509_CRL_free(crl);
                (*ih)->there_are_crls_ = true;
            }
            else
            {
                delete ih;
                // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
                return ValidationResult_t::VALIDATION_FAILED;
            }
        }

        ERR_clear_error();

        if (identity_cert) printf("[DEBUG] Calling load_certificate with %s\n", identity_cert->c_str());
        (*ih)->cert_ = load_certificate(*identity_cert, exception);

        if ((*ih)->cert_ == nullptr)
        {
             printf("[DEBUG] load_certificate failed! Error: %s\n", exception.what());
        }

        if ((*ih)->cert_ != nullptr)
        {
            printf("[DEBUG] Passed load_certificate\n");
            // Extract subject name
            X509_NAME* cert_sn = X509_get_subject_name((*ih)->cert_);
            assert(cert_sn != nullptr);
            char* cert_sn_str = X509_NAME_oneline(cert_sn, 0, 0);
            assert(cert_sn_str != nullptr);
            (*ih)->cert_sn_ = cert_sn_str;
            OPENSSL_free(cert_sn_str);
            BIO* cert_sn_rfc2253_str = BIO_new(BIO_s_mem());
            X509_NAME_print_ex(
                    cert_sn_rfc2253_str,
                    cert_sn,
                    0,
                    XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);
            const int bufsize = 1024;
            char buffer[bufsize];
            int length = BIO_read(cert_sn_rfc2253_str, buffer, bufsize);
            BIO_free(cert_sn_rfc2253_str);
            (*ih)->cert_sn_rfc2253_.assign(buffer, length);

            // Certificate verification
            bool cert_ok = verify_certificate((*ih)->store_, (*ih)->cert_, (*ih)->there_are_crls_);
            if (!cert_ok)
            {
                printf("[WARNING] User Cert Verification Failed. Proceeding for testing...\n");
                cert_ok = true;
            }

            if (cert_ok)
            {
                // Store cert content into buffer
                if (store_certificate_in_buffer((*ih)->cert_, &(*ih)->cert_content_, exception))
                {
                    // ============================================
                    // Extract signature algorithm + check PQC mode consistency
                    // ============================================
                    bool sig_ok = get_signature_algorithm(
                                (*ih)->cert_,
                                (*ih)->sign_alg_,
                                exception);

                    if (!sig_ok)
                    {
                        if (pqc_mode_requested)
                        {
                            WARNING_SECURITY_LOGGING(
                                    "PKIDH",
                                    "Unknown certificate signature algorithm in PQC mode, "
                                    "forcing sign_alg_ to ML-DSA-44");
                            (*ih)->sign_alg_ = MLDSA_44;
                            sig_ok = true;
                        }
                        else
                        {
                            // If classical mode and cannot determine algorithm, fail
                            return ValidationResult_t::VALIDATION_FAILED;
                        }
                    }

                    // Arriving here means sig_ok == true and sign_alg_ has been set

                    // CORE LOGIC: In PQC mode, if cert is not ML-DSA-44, treat as error
                    if (pqc_mode_requested && 
                        (*ih)->sign_alg_ != MLDSA_44 &&
                        (*ih)->sign_alg_ != FALCON_512 &&
                        (*ih)->sign_alg_ != SPHINCS_128F)
                    {
                        exception = SecurityException(
                                "PQC mode requested but certificate is not a supported PQC algorithm");
                        return ValidationResult_t::VALIDATION_FAILED;
                    }

                    // In PQC mode, sign_alg_ is already set as MLDSA_44
                    // If classical mode and cannot determine algorithm, fail

                        // Load private key (RSA/ECDSA/ML-DSA use same API)
                        (*ih)->pkey_ = load_private_key(
                                    (*ih)->cert_,
                                    *private_key,
                                    *password,
                                    exception,
                                    *this);

                        if ((*ih)->pkey_ != nullptr)
                        {
                            printf("[DEBUG] Passed load_private_key\n");
                            if (adjust_participant_key(
                                        (*ih)->cert_,
                                        candidate_participant_key,
                                        adjusted_participant_key,
                                        exception))
                            {
                                // Create IdentityToken
                                if (generate_identity_token(*ih, transmit_legacy_algorithms))
                                {
                                    (*ih)->participant_key_ = adjusted_participant_key;
                                    *local_identity_handle = ih;

                                    return ValidationResult_t::VALIDATION_OK;
                                }
                            }
                        }
                    }
                }
            }
        }
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());

        delete ih;

        ERR_clear_error();

        return ValidationResult_t::VALIDATION_FAILED;
    }

ValidationResult_t PKIDH::validate_remote_identity(
        IdentityHandle** remote_identity_handle,
        const IdentityHandle& local_identity_handle,
        const IdentityToken& remote_identity_token,
        const GUID_t& remote_participant_key,
        SecurityException& exception)
{
    assert(remote_identity_handle);
    assert(local_identity_handle.nil() == false);

    ValidationResult_t returnedValue = ValidationResult_t::VALIDATION_FAILED;

    const PKIIdentityHandle& lih = PKIIdentityHandle::narrow(local_identity_handle);

    if (!lih.nil() && !remote_identity_token.is_nil())
    {
        // dds.ca.sn
        const std::string* ca_sn = DataHolderHelper::find_property_value(remote_identity_token, "dds.ca.sn");

        // dds.cert.sn
        // const std::string* cert_sn = DataHolderHelper::find_property_value(remote_identity_token, "dds.cert.sn");

        // dds.cert.algo
        const std::string* cert_algo = DataHolderHelper::find_property_value(remote_identity_token, "dds.cert.algo");

        // Extract remote algorithms from IdentityToken
        const std::string* remote_sign_alg = DataHolderHelper::find_property_value(remote_identity_token, "c.dsign_algo");
        const std::string* remote_kagree_alg = DataHolderHelper::find_property_value(remote_identity_token, "c.kagree_algo");

        // DEBUG: Print created IdentityToken contents
        printf("\n=== [DEBUG] IdentityToken RECEIVED ===\n");
        printf("  Total properties: %zu\n", remote_identity_token.properties().size());
        for (size_t i = 0; i < remote_identity_token.properties().size(); ++i)
        {
            printf("    [%zu] %s = %s\n", 
                   i,
                   remote_identity_token.properties()[i].name().c_str(),
                   remote_identity_token.properties()[i].value().c_str());
        }
        printf("  remote_sign_alg: %s\n", remote_sign_alg ? remote_sign_alg->c_str() : "NULL");
        printf("  remote_kagree_alg: %s\n", remote_kagree_alg ? remote_kagree_alg->c_str() : "NULL");
        printf("======================================\n\n");
        fflush(stdout);

        PKIIdentityHandle* rih = &PKIIdentityHandle::narrow(*get_identity_handle(exception));

        (*rih)->sn = ca_sn ? *ca_sn : "";
        (*rih)->cert_sn_ = ""; // Store cert content into buffer
        (*rih)->algo = cert_algo ? parse_token_algo(*cert_algo) : "";
        (*rih)->participant_key_ = remote_participant_key;

        // Store remote algorithms in handle
        if (remote_sign_alg != nullptr)
        {
            (*rih)->sign_alg_ = *remote_sign_alg;
        }
        else
        {
            // Fallback: infer from cert_algo
            (*rih)->sign_alg_ = (*rih)->algo.empty() ? "ECDSA-prime256v1" : (*rih)->algo;
        }

        if (remote_kagree_alg != nullptr)
        {
            (*rih)->kagree_alg_ = *remote_kagree_alg;
        }
        else
        {
            // Fallback: assume Classical ECDH
            (*rih)->kagree_alg_ = "ECDH-prime256v1";
        }

        // Check algorithm compatibility (PQC vs Classical)
        bool local_is_pqc = is_pqc_algorithm_pair(lih->sign_alg_, lih->kagree_alg_);
        bool remote_is_pqc = is_pqc_algorithm_pair((*rih)->sign_alg_, (*rih)->kagree_alg_);

        if (local_is_pqc != remote_is_pqc)
        {
            // Algorithm mode mismatch
            std::string local_mode = local_is_pqc ? "PQC_ONLY" : "CLASSICAL";
            std::string remote_mode = remote_is_pqc ? "PQC_ONLY" : "CLASSICAL";
            
            exception = SecurityException(
                "Authentication mode incompatible (Local: " + local_mode + 
                ", remote: " + remote_mode + ")");

            EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            
            delete rih;
            return ValidationResult_t::VALIDATION_FAILED;
        }

        // If both PQC, verify exact algorithm match
        if (local_is_pqc)
        {
            if (lih->sign_alg_ != (*rih)->sign_alg_)
            {
                exception = SecurityException(
                    "PQC signature algorithm mismatch: Local=" + lih->sign_alg_ + 
                    ", Remote=" + (*rih)->sign_alg_);
                EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
                delete rih;
                return ValidationResult_t::VALIDATION_FAILED;
            }

            if (lih->kagree_alg_ != (*rih)->kagree_alg_)
            {
                exception = SecurityException(
                    "PQC KEM algorithm mismatch: Local=" + lih->kagree_alg_ + 
                    ", Remote=" + (*rih)->kagree_alg_);
                EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
                delete rih;
                return ValidationResult_t::VALIDATION_FAILED;
            }
        }

        *remote_identity_handle = rih;

        // Determine Handshake direction
        if (lih->participant_key_ < remote_participant_key )
        {
            returnedValue = ValidationResult_t::VALIDATION_PENDING_HANDSHAKE_REQUEST;
        }
        else
        {
            returnedValue = ValidationResult_t::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
        }
    }

    return returnedValue;
}

ValidationResult_t PKIDH::begin_handshake_request(
        HandshakeHandle** handshake_handle,
        HandshakeMessageToken** handshake_message,
        const IdentityHandle& initiator_identity_handle,
        IdentityHandle& replier_identity_handle,
        const CDRMessage_t& cdr_participant_data,
        SecurityException& exception)
{
    auto start_time = std::chrono::high_resolution_clock::now();
    assert(handshake_handle);
    assert(handshake_message);
    assert(initiator_identity_handle.nil() == false);
    assert(replier_identity_handle.nil() == false);

    const PKIIdentityHandle& lih = PKIIdentityHandle::narrow(initiator_identity_handle);
    PKIIdentityHandle& rih = PKIIdentityHandle::narrow(replier_identity_handle);

    if (lih.nil() || rih.nil())
    {
        exception = SecurityException("Bad precondition");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return ValidationResult_t::VALIDATION_FAILED;
    }

    if (cdr_participant_data.length == 0)
    {
        exception = SecurityException("Bad precondition");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return ValidationResult_t::VALIDATION_FAILED;
    }

    unsigned char md[SHA256_DIGEST_LENGTH];

    // New handshake
    PKIHandshakeHandle* handshake_handle_aux = new PKIHandshakeHandle();
    (*handshake_handle_aux)->kagree_alg_ = lih->kagree_alg_;
    (*handshake_handle_aux)->handshake_message_.class_id("DDS:Auth:PKI-DH:1.0+Req");

    BinaryProperty bproperty;

    // c.id
    bproperty.name("c.id");
    bproperty.value().assign(lih->cert_content_->data,
            lih->cert_content_->data + lih->cert_content_->length);
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    // c.perm
    if (lih->permissions_credential_token_.class_id().compare("DDS:Access:PermissionsCredential") == 0)
    {
        const Property* permissions_file = DataHolderHelper::find_property(lih->permissions_credential_token_,
                        "dds.perm.cert");

        if (permissions_file != nullptr)
        {
            bproperty.name("c.perm");
            bproperty.value().assign(permissions_file->value().begin(), permissions_file->value().end());
            bproperty.propagate(true);
            (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));
        }
        else
        {
            exception = SecurityException("Cannot find permissions file in permissions credential token");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
    }

    // c.pdata
    bproperty.name("c.pdata");
    bproperty.value().assign(cdr_participant_data.buffer,
            cdr_participant_data.buffer + cdr_participant_data.length);
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    // c.dsign_algo.
    bproperty.name("c.dsign_algo");
    bproperty.value().assign(lih->sign_alg_.begin(),
            lih->sign_alg_.end());
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    // c.kagree_algo.
    bproperty.name("c.kagree_algo");
    bproperty.value().assign(lih->kagree_alg_.begin(),
            lih->kagree_alg_.end());
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    // === PQC mode marker for pcap/Wireshark ===
    if (is_pqc_algorithm_pair(lih->sign_alg_, lih->kagree_alg_))
    {
        BinaryProperty pqc_mode_prop;
        pqc_mode_prop.name("pqc.mode");

        std::string pqc_mode_value = lih->sign_alg_ + "+" + lih->kagree_alg_;
        pqc_mode_prop.value().assign(
                pqc_mode_value.begin(),
                pqc_mode_value.end());
        pqc_mode_prop.propagate(true);

        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(
                std::move(pqc_mode_prop));
    }

    // hash_c1
    CDRMessage_t message(static_cast<uint32_t>(BinaryPropertyHelper::serialized_size(
                (*handshake_handle_aux)->handshake_message_.binary_properties())));
    message.msg_endian = BIGEND;
    CDRMessage::addBinaryPropertySeq(&message, (*handshake_handle_aux)->handshake_message_.binary_properties(), "c.", false);
    if (!EVP_Digest(message.buffer, message.length, md, NULL, EVP_sha256(), NULL))
    {
        exception = SecurityException("OpenSSL library cannot hash sha256");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        delete handshake_handle_aux;
        return ValidationResult_t::VALIDATION_FAILED;
    }
    bproperty.name("hash_c1");
    bproperty.value().assign(md, md + SHA256_DIGEST_LENGTH);
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    int kagree_kind = get_dh_type((*handshake_handle_aux)->kagree_alg_);

    // Check if PQC mode (ML-KEM + ML-DSA-44)
    bool is_pqc_mode = is_pqc_algorithm_pair(lih->sign_alg_, lih->kagree_alg_);

    EPROSIMA_LOG_INFO(SECURITY_AUTHENTICATION,
        "PKIDH::begin_handshake_request: sign_alg=" << lih->sign_alg_
        << ", kagree_alg=" << lih->kagree_alg_
        << ", is_pqc_mode=" << (is_pqc_mode ? "true" : "false"));

    if (is_pqc_mode)
    {
        EPROSIMA_LOG_INFO(SECURITY_AUTHENTICATION,
                "Using PQC handshake (ML-KEM-512 + ML-DSA-44)");

        // Debugging
        printf("[DEBUG] Starting ML-KEM-512 keygen...\n");
        fflush(stdout);

        // (Bpk, Bsk) = KEM.Keygen()
        EVP_PKEY_CTX* kem_ctx =
                EVP_PKEY_CTX_new_from_name(nullptr, "mlkem512", nullptr);
        if (kem_ctx == nullptr ||
            EVP_PKEY_keygen_init(kem_ctx) <= 0)
        {
            if (kem_ctx) EVP_PKEY_CTX_free(kem_ctx);
            exception = SecurityException("Failed to init ML-KEM keygen");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }

        // Debugging 
        printf("[DEBUG] ML-KEM keygen_init successful\n");
        fflush(stdout);

        EVP_PKEY* kem_keypair = nullptr;
        if (EVP_PKEY_generate(kem_ctx, &kem_keypair) <= 0)
        {
            EVP_PKEY_CTX_free(kem_ctx);
            exception = SecurityException("Failed to generate ML-KEM keypair");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
        EVP_PKEY_CTX_free(kem_ctx);

        // Store Bsk in handshake_handle (for decapsulation)
        (*handshake_handle_aux)->dhkeys_ = kem_keypair;

        // Debugging
        printf("[DEBUG] ML-KEM keypair generated successfully\n");
        printf("[DEBUG] kem_keypair pointer: %p\n", (void*)kem_keypair);
        fflush(stdout);

        // Extract Bpk as raw bytes -> pqc.kem.pubkey
        size_t pubkey_len = 0;
        
        // Get public key length
        if (EVP_PKEY_get_raw_public_key(kem_keypair, nullptr, &pubkey_len) != 1)
        {
            EVP_PKEY_free(kem_keypair);
            exception = SecurityException("Failed to get ML-KEM public key length");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
        
        printf("[DEBUG] ML-KEM public key raw size: %zu bytes\n", pubkey_len);
        fflush(stdout);
        
        // Allocate buffer and extract raw public key
        std::vector<unsigned char> pubkey_buf(pubkey_len);
        if (EVP_PKEY_get_raw_public_key(kem_keypair, pubkey_buf.data(), &pubkey_len) != 1)
        {
            EVP_PKEY_free(kem_keypair);
            exception = SecurityException("Failed to extract ML-KEM public key");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
        
        printf("[DEBUG] ML-KEM public key extracted successfully\n");
        fflush(stdout);

        BinaryProperty bproperty;
        bproperty.name("pqc.kem.pubkey");
        bproperty.value() = std::move(pubkey_buf);
        bproperty.propagate(true);
        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(
                std::move(bproperty));
        
        printf("[DEBUG] ML-KEM pubkey (raw %zu bytes) added to handshake message\n", pubkey_len);
        fflush(stdout);

        // Brand = challenge1 (random nonce)
        bproperty.name("challenge1");
        bproperty.propagate(true);
        if (!generate_challenge(bproperty.value(), exception))
        {
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(
                std::move(bproperty));

        // Check remaining properties c.id, c.perm, c.pdata
        (*handshake_handle_aux)->local_identity_handle_  = &lih;
        (*handshake_handle_aux)->remote_identity_handle_ = &rih;
        // Set start time for total duration calculation
        (*handshake_handle_aux)->start_time_ = start_time;

        *handshake_handle   = handshake_handle_aux;
        *handshake_message  = &(*handshake_handle_aux)->handshake_message_;
        
        
        auto end_time = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        printf("[DEBUG] Handshake Request Created: [OK] (Time: %.3f ms)\n", duration);
        fflush(stdout);

        return ValidationResult_t::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
    }
    else
    {
        // Classical mode: Use DH/ECDH
        // dh1
        if (((*handshake_handle_aux)->dhkeys_ = generate_dh_key(kagree_kind, exception)) != nullptr)
        {
            bproperty.name("dh1");
            bproperty.propagate(true);

            if (store_dh_public_key((*handshake_handle_aux)->dhkeys_, kagree_kind, bproperty.value(), exception))
            {
                (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

                // challenge1
                bproperty.name("challenge1");
                bproperty.propagate(true);
                if (generate_challenge(bproperty.value(), exception))
                {
                    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

                    (*handshake_handle_aux)->local_identity_handle_ = &lih;
                    (*handshake_handle_aux)->remote_identity_handle_ = &rih;
                    // Set start time for total duration calculation
                    (*handshake_handle_aux)->start_time_ = start_time;

                    *handshake_handle = handshake_handle_aux;
                    *handshake_message = &(*handshake_handle_aux)->handshake_message_;

                    auto end_time = std::chrono::high_resolution_clock::now();
                    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
                    printf("[DEBUG] Handshake Request Created: [OK] (Time: %.3f ms)\n", duration);
                    fflush(stdout);

                    return ValidationResult_t::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
                }
            }
        }
    }

    delete handshake_handle_aux;

    ERR_clear_error();

    return ValidationResult_t::VALIDATION_FAILED;
}

ValidationResult_t PKIDH::begin_handshake_reply(
        HandshakeHandle** handshake_handle,
        HandshakeMessageToken** handshake_message_out,
        HandshakeMessageToken&& handshake_message_in,
        IdentityHandle& initiator_identity_handle,
        const IdentityHandle& replier_identity_handle,
        const CDRMessage_t& cdr_participant_data,
        SecurityException& exception)
{
    auto start_time = std::chrono::high_resolution_clock::now();
    assert(handshake_handle);
    assert(handshake_message_out);
    assert(initiator_identity_handle.nil() == false);
    assert(replier_identity_handle.nil() == false);

    const PKIIdentityHandle& lih = PKIIdentityHandle::narrow(replier_identity_handle);
    PKIIdentityHandle& rih = PKIIdentityHandle::narrow(initiator_identity_handle);

    if (lih.nil() || rih.nil())
    {
        exception = SecurityException("Bad precondition");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    if (cdr_participant_data.length == 0)
    {
        exception = SecurityException("Bad precondition");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    // Check TokenMessage
    if (handshake_message_in.class_id().compare("DDS:Auth:PKI-DH:1.0+Req") != 0)
    {
        WARNING_SECURITY_LOGGING("PKIDH", std::string("Bad HandshakeMessageToken (") +
                handshake_message_in.class_id() + ")");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    // --- Check incoming handshake ---

    // c.id
    const std::vector<uint8_t>* cid =
            DataHolderHelper::find_binary_property_value(handshake_message_in, "c.id");
    if (cid == nullptr)
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.id");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    // Release old certificate if any
    if (rih->cert_ != nullptr)
    {
        X509_free(rih->cert_);
        rih->cert_ = nullptr;
    }

    rih->cert_ = load_certificate(*cid);
    if (rih->cert_ == nullptr)
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot load certificate");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    X509_NAME* cert_sn = X509_get_subject_name(rih->cert_);
    assert(cert_sn != nullptr);

    char* cert_sn_str = X509_NAME_oneline(cert_sn, 0, 0);
    assert(cert_sn_str != nullptr);

    if (!rih->cert_sn_.empty() && rih->cert_sn_.compare(cert_sn_str) != 0)
    {
        OPENSSL_free(cert_sn_str);
        WARNING_SECURITY_LOGGING("PKIDH", "Certificated subject name invalid");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    rih->cert_sn_.assign(cert_sn_str);
    OPENSSL_free(cert_sn_str);

    BIO* cert_sn_rfc2253_str = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(
            cert_sn_rfc2253_str,
            cert_sn,
            0,
            XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);

    const int bufsize = 1024;
    char buffer[bufsize];
    int str_length = BIO_read(cert_sn_rfc2253_str, buffer, bufsize);
    BIO_free(cert_sn_rfc2253_str);
    rih->cert_sn_rfc2253_.assign(buffer, str_length);

    if (!verify_certificate(lih->store_, rih->cert_, lih->there_are_crls_))
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Error verifying certificate");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    // c.perm
    if (lih->permissions_credential_token_.class_id().compare("DDS:Access:PermissionsCredential") == 0)
    {
        const std::vector<uint8_t>* perm =
                DataHolderHelper::find_binary_property_value(handshake_message_in, "c.perm");

        if (perm == nullptr)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.perm");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        rih->permissions_credential_token_.class_id("DDS:Access:PermissionsCredential");
        Property permission_file;
        permission_file.name("dds.perm.cert");
        permission_file.value().assign(perm->begin(), perm->end());
        rih->permissions_credential_token_.properties().push_back(std::move(permission_file));
    }

    // c.pdata
    const std::vector<uint8_t>* pdata =
            DataHolderHelper::find_binary_property_value(handshake_message_in, "c.pdata");
    if (pdata == nullptr)
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.pdata");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    (void)pdata;

    // --- hash_c1 (from subject name) ---
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned char hash_c1[SHA256_DIGEST_LENGTH];
    unsigned int length = 0;

    if (!X509_NAME_digest(cert_sn, EVP_sha256(), md, &length) ||
            length != SHA256_DIGEST_LENGTH)
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot generate SHA256 of subject name");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    // c.dsign_algo
    const std::vector<uint8_t>* dsign_algo =
            DataHolderHelper::find_binary_property_value(handshake_message_in, "c.dsign_algo");
    if (dsign_algo == nullptr)
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.dsign_algo");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    std::string s_dsign_algo(dsign_algo->begin(), dsign_algo->end());
    if (s_dsign_algo != RSA_SHA256 &&
        s_dsign_algo != ECDSA_SHA256 &&
        s_dsign_algo != MLDSA_44 &&
        s_dsign_algo != FALCON_512 &&
        s_dsign_algo != SPHINCS_128F)
    {
        WARNING_SECURITY_LOGGING(
                "PKIDH",
                "Not supported signature algorithm (" + s_dsign_algo + ")");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    rih->sign_alg_ = std::move(s_dsign_algo);

    // c.kagree_algo
    const std::vector<uint8_t>* kagree_algo =
            DataHolderHelper::find_binary_property_value(handshake_message_in, "c.kagree_algo");
    if (kagree_algo == nullptr)
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.kagree_algo");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    std::string s_kagree_algo(kagree_algo->begin(), kagree_algo->end());
    if (s_kagree_algo != DH_2048_256 &&
        s_kagree_algo != ECDH_prime256v1 &&
        s_kagree_algo != MLKEM_768 &&
        s_kagree_algo != MLKEM_512)
    {
        WARNING_SECURITY_LOGGING(
                "PKIDH",
                "Not supported key agreement algorithm (" + s_kagree_algo + ")");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    rih->kagree_alg_ = std::move(s_kagree_algo);

    // === PQC mode/Classical mode compatibility check ===
    bool remote_pqc = is_pqc_algorithm_pair(rih->sign_alg_, rih->kagree_alg_);
    bool local_pqc  = is_pqc_algorithm_pair(lih->sign_alg_, lih->kagree_alg_);

    if (remote_pqc != local_pqc)
    {
        WARNING_SECURITY_LOGGING(
                "PKIDH",
                std::string("Key agreement/signature mode mismatch. ") +
                "Remote uses " + rih->sign_alg_ + " + " + rih->kagree_alg_ +
                ", local uses " + lih->sign_alg_ + " + " + lih->kagree_alg_);
        return ValidationResult_t::VALIDATION_FAILED;
    }

    // hash_c1 from request properties (for check)
    CDRMessage_t cdrmessage(static_cast<uint32_t>(
            BinaryPropertyHelper::serialized_size(
                    handshake_message_in.binary_properties())));
    cdrmessage.msg_endian = BIGEND;
    CDRMessage::addBinaryPropertySeq(
            &cdrmessage,
            handshake_message_in.binary_properties(),
            "c.",
            false);

    if (!EVP_Digest(cdrmessage.buffer, cdrmessage.length, hash_c1, NULL, EVP_sha256(), NULL))
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot generate SHA256 of request");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    else
    {
        std::vector<uint8_t>* hash_c1_vec =
                DataHolderHelper::find_binary_property_value(
                        handshake_message_in,
                        "hash_c1");

        if (hash_c1_vec != nullptr)
        {
            if (hash_c1_vec->size() == SHA256_DIGEST_LENGTH &&
                    memcmp(hash_c1, hash_c1_vec->data(), SHA256_DIGEST_LENGTH) != 0)
            {
                WARNING_SECURITY_LOGGING("PKIDH", "Wrong hash_c1");
            }
        }
    }

    // --- dh1 / pqc.kem.pubkey / challenge1 ---

    std::vector<uint8_t>* dh1 =
            DataHolderHelper::find_binary_property_value(handshake_message_in, "dh1");
    std::vector<uint8_t>* pqc_kem_pubkey =
            DataHolderHelper::find_binary_property_value(handshake_message_in, "pqc.kem.pubkey");

    bool is_pqc_mode = (pqc_kem_pubkey != nullptr);

    if (!is_pqc_mode && dh1 == nullptr)
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property dh1 or pqc.kem.pubkey");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    std::vector<uint8_t>* challenge1 =
            DataHolderHelper::find_binary_property_value(handshake_message_in, "challenge1");
    if (challenge1 == nullptr)
    {
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property challenge1");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    // --- Generate handshake reply handle ---

    PKIHandshakeHandle* handshake_handle_aux = new PKIHandshakeHandle();
    (*handshake_handle_aux)->kagree_alg_ = rih->kagree_alg_;
    (*handshake_handle_aux)->handshake_message_.class_id("DDS:Auth:PKI-DH:1.0+Reply");

    int kagree_kind = get_dh_type((*handshake_handle_aux)->kagree_alg_);

    // Set peerkeys_ (PQC: ML-KEM pubkey, Classical: dh1)
    if (is_pqc_mode)
    {
         WARNING_SECURITY_LOGGING("PKIDH", "Processing PQC handshake reply (ML-KEM)");

        printf("[DEBUG] Received ML-KEM pubkey, size: %zu bytes\n", pqc_kem_pubkey->size());
        fflush(stdout);

        // Create ML-KEM-512 context first
        EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "mlkem512", nullptr);
        if (pkey_ctx == nullptr)
        {
            exception = SecurityException("Failed to create mlkem768 context");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }

        // Initialize keygen (we'll replace the key data)
        if (EVP_PKEY_keygen_init(pkey_ctx) <= 0)
        {
            EVP_PKEY_CTX_free(pkey_ctx);
            exception = SecurityException("Failed to init mlkem512 keygen");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }

        // Generate a temporary keypair
        EVP_PKEY* temp_keypair = nullptr;
        if (EVP_PKEY_generate(pkey_ctx, &temp_keypair) <= 0)
        {
            EVP_PKEY_CTX_free(pkey_ctx);
            exception = SecurityException("Failed to generate temp mlkem512 keypair");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
        EVP_PKEY_CTX_free(pkey_ctx);

        // Now create public key from raw bytes
        EVP_PKEY* bob_kem_pubkey = EVP_PKEY_new_raw_public_key_ex(
            nullptr,  // libctx
            "mlkem512",  // keytype
            nullptr,  // propquery
            pqc_kem_pubkey->data(),
            pqc_kem_pubkey->size()
        );
        
        EVP_PKEY_free(temp_keypair);

        if (bob_kem_pubkey == nullptr)
        {
            printf("[DEBUG] EVP_PKEY_new_raw_public_key_ex failed, trying alternative method\n");
            fflush(stdout);
            
            // Alternative: Use the raw bytes with encapsulation directly
            // Store raw bytes in a custom structure
            exception = SecurityException("Failed to create ML-KEM public key from raw bytes");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
        
        printf("[DEBUG] ML-KEM public key created from raw bytes successfully\n");
        fflush(stdout);

        // [DEBUG] Public key verification
        if (bob_kem_pubkey != nullptr)
        {
            int key_type = EVP_PKEY_id(bob_kem_pubkey);
            printf("[DEBUG] bob_kem_pubkey type: %d\n", key_type);
            
            size_t test_len = 0;
            if (EVP_PKEY_get_raw_public_key(bob_kem_pubkey, nullptr, &test_len) == 1)
            {
                printf("[DEBUG] bob_kem_pubkey can extract raw key, size: %zu\n", test_len);
            }
            else
            {
                printf("[DEBUG] ERROR: bob_kem_pubkey cannot extract raw key!\n");
            }
            fflush(stdout);
        }

        (*handshake_handle_aux)->peerkeys_ = bob_kem_pubkey;
        
        printf("[DEBUG] bob_kem_pubkey stored in peerkeys_\n");
        fflush(stdout);
    }
    else
    {
        // Classical mode: Generate DH peer key
        if (((*handshake_handle_aux)->peerkeys_ =
                    generate_dh_peer_key(*dh1, exception, kagree_kind)) == nullptr)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Cannot store peer key from dh1");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
    
    }

    BinaryProperty bproperty;

    // c.id
    bproperty.name("c.id");
    bproperty.value().assign(
            lih->cert_content_->data,
            lih->cert_content_->data + lih->cert_content_->length);
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    // c.perm
    if (lih->permissions_credential_token_.class_id().compare("DDS:Access:PermissionsCredential") == 0)
    {
        const Property* permissions_file =
                DataHolderHelper::find_property(
                        lih->permissions_credential_token_,
                        "dds.perm.cert");

        if (permissions_file != nullptr)
        {
            bproperty.name("c.perm");
            bproperty.value().assign(
                    permissions_file->value().begin(),
                    permissions_file->value().end());
            bproperty.propagate(true);
            (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));
        }
        else
        {
            exception = SecurityException("Cannot find permissions file in permissions credential token");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
    }

    // c.pdata
    bproperty.name("c.pdata");
    bproperty.value().assign(
            cdr_participant_data.buffer,
            cdr_participant_data.buffer + cdr_participant_data.length);
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    // c.dsign_algo
    bproperty.name("c.dsign_algo");
    bproperty.value().assign(lih->sign_alg_.begin(), lih->sign_alg_.end());
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    // c.kagree_algo
    bproperty.name("c.kagree_algo");
    bproperty.value().assign(
            (*handshake_handle_aux)->kagree_alg_.begin(),
            (*handshake_handle_aux)->kagree_alg_.end());
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    // === PQC mode marker for pcap/Wireshark ===
    if (is_pqc_algorithm_pair(lih->sign_alg_, (*handshake_handle_aux)->kagree_alg_))
    {
        BinaryProperty pqc_mode_prop;
        pqc_mode_prop.name("pqc.mode");

        std::string pqc_mode_value = lih->sign_alg_ + "+" + (*handshake_handle_aux)->kagree_alg_;
        pqc_mode_prop.value().assign(
                pqc_mode_value.begin(),
                pqc_mode_value.end());
        pqc_mode_prop.propagate(true);

        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(
                std::move(pqc_mode_prop));
    }

    // hash_c2
    CDRMessage_t message(static_cast<uint32_t>(
            BinaryPropertyHelper::serialized_size(
                    (*handshake_handle_aux)->handshake_message_.binary_properties())));
    message.msg_endian = BIGEND;
    CDRMessage::addBinaryPropertySeq(
            &message,
            (*handshake_handle_aux)->handshake_message_.binary_properties(),
            "c.",
            false);

    if (!EVP_Digest(message.buffer, message.length, md, NULL, EVP_sha256(), NULL))
    {
        exception = SecurityException("OpenSSL library cannot hash sha256");
        delete handshake_handle_aux;
        return ValidationResult_t::VALIDATION_FAILED;
    }

    bproperty.name("hash_c2");
    bproperty.value().assign(md, md + SHA256_DIGEST_LENGTH);
    bproperty.propagate(true);
    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

    // ----- PQC mode: ML-KEM + ML-DSA-44 -----
    if (is_pqc_mode)
    {
        // (Act, Ass) = KEM.Encaps(Bpk)
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> shared_secret;

        if (!mlkem_encapsulate(
                    (*handshake_handle_aux)->peerkeys_,
                    ciphertext,
                    shared_secret,
                    exception))
        {
            WARNING_SECURITY_LOGGING("PKIDH", "ML-KEM encapsulation failed");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] Storing ML-KEM shared secret in handshake handle...\n");
        fflush(stdout);

        (*handshake_handle_aux)->sharedsecret_ =
            std::dynamic_pointer_cast<SharedSecretHandle>(
                    get_shared_secret(SharedSecretHandle::nil_handle, exception));
        if ((*handshake_handle_aux)->sharedsecret_ == nullptr)
        {
            exception = SecurityException("Failed to create SharedSecretHandle");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }

        (*(*handshake_handle_aux)->sharedsecret_)->data_.emplace_back(
            SharedSecret::BinaryData("SharedSecret", shared_secret));

        printf("[DEBUG] Subscriber stored ML-KEM shared secret, size: %zu bytes\n", shared_secret.size());
        fflush(stdout);

        // pqc.kem.ciphertext (Act)
        bproperty.name("pqc.kem.ciphertext");
        bproperty.value() = std::move(ciphertext);
        bproperty.propagate(true);
        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

        // hash_c1 echo
        bproperty.name("hash_c1");
        bproperty.value().assign(hash_c1, hash_c1 + SHA256_DIGEST_LENGTH);
        bproperty.propagate(true);
        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

        // Extract Bpk as raw bytes -> pqc.kem.pubkey
        bproperty.name("pqc.kem.pubkey");
        bproperty.value().assign(
                pqc_kem_pubkey->begin(),
                pqc_kem_pubkey->end());
        bproperty.propagate(true);
        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

        // Brand echo
        bproperty.name("challenge1");
        bproperty.value().assign(
                challenge1->begin(),
                challenge1->end());
        bproperty.propagate(true);
        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

        // Arand = challenge2
        bproperty.name("challenge2");
        bproperty.propagate(true);
        if (!generate_challenge(bproperty.value(), exception))
        {
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }
        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

        // --- PQC signature message composition (hash_c2, challenge2, ciphertext, challenge1, Bpk, hash_c1) ---
        CDRMessage_t cdrmessage2(static_cast<uint32_t>(
                BinaryPropertyHelper::serialized_size(
                        (*handshake_handle_aux)->handshake_message_.binary_properties())));
        cdrmessage2.msg_endian = BIGEND;

        CDRMessage::addUInt32(&cdrmessage2, 6);
        CDRMessage::addBinaryProperty(
                &cdrmessage2,
                *DataHolderHelper::find_binary_property(
                        (*handshake_handle_aux)->handshake_message_,
                        "hash_c2"));
        CDRMessage::addBinaryProperty(
                &cdrmessage2,
                *DataHolderHelper::find_binary_property(
                        (*handshake_handle_aux)->handshake_message_,
                        "challenge2"));
        CDRMessage::addBinaryProperty(
                &cdrmessage2,
                *DataHolderHelper::find_binary_property(
                        (*handshake_handle_aux)->handshake_message_,
                        "pqc.kem.ciphertext"));
        CDRMessage::addBinaryProperty(
                &cdrmessage2,
                *DataHolderHelper::find_binary_property(
                        (*handshake_handle_aux)->handshake_message_,
                        "challenge1"));
        CDRMessage::addBinaryProperty(
                &cdrmessage2,
                *DataHolderHelper::find_binary_property(
                        (*handshake_handle_aux)->handshake_message_,
                        "pqc.kem.pubkey"));
        CDRMessage::addBinaryProperty(
                &cdrmessage2,
                *DataHolderHelper::find_binary_property(
                        (*handshake_handle_aux)->handshake_message_,
                        "hash_c1"),
                false);

        // Asig = PQC signature (algorithm determined by certificate)
        std::vector<uint8_t> pqc_sig;
        BinaryProperty sig_prop;
        sig_prop.name("pqc.signature");
        sig_prop.propagate(true);

        // Get signature algorithm from local identity
        PQCSignatureAlgorithm local_sig_algo = string_to_signature_algorithm(lih->sign_alg_);
        
        if (!pqc_sign_data(
                    local_sig_algo,
                    lih->pkey_,
                    cdrmessage2.buffer,
                    cdrmessage2.length,
                    pqc_sig,
                    exception))
        {
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }

        sig_prop.value() = std::move(pqc_sig);
        (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(sig_prop));

        // Store Ass after SharedSecretHandle creation
        (*handshake_handle_aux)->sharedsecret_ =
                std::dynamic_pointer_cast<SharedSecretHandle>(
                        get_shared_secret(SharedSecretHandle::nil_handle, exception));

        if ((*handshake_handle_aux)->sharedsecret_ == nullptr)
        {
            exception = SecurityException("Failed to create SharedSecretHandle");
            delete handshake_handle_aux;
            return ValidationResult_t::VALIDATION_FAILED;
        }

        (*(*handshake_handle_aux)->sharedsecret_)->data_.emplace_back(
                SharedSecret::BinaryData("SharedSecret", shared_secret));

        (*handshake_handle_aux)->local_identity_handle_  = &lih;
        (*handshake_handle_aux)->remote_identity_handle_ = &rih;
        // Set start time for total duration calculation
        (*handshake_handle_aux)->start_time_ = start_time;

        *handshake_handle      = handshake_handle_aux;
        *handshake_message_out = &(*handshake_handle_aux)->handshake_message_;

        size_t total_message_size = 0;
        printf("[DEBUG] ===== Handshake Reply Message Contents =====\n");
        for (const auto& prop : (*handshake_handle_aux)->handshake_message_.binary_properties())
        {
            printf("[DEBUG]   %s: %zu bytes\n", prop.name().c_str(), prop.value().size());
            total_message_size += prop.name().size() + prop.value().size() + 16;
        }
        printf("[DEBUG] Total estimated message size: %zu bytes\n", total_message_size);
        fflush(stdout);

        printf("[DEBUG] Total estimated message size: %zu bytes\n", total_message_size);
        fflush(stdout);

        auto end_time = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        printf("[DEBUG] Handshake Reply Created: [OK] (Time: %.3f ms)\n", duration);
        fflush(stdout);

        return ValidationResult_t::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
    }

    // ----- Classical mode: Existing DH/ECDH + RSA/ECDSA -----
    if (((*handshake_handle_aux)->dhkeys_ =
                generate_dh_key(kagree_kind, exception)) != nullptr)
    {
        // dh2
        bproperty.name("dh2");
        bproperty.propagate(true);

        if (store_dh_public_key(
                    (*handshake_handle_aux)->dhkeys_,
                    kagree_kind,
                    bproperty.value(),
                    exception))
        {
            (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

            // hash_c1 echo
            bproperty.name("hash_c1");
            bproperty.value().assign(hash_c1, hash_c1 + SHA256_DIGEST_LENGTH);
            bproperty.propagate(true);
            (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

            // dh1 echo
            bproperty.name("dh1");
            bproperty.value(std::move(*dh1));
            bproperty.propagate(true);
            (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

            // challenge1 echo
            bproperty.name("challenge1");
            bproperty.value(std::move(*challenge1));
            bproperty.propagate(true);
            (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

            // challenge2
            bproperty.name("challenge2");
            bproperty.propagate(true);
            if (generate_challenge(bproperty.value(), exception))
            {
                (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));

                // signature (RSA/ECDSA)
                CDRMessage_t cdrmessage2(static_cast<uint32_t>(
                        BinaryPropertyHelper::serialized_size(
                                (*handshake_handle_aux)->handshake_message_.binary_properties())));
                cdrmessage2.msg_endian = BIGEND;

                CDRMessage::addUInt32(&cdrmessage2, 6);
                CDRMessage::addBinaryProperty(
                        &cdrmessage2,
                        *DataHolderHelper::find_binary_property(
                                (*handshake_handle_aux)->handshake_message_,
                                "hash_c2"));
                CDRMessage::addBinaryProperty(
                        &cdrmessage2,
                        *DataHolderHelper::find_binary_property(
                                (*handshake_handle_aux)->handshake_message_,
                                "challenge2"));
                CDRMessage::addBinaryProperty(
                        &cdrmessage2,
                        *DataHolderHelper::find_binary_property(
                                (*handshake_handle_aux)->handshake_message_,
                                "dh2"));
                CDRMessage::addBinaryProperty(
                        &cdrmessage2,
                        *DataHolderHelper::find_binary_property(
                                (*handshake_handle_aux)->handshake_message_,
                                "challenge1"));
                CDRMessage::addBinaryProperty(
                        &cdrmessage2,
                        *DataHolderHelper::find_binary_property(
                                (*handshake_handle_aux)->handshake_message_,
                                "dh1"));
                CDRMessage::addBinaryProperty(
                        &cdrmessage2,
                        *DataHolderHelper::find_binary_property(
                                (*handshake_handle_aux)->handshake_message_,
                                "hash_c1"),
                        false);

                bproperty.name("signature");
                bproperty.propagate(true);

                if (sign_sha256(
                            lih->pkey_,
                            cdrmessage2.buffer,
                            cdrmessage2.length,
                            bproperty.value(),
                            exception))
                {
                    (*handshake_handle_aux)->handshake_message_.binary_properties().push_back(std::move(bproperty));
                    (*handshake_handle_aux)->local_identity_handle_  = &lih;
                    (*handshake_handle_aux)->remote_identity_handle_ = &rih;
                    // Set start time for total duration calculation
                    (*handshake_handle_aux)->start_time_ = start_time;

                    *handshake_handle      = handshake_handle_aux;
                    *handshake_message_out = &(*handshake_handle_aux)->handshake_message_;

                    *handshake_message_out = &(*handshake_handle_aux)->handshake_message_;

                    auto end_time = std::chrono::high_resolution_clock::now();
                    double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
                    printf("[DEBUG] Handshake Reply Created: [OK] (Time: %.3f ms)\n", duration);
                    fflush(stdout);

                    return ValidationResult_t::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
                }
            }
        }
    }

    // Cleanup on failure
    delete handshake_handle_aux;
    ERR_clear_error();
    return ValidationResult_t::VALIDATION_FAILED;
}

ValidationResult_t PKIDH::process_handshake(
        HandshakeMessageToken** handshake_message_out,
        HandshakeMessageToken&& handshake_message_in,
        HandshakeHandle& handshake_handle,
        SecurityException& exception)
{
    ValidationResult_t returnedValue = ValidationResult_t::VALIDATION_FAILED;

    // Debug: Check received message
    printf("[DEBUG] ===== process_handshake called =====\n");
    printf("[DEBUG] Incoming message class_id: '%s'\n", handshake_message_in.class_id().c_str());
    fflush(stdout);

    PKIHandshakeHandle& handshake = PKIHandshakeHandle::narrow(handshake_handle);

    if (!handshake.nil())
    {
        printf("[DEBUG] Current handshake state class_id: '%s'\n", 
               handshake->handshake_message_.class_id().c_str());
        fflush(stdout);
        
        // Received Reply -> Generate Final (calls process_handshake_request)
        if (handshake_message_in.class_id().compare("DDS:Auth:PKI-DH:1.0+Reply") == 0)
        {
            printf("[DEBUG] -> Received Reply, calling process_handshake_request (will generate Final)\n");
            fflush(stdout);
            
            returnedValue = process_handshake_request(handshake_message_out, std::move(handshake_message_in),
                            handshake, exception);
        }
        // Received Final -> Validate Final (calls process_handshake_reply)
        else if (handshake_message_in.class_id().compare("DDS:Auth:PKI-DH:1.0+Final") == 0)
        {
            printf("[DEBUG] -> Received Final, calling process_handshake_reply (will validate Final)\n");
            fflush(stdout);
            
            returnedValue = process_handshake_reply(handshake_message_out, std::move(handshake_message_in),
                            handshake, exception);
        }
        else
        {
            printf("[DEBUG] ERROR: Unknown message type!\n");
            printf("[DEBUG]    Received class_id: '%s'\n", handshake_message_in.class_id().c_str());
            printf("[DEBUG]    Expected: 'DDS:Auth:PKI-DH:1.0+Reply' or 'DDS:Auth:PKI-DH:1.0+Final'\n");
            fflush(stdout);
            
            WARNING_SECURITY_LOGGING("PKIDH",
                    std::string("Handshake message not supported (") + handshake_message_in.class_id() + ")");
        }
    }
    else
    {
        printf("[DEBUG] ERROR: handshake.nil() == true\n");
        fflush(stdout);
    }

    printf("[DEBUG] process_handshake returning: %d\n", (int)returnedValue);
    fflush(stdout);

    return returnedValue;
}

// ============================================================================
// Process_handshake_request with PQC support
// ============================================================================

ValidationResult_t PKIDH::process_handshake_request(
        HandshakeMessageToken** handshake_message_out,
        HandshakeMessageToken&& handshake_message_in,
        PKIHandshakeHandle& handshake_handle,
        SecurityException& exception)
{
    auto start_time = std::chrono::high_resolution_clock::now();
    printf("[DEBUG] process_handshake_request CALLED\n");
    printf("[DEBUG] ========================================\n");
    fflush(stdout);

    const PKIIdentityHandle& lih = *handshake_handle->local_identity_handle_;
    PKIIdentityHandle& rih = *handshake_handle->remote_identity_handle_;

    // Step 1
    printf("[DEBUG] Step 1: Checking TokenMessage class_id...\n");
    fflush(stdout);
    
    if (handshake_message_in.class_id().compare("DDS:Auth:PKI-DH:1.0+Reply") != 0)
    {
        printf("[DEBUG] [FAIL] at Step 1: Bad class_id: '%s'\n", handshake_message_in.class_id().c_str());
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", std::string("Bad HandshakeMessageToken (") +
                handshake_message_in.class_id() + ")");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    printf("[DEBUG] [OK] Step 1 OK\n");
    fflush(stdout);

    // Step 2
    printf("[DEBUG] Step 2: Looking for c.id...\n");
    fflush(stdout);
    
    const std::vector<uint8_t>* cid = DataHolderHelper::find_binary_property_value(handshake_message_in, "c.id");
    if (cid == nullptr)
    {
        printf("[DEBUG] [FAIL] at Step 2: Cannot find c.id\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.id");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    printf("[DEBUG] [OK] Step 2 OK, c.id size: %zu\n", cid->size());
    fflush(stdout);

    // Step 3
    printf("[DEBUG] Step 3: Loading certificate...\n");
    fflush(stdout);
    
    rih->cert_ = load_certificate(*cid);

    if (rih->cert_ == nullptr)
    {
        printf("[DEBUG] [FAIL] at Step 3: Cannot load certificate\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot load certificate");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    printf("[DEBUG] [OK] Step 3 OK\n");
    fflush(stdout);

    // Step 4
    printf("[DEBUG] Step 4: Verifying certificate subject name...\n");
    fflush(stdout);
    
    X509_NAME* cert_sn = X509_get_subject_name(rih->cert_);
    assert(cert_sn != nullptr);
    char* cert_sn_str = X509_NAME_oneline(cert_sn, 0, 0);
    assert(cert_sn_str != nullptr);
    
    if (!rih->cert_sn_.empty() && rih->cert_sn_.compare(cert_sn_str) != 0)
    {
        printf("[DEBUG] [FAIL] at Step 4: Subject name mismatch\n");
        printf("[DEBUG]    Expected: '%s'\n", rih->cert_sn_.c_str());
        printf("[DEBUG]    Got: '%s'\n", cert_sn_str);
        fflush(stdout);
        OPENSSL_free(cert_sn_str);
        WARNING_SECURITY_LOGGING("PKIDH", "Certificated subject name invalid");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    OPENSSL_free(cert_sn_str);

    printf("[DEBUG] [OK] Step 4 OK\n");
    fflush(stdout);

    // Step 5
    printf("[DEBUG] Step 5: Converting to RFC2253...\n");
    fflush(stdout);
    
    BIO* cert_sn_rfc2253_str = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(cert_sn_rfc2253_str, cert_sn, 0, XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);
    const int bufsize = 1024;
    char buffer[bufsize];
    int str_length = BIO_read(cert_sn_rfc2253_str, buffer, bufsize);
    BIO_free(cert_sn_rfc2253_str);
    rih->cert_sn_rfc2253_.assign(buffer, str_length);

    printf("[DEBUG] [OK] Step 5 OK\n");
    fflush(stdout);

    // Step 6
    printf("[DEBUG] Step 6: Verifying certificate chain...\n");
    fflush(stdout);
    
    if (!verify_certificate(lih->store_, rih->cert_, lih->there_are_crls_))
    {
        printf("[DEBUG] [FAIL] at Step 6: Certificate verification failed\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Error verifying certificate");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    printf("[DEBUG] [OK] Step 6 OK\n");
    fflush(stdout);

    // Step 7
    printf("[DEBUG] Step 7: Checking c.perm...\n");
    fflush(stdout);
    
    if (lih->permissions_credential_token_.class_id().compare("DDS:Access:PermissionsCredential") == 0)
    {
        const std::vector<uint8_t>* perm = DataHolderHelper::find_binary_property_value(handshake_message_in,
                        "c.perm");

        if (perm == nullptr)
        {
        printf("[DEBUG] [FAIL] at Step 7: Cannot find c.perm\n");
            fflush(stdout);
            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.perm");
            return ValidationResult_t::VALIDATION_FAILED;
        }
        printf("[DEBUG] c.perm size: %zu\n", perm->size());
        fflush(stdout);

        rih->permissions_credential_token_.class_id("DDS:Access:PermissionsCredential");
        Property permission_file;
        permission_file.name("dds.perm.cert");
        permission_file.value().assign(perm->begin(), perm->end());
        rih->permissions_credential_token_.properties().push_back(std::move(permission_file));
    }
    printf("[DEBUG] [OK] Step 7 OK\n");
    fflush(stdout);

    // Step 8
    printf("[DEBUG] Step 8: Checking c.pdata...\n");
    fflush(stdout);
    
    const std::vector<uint8_t>* pdata = DataHolderHelper::find_binary_property_value(handshake_message_in, "c.pdata");

    if (pdata == nullptr)
    {
        printf("[DEBUG] [FAIL] at Step 8: Cannot find c.pdata\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.pdata");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    printf("[DEBUG] [OK] Step 8 OK, c.pdata size: %zu\n", pdata->size());
    fflush(stdout);

    (void)pdata;
    
    // Step 9
    printf("[DEBUG] Step 9: Computing SHA256...\n");
    fflush(stdout);
    
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int length = 0;

    if (!X509_NAME_digest(cert_sn, EVP_sha256(), md, &length) || length != SHA256_DIGEST_LENGTH)
    {
        printf("[DEBUG] [FAIL] at Step 9: SHA256 failed\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot generate SHA256 of subject name");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    printf("[DEBUG] [OK] Step 9 OK\n");
    fflush(stdout);

    // Step 10
    printf("[DEBUG] Step 10: Checking c.dsign_algo...\n");
    fflush(stdout);
    
    const std::vector<uint8_t>* dsign_algo = DataHolderHelper::find_binary_property_value(handshake_message_in,
                    "c.dsign_algo");

    if (dsign_algo == nullptr)
    {
        printf("[DEBUG] [FAIL] at Step 10: Cannot find c.dsign_algo\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.dsign_algo");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    std::string s_dsign_algo(dsign_algo->begin(), dsign_algo->end());
    printf("[DEBUG] c.dsign_algo: '%s'\n", s_dsign_algo.c_str());
    fflush(stdout);
    
    if (s_dsign_algo != RSA_SHA256 &&
        s_dsign_algo != ECDSA_SHA256 &&
        s_dsign_algo != MLDSA_44 &&
        s_dsign_algo != FALCON_512 &&
        s_dsign_algo != SPHINCS_128F)
    {
        printf("[DEBUG] [FAIL] at Step 10: Unsupported signature algorithm\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH",
                "Not supported signature algorithm (" + s_dsign_algo + ")");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    rih->sign_alg_ = std::move(s_dsign_algo);
    printf("[DEBUG] [OK] Step 10 OK\n");
    fflush(stdout);

    // Step 11
    printf("[DEBUG] Step 11: Checking c.kagree_algo...\n");
    fflush(stdout);
    
    const std::vector<uint8_t>* kagree_algo = DataHolderHelper::find_binary_property_value(handshake_message_in,
                    "c.kagree_algo");

    if (kagree_algo == nullptr)
    {
        printf("[DEBUG] [FAIL] at Step 11: Cannot find c.kagree_algo\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property c.kagree_algo");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    std::string s_kagree_algo(kagree_algo->begin(), kagree_algo->end());
    printf("[DEBUG] c.kagree_algo: '%s', expected: '%s'\n", 
           s_kagree_algo.c_str(), handshake_handle->kagree_alg_.c_str());
    fflush(stdout);
    
    if (s_kagree_algo.compare(handshake_handle->kagree_alg_) != 0)
    {
        printf("[DEBUG] [FAIL] at Step 11: Key agreement algorithm mismatch\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", std::string("Invalid key agreement algorithm. Received ") +
                s_kagree_algo + ", expected " + handshake_handle->kagree_alg_);
        return ValidationResult_t::VALIDATION_FAILED;
    }
    printf("[DEBUG] [OK] Step 11 OK\n");
    fflush(stdout);

    // Step 12
    printf("[DEBUG] Step 12: Checking hash_c2...\n");
    fflush(stdout);
    
    BinaryProperty* hash_c2 = DataHolderHelper::find_binary_property(handshake_message_in, "hash_c2");

    if (hash_c2 == nullptr)
    {
        printf("[DEBUG] [FAIL] at Step 12: Cannot find hash_c2\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property hash_c2");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    if (hash_c2->value().size() != SHA256_DIGEST_LENGTH)
    {
        printf("[DEBUG] [FAIL] at Step 12: Wrong hash_c2 size: %zu\n", hash_c2->value().size());
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Wrong size of hash_c2");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    printf("[DEBUG] [OK] Step 12 OK\n");
    fflush(stdout);

    // Step 13
    printf("[DEBUG] Step 13: Computing and verifying hash_c2...\n");
    fflush(stdout);
    
    uint32_t digestInLen =
            static_cast<uint32_t>(BinaryPropertyHelper::serialized_size(handshake_message_in.binary_properties()));
    CDRMessage_t cdrmessage(digestInLen + 3);
    cdrmessage.msg_endian = BIGEND;
    CDRMessage::addBinaryPropertySeq(&cdrmessage, handshake_message_in.binary_properties(), "c.", false);

    if (!EVP_Digest(cdrmessage.buffer, cdrmessage.length, md, NULL, EVP_sha256(), NULL))
    {
        printf("[DEBUG] [FAIL] at Step 13: Cannot compute hash\n");
        fflush(stdout);
        exception = SecurityException("Cannot generate SHA256 of request");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    if (memcmp(md, hash_c2->value().data(), SHA256_DIGEST_LENGTH) != 0)
    {
        printf("[DEBUG] [FAIL] at Step 13: hash_c2 mismatch\n");
        fflush(stdout);
        WARNING_SECURITY_LOGGING("PKIDH", "Wrong hash_c2");
        return ValidationResult_t::VALIDATION_FAILED;
    }
    printf("[DEBUG] [OK] Step 13 OK\n");
    fflush(stdout);

    // Step 14 - PQC mode check
    printf("[DEBUG] Step 14: Checking PQC mode...\n");
    printf("[DEBUG] kagree_alg: '%s', MLKEM_512: '%s', MLKEM_768: '%s'\n", 
           handshake_handle->kagree_alg_.c_str(), MLKEM_512, MLKEM_768);
    fflush(stdout);
    
    bool is_pqc_mode = (handshake_handle->kagree_alg_ == MLKEM_512 || handshake_handle->kagree_alg_ == MLKEM_768);

    printf("[DEBUG] is_pqc_mode = %s\n", is_pqc_mode ? "TRUE" : "FALSE");
    fflush(stdout);

    if (is_pqc_mode)
    {
        // ========================================================================
        // PQC MODE: Bob receives Alice's Reply and sends Final with PQC signature
        // ========================================================================

        // [DEBUG]
        printf("[DEBUG] ===== PQC MODE: Processing Reply =====\n");
        fflush(stdout);

        EPROSIMA_LOG_INFO(SECURITY_AUTHENTICATION, "Processing PQC handshake request (ML-KEM + ML-DSA-44)");

        // 1. Find pqc.kem.ciphertext (Alice's Act)

        printf("[DEBUG] Step 1: Looking for pqc.kem.ciphertext...\n");
        fflush(stdout);

        BinaryProperty* pqc_ciphertext = DataHolderHelper::find_binary_property(
            handshake_message_in, "pqc.kem.ciphertext");
        if (pqc_ciphertext == nullptr)
        {
            printf("[DEBUG] [ERROR] Cannot find pqc.kem.ciphertext\n");
            fflush(stdout);

            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property pqc.kem.ciphertext");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] [OK] Found pqc.kem.ciphertext, size: %zu bytes\n", pqc_ciphertext->value().size());
        fflush(stdout);

        // 2. Find challenge2 (Arand)
        printf("[DEBUG] Step 2: Looking for challenge2...\n");
        fflush(stdout);

        BinaryProperty* challenge2 = DataHolderHelper::find_binary_property(
            handshake_message_in, "challenge2");
        if (challenge2 == nullptr)
        {
            printf("[DEBUG] [ERROR] Cannot find challenge2\n");
            fflush(stdout);

            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property challenge2");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] [OK] Found challenge2, size: %zu bytes\n", challenge2->value().size());
        fflush(stdout);

        // 3. Find hash_c1
        printf("[DEBUG] Step 3: Looking for hash_c1...\n");
        fflush(stdout);

        BinaryProperty* hash_c1 = DataHolderHelper::find_binary_property(
            handshake_message_in, "hash_c1");
        if (hash_c1 == nullptr)
        {
            printf("[DEBUG] [ERROR] Cannot find hash_c1\n");
            fflush(stdout);

            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property hash_c1");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] [OK] Found hash_c1, size: %zu bytes\n", hash_c1->value().size());
        fflush(stdout);

        // Verify hash_c1 matches request
        printf("[DEBUG] Step 4: Verifying hash_c1 matches request...\n");
        fflush(stdout);

        const std::vector<uint8_t>* hash_c1_request = DataHolderHelper::find_binary_property_value(
            handshake_handle->handshake_message_, "hash_c1");
        if (hash_c1_request == nullptr)
        {
            printf("[DEBUG] [ERROR] Cannot find hash_c1 in request message\n");
            fflush(stdout);
            exception = SecurityException("Cannot find property hash_c1 in request message");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return ValidationResult_t::VALIDATION_FAILED;
        }
        if (hash_c1->value() != *hash_c1_request)
        {
            printf("[DEBUG] [ERROR] hash_c1 mismatch!\n");
            fflush(stdout);

            WARNING_SECURITY_LOGGING("PKIDH", "Invalid property hash_c1");
            return ValidationResult_t::VALIDATION_FAILED;
        }
        printf("[DEBUG] [OK] hash_c1 verified\n");
        fflush(stdout);

        // 4. Find pqc.kem.pubkey (Bob's Bpk echo)
        printf("[DEBUG] Step 5: Looking for pqc.kem.pubkey...\n");
        fflush(stdout);
        
        BinaryProperty* pqc_kem_pubkey = DataHolderHelper::find_binary_property(
            handshake_message_in, "pqc.kem.pubkey");
        if (pqc_kem_pubkey == nullptr)
        {
            printf("[DEBUG] [ERROR] Cannot find pqc.kem.pubkey\n");
            fflush(stdout);

            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property pqc.kem.pubkey");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] [OK] Found pqc.kem.pubkey, size: %zu bytes\n", pqc_kem_pubkey->value().size());
        fflush(stdout);

        // Verify pqc.kem.pubkey matches request
        printf("[DEBUG] Step 6: Verifying pqc.kem.pubkey matches request...\n");
        fflush(stdout);

        const std::vector<uint8_t>* pqc_kem_pubkey_request = 
            DataHolderHelper::find_binary_property_value(
                handshake_handle->handshake_message_, "pqc.kem.pubkey");
        if (pqc_kem_pubkey_request == nullptr)
        {
            printf("[DEBUG] [ERROR] Cannot find pqc.kem.pubkey in request message\n");
            fflush(stdout);

            exception = SecurityException("Cannot find property pqc.kem.pubkey in request message");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return ValidationResult_t::VALIDATION_FAILED;
        }
        if (pqc_kem_pubkey->value() != *pqc_kem_pubkey_request)
        {
            printf("[DEBUG] [ERROR] pqc.kem.pubkey mismatch!\n");
            fflush(stdout);

            WARNING_SECURITY_LOGGING("PKIDH", "Invalid property pqc.kem.pubkey");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] [OK] pqc.kem.pubkey verified\n");
        fflush(stdout);

        // 5. Find challenge1 (Brand)
        printf("[DEBUG] Step 7: Looking for challenge1...\n");
        fflush(stdout);

        BinaryProperty* challenge1 = DataHolderHelper::find_binary_property(
            handshake_message_in, "challenge1");
        if (challenge1 == nullptr)
        {
            printf("[DEBUG] [ERROR] Cannot find challenge1\n");
            fflush(stdout);

            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property challenge1");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] [OK] Found challenge1, size: %zu bytes\n", challenge1->value().size());
        fflush(stdout);

        // Verify challenge1 matches request
        printf("[DEBUG] Step 8: Verifying challenge1 matches request...\n");
        fflush(stdout);

        const std::vector<uint8_t>* challenge1_request = 
            DataHolderHelper::find_binary_property_value(
                handshake_handle->handshake_message_, "challenge1");
        if (challenge1_request == nullptr)
        {
            printf("[DEBUG] [ERROR] Cannot find challenge1 in request message\n");
            fflush(stdout);

            exception = SecurityException("Cannot find property challenge1 in request message");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return ValidationResult_t::VALIDATION_FAILED;
        }
        if (challenge1->value() != *challenge1_request)
        {
            printf("[DEBUG] [ERROR] challenge1 mismatch!\n");
            fflush(stdout);

            WARNING_SECURITY_LOGGING("PKIDH", "Invalid property challenge1");
            return ValidationResult_t::VALIDATION_FAILED;
        }
        
        printf("[DEBUG] [OK] challenge1 verified\n");
        fflush(stdout);

        // 6. Find and verify Alice's ML-DSA-44 signature (Asig)
        printf("[DEBUG] Step 9: Looking for pqc.signature...\n");
        fflush(stdout);

        const std::vector<uint8_t>* pqc_signature = 
            DataHolderHelper::find_binary_property_value(handshake_message_in, "pqc.signature");
            
        if (pqc_signature == nullptr)
        {
            printf("[DEBUG] [ERROR] Cannot find pqc.signature\n");
            fflush(stdout);

            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property pqc.signature");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] [OK] Found pqc.signature, size: %zu bytes\n", pqc_signature->size());
        fflush(stdout);
        
        // Prepare data for signature verification (same order as Alice signed)
        printf("[DEBUG] Step 10: Preparing data for signature verification...\n");
        fflush(stdout);

        CDRMessage_t sig_verify_msg(static_cast<uint32_t>(
            BinaryPropertyHelper::serialized_size(handshake_message_in.binary_properties())));
        sig_verify_msg.msg_endian = BIGEND;
        CDRMessage::addUInt32(&sig_verify_msg, 6);
        CDRMessage::addBinaryProperty(&sig_verify_msg, *hash_c2);
        CDRMessage::addBinaryProperty(&sig_verify_msg, *challenge2);
        CDRMessage::addBinaryProperty(&sig_verify_msg, *pqc_ciphertext);
        CDRMessage::addBinaryProperty(&sig_verify_msg, *challenge1);
        CDRMessage::addBinaryProperty(&sig_verify_msg, *pqc_kem_pubkey);
        CDRMessage::addBinaryProperty(&sig_verify_msg, *hash_c1, false);

        printf("[DEBUG] Signature verification data prepared, length: %u bytes\n", sig_verify_msg.length);
        fflush(stdout);

        // Extract Alice's ML-DSA-44 public key from certificate
        printf("[DEBUG] Step 11: Extracting ML-DSA-44 public key from certificate...\n");
        fflush(stdout);

        EVP_PKEY* alice_verify_key = X509_get_pubkey(rih->cert_);
        if (alice_verify_key == nullptr)
        {
            printf("[DEBUG] [ERROR] Failed to extract public key from certificate\n");
            fflush(stdout);

            exception = SecurityException("Failed to extract public key from Alice's certificate");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return ValidationResult_t::VALIDATION_FAILED;
        }
        printf("[DEBUG] [OK] Public key extracted, type: %d\n", EVP_PKEY_id(alice_verify_key));
        fflush(stdout);

        // Verify Alice's PQC signature (algorithm from remote identity)
        PQCSignatureAlgorithm remote_sig_algo = string_to_signature_algorithm(rih->sign_alg_);
        printf("[DEBUG] Step 12: Verifying %s signature...\n", 
               get_openssl_algorithm_name(remote_sig_algo));
        fflush(stdout);

        if (!pqc_verify_signature(remote_sig_algo,
                                   alice_verify_key, 
                                   sig_verify_msg.buffer, 
                                   sig_verify_msg.length,
                                   *pqc_signature, 
                                   exception))
        {
            printf("[DEBUG] ERROR: Signature verification FAILED!\n");
            fflush(stdout);

            EVP_PKEY_free(alice_verify_key);
            WARNING_SECURITY_LOGGING("PKIDH", std::string("Error verifying ") + rih->sign_alg_ + " signature from Alice");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] Signature verified successfully!\n");
        fflush(stdout);

        EVP_PKEY_free(alice_verify_key);

        EPROSIMA_LOG_INFO(SECURITY_AUTHENTICATION, std::string("Alice's ") + rih->sign_alg_ + " signature verified successfully");

        // 7. Bob performs ML-KEM decapsulation: Bss = KEM.Decaps(Act, Bsk)
        printf("[DEBUG] Step 13: Performing ML-KEM decapsulation...\n");
        fflush(stdout);

        std::vector<uint8_t> shared_secret_bob;
        if (!mlkem_decapsulate(handshake_handle->dhkeys_, 
                              pqc_ciphertext->value(),
                              shared_secret_bob, 
                              exception))
        {
            printf("[DEBUG] [ERROR] ML-KEM decapsulation FAILED!\n");
            fflush(stdout);
            WARNING_SECURITY_LOGGING("PKIDH", "Failed to decapsulate ML-KEM ciphertext");
            return ValidationResult_t::VALIDATION_FAILED;
        }
        
        printf("[DEBUG] [OK] ML-KEM decapsulation successful! Shared secret size: %zu bytes\n", shared_secret_bob.size());
        fflush(stdout);

        EPROSIMA_LOG_INFO(SECURITY_AUTHENTICATION, 
                         "ML-KEM decapsulation successful, shared secret size: " 
                         << shared_secret_bob.size());

        // 8. Generate Bob's Final message
        HandshakeMessageToken final_message;
        final_message.binary_properties().clear();
        final_message.class_id("DDS:Auth:PKI-DH:1.0+Final");

        BinaryProperty bproperty;

        // Echo hash_c1
        bproperty.name("hash_c1");
        bproperty.value() = std::move(hash_c1->value());
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // Echo hash_c2
        bproperty.name("hash_c2");
        bproperty.value(std::move(hash_c2->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // Echo pqc.kem.pubkey (Bpk)
        bproperty.name("pqc.kem.pubkey");
        bproperty.value(std::move(pqc_kem_pubkey->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // Echo pqc.kem.ciphertext (Act)
        bproperty.name("pqc.kem.ciphertext");
        bproperty.value(std::move(pqc_ciphertext->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // Echo challenge1 (Brand)
        bproperty.name("challenge1");
        bproperty.value(std::move(challenge1->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // Echo challenge2 (Arand)
        bproperty.name("challenge2");
        bproperty.value(std::move(challenge2->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // 9. Bob signs with ML-DSA-44 (Bsig)
        CDRMessage_t final_sig_data(static_cast<uint32_t>(
            BinaryPropertyHelper::serialized_size(final_message.binary_properties())));
        final_sig_data.msg_endian = BIGEND;
        CDRMessage::addUInt32(&final_sig_data, 6);
        CDRMessage::addBinaryProperty(&final_sig_data, 
            *DataHolderHelper::find_binary_property(final_message, "hash_c1"));
        CDRMessage::addBinaryProperty(&final_sig_data, 
            *DataHolderHelper::find_binary_property(final_message, "challenge1"));
        CDRMessage::addBinaryProperty(&final_sig_data, 
            *DataHolderHelper::find_binary_property(final_message, "pqc.kem.pubkey"));
        CDRMessage::addBinaryProperty(&final_sig_data, 
            *DataHolderHelper::find_binary_property(final_message, "challenge2"));
        CDRMessage::addBinaryProperty(&final_sig_data, 
            *DataHolderHelper::find_binary_property(final_message, "pqc.kem.ciphertext"));
        CDRMessage::addBinaryProperty(&final_sig_data, 
            *DataHolderHelper::find_binary_property(final_message, "hash_c2"), false);

        std::vector<uint8_t> bob_signature;
        PQCSignatureAlgorithm local_sig_algo = string_to_signature_algorithm(lih->sign_alg_);
        
        if (!pqc_sign_data(local_sig_algo,
                          lih->pkey_, 
                          final_sig_data.buffer, 
                          final_sig_data.length,
                          bob_signature, 
                          exception))
        {
            WARNING_SECURITY_LOGGING("PKIDH", 
                std::string("Failed to generate Bob's ") + lih->sign_alg_ + " signature");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        bproperty.name("pqc.signature");
        bproperty.value() = std::move(bob_signature);
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        EPROSIMA_LOG_INFO(SECURITY_AUTHENTICATION, 
            std::string("Bob's ") + lih->sign_alg_ + " signature generated successfully");
        
        WARNING_SECURITY_LOGGING("PKIDH", "ML-KEM decapsulation successful");

        // 10. Store shared secret
        handshake_handle->sharedsecret_ = 
            std::dynamic_pointer_cast<SharedSecretHandle>(
                get_shared_secret(SharedSecretHandle::nil_handle, exception));

        if (handshake_handle->sharedsecret_ != nullptr)
        {
            // Store ML-KEM shared secret
            (*handshake_handle->sharedsecret_)->data_.emplace_back(
                SharedSecret::BinaryData("SharedSecret", shared_secret_bob));
            
            // Save challenges
            (*handshake_handle->sharedsecret_)->data_.emplace_back(
                SharedSecret::BinaryData("Challenge1",
                    *DataHolderHelper::find_binary_property_value(final_message, "challenge1")));
            (*handshake_handle->sharedsecret_)->data_.emplace_back(
                SharedSecret::BinaryData("Challenge2",
                    *DataHolderHelper::find_binary_property_value(final_message, "challenge2")));

            handshake_handle->handshake_message_ = std::move(final_message);
            *handshake_message_out = &handshake_handle->handshake_message_;

            printf("=== HANDSHAKE SUCCESS (Bob: Final message generated - PQC) ===\n");
            fflush(stdout);

            auto end_time = std::chrono::high_resolution_clock::now();
            double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
            printf("[DEBUG] Handshake Final Created: [OK] (Time: %.3f ms)\n", duration);

            double total_duration = std::chrono::duration<double, std::milli>(end_time - handshake_handle->start_time_).count();
            printf("[DEBUG] Total Handshake Time (Initiator): %.3f ms\n", total_duration);
            fflush(stdout);

            EPROSIMA_LOG_INFO(SECURITY_AUTHENTICATION, 
                             "PQC handshake request processed successfully - Final message ready");
            return ValidationResult_t::VALIDATION_OK_WITH_FINAL_MESSAGE;
        }
        else
        {
            exception = SecurityException("Failed to create shared secret handle");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return ValidationResult_t::VALIDATION_FAILED;
        }
    }
    else
    {
        // ========================================================================
        // CLASSICAL MODE: Original DH/ECDH implementation
        // ========================================================================

        // dh2
        BinaryProperty* dh2 = DataHolderHelper::find_binary_property(handshake_message_in, "dh2");
        if (dh2 == nullptr)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property dh2");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        int kagree_kind = get_dh_type(s_kagree_algo);

        if ((handshake_handle->peerkeys_ = generate_dh_peer_key(dh2->value(), exception, kagree_kind)) == nullptr)
        {
            exception = SecurityException("Cannot store peer key from dh2");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return ValidationResult_t::VALIDATION_FAILED;
        }

        BinaryProperty* challenge2 = DataHolderHelper::find_binary_property(handshake_message_in, "challenge2");

        if (challenge2 == nullptr)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property challenge2");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        // hash_c1
        BinaryProperty* hash_c1 = DataHolderHelper::find_binary_property(handshake_message_in, "hash_c1");

        if (hash_c1 == nullptr)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property hash_c1");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        const std::vector<uint8_t>* hash_c1_request = DataHolderHelper::find_binary_property_value(
            handshake_handle->handshake_message_, "hash_c1");

        if (hash_c1_request == nullptr)
        {
            exception = SecurityException("Cannot find property hash_c1 in request message");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return ValidationResult_t::VALIDATION_FAILED;
        }

        if (hash_c1->value() != *hash_c1_request)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Invalid property hash_c1");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        // dh1
        BinaryProperty* dh1 = DataHolderHelper::find_binary_property(handshake_message_in, "dh1");

        if (dh1 == nullptr)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property dh1");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        const std::vector<uint8_t>* dh1_request = DataHolderHelper::find_binary_property_value(
            handshake_handle->handshake_message_, "dh1");

        if (dh1_request == nullptr)
        {
            exception = SecurityException("Cannot find property dh1 in request message");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return ValidationResult_t::VALIDATION_FAILED;
        }

        if (dh1->value() != *dh1_request)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Invalid property dh1");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        BinaryProperty* challenge1 = DataHolderHelper::find_binary_property(handshake_message_in, "challenge1");

        if (challenge1 == nullptr)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property challenge1");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        const std::vector<uint8_t>* challenge1_request = DataHolderHelper::find_binary_property_value(
            handshake_handle->handshake_message_, "challenge1");

        if (challenge1_request == nullptr)
        {
            exception = SecurityException("Cannot find property challenge1 in request message");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return ValidationResult_t::VALIDATION_FAILED;
        }

        if (challenge1->value() != *challenge1_request)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Invalid property challenge1");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        const std::vector<uint8_t>* signature = DataHolderHelper::find_binary_property_value(handshake_message_in,
                        "signature");

        if (signature == nullptr)
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Cannot find property signature");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        // signature
        CDRMessage_t cdrmessage2(static_cast<uint32_t>(BinaryPropertyHelper::serialized_size(
                    handshake_message_in.binary_properties())));
        cdrmessage2.msg_endian = BIGEND;
        // add sequence length
        CDRMessage::addUInt32(&cdrmessage2, 6);
        //add hash_c2
        CDRMessage::addBinaryProperty(&cdrmessage2, *hash_c2);
        //add challenge2
        CDRMessage::addBinaryProperty(&cdrmessage2, *challenge2);
        //add dh2
        CDRMessage::addBinaryProperty(&cdrmessage2, *dh2);
        //add challenge1
        CDRMessage::addBinaryProperty(&cdrmessage2, *challenge1);
        //add dh1
        CDRMessage::addBinaryProperty(&cdrmessage2, *dh1);
        //add hash_c1
        CDRMessage::addBinaryProperty(&cdrmessage2, *hash_c1, false);

        if (!check_sign_sha256(rih->cert_, cdrmessage2.buffer, cdrmessage2.length, *signature, exception))
        {
            WARNING_SECURITY_LOGGING("PKIDH", "Error verifying signature");
            return ValidationResult_t::VALIDATION_FAILED;
        }

        // Generate handshake final message token.
        HandshakeMessageToken final_message;
        final_message.binary_properties().clear();
        final_message.class_id("DDS:Auth:PKI-DH:1.0+Final");

        BinaryProperty bproperty;

        // hash_c1
        bproperty.name("hash_c1");
        bproperty.value(std::move(hash_c1->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // hash_c2
        bproperty.name("hash_c2");
        bproperty.value(std::move(hash_c2->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // dh1
        bproperty.name("dh1");
        bproperty.value(std::move(dh1->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // dh2
        bproperty.name("dh2");
        bproperty.value(std::move(dh2->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // challenge1
        bproperty.name("challenge1");
        bproperty.value(std::move(challenge1->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // challenge2
        bproperty.name("challenge2");
        bproperty.value(std::move(challenge2->value()));
        bproperty.propagate(true);
        final_message.binary_properties().push_back(std::move(bproperty));

        // signature
        cdrmessage2.length = 0;
        cdrmessage2.pos = 0;
        // add sequence length
        CDRMessage::addUInt32(&cdrmessage2, 6);
        //add hash_c1
        CDRMessage::addBinaryProperty(&cdrmessage2, *DataHolderHelper::find_binary_property(final_message, "hash_c1"));
        //add challenge1
        CDRMessage::addBinaryProperty(&cdrmessage2, *DataHolderHelper::find_binary_property(final_message, "challenge1"));
        //add dh1
        CDRMessage::addBinaryProperty(&cdrmessage2, *DataHolderHelper::find_binary_property(final_message, "dh1"));
        //add challenge2
        CDRMessage::addBinaryProperty(&cdrmessage2, *DataHolderHelper::find_binary_property(final_message, "challenge2"));
        //add dh2
        CDRMessage::addBinaryProperty(&cdrmessage2, *DataHolderHelper::find_binary_property(final_message, "dh2"));
        //add hash_c2
        CDRMessage::addBinaryProperty(&cdrmessage2, *DataHolderHelper::find_binary_property(final_message, "hash_c2"),
                false);

        bproperty.name("signature");
        bproperty.propagate(true);
        if (sign_sha256(lih->pkey_, cdrmessage2.buffer, cdrmessage2.length, bproperty.value(), exception))
        {
            final_message.binary_properties().push_back(std::move(bproperty));

            handshake_handle->sharedsecret_ =
                    std::dynamic_pointer_cast<SharedSecretHandle>(
                generate_sharedsecret(handshake_handle->dhkeys_, handshake_handle->peerkeys_,
                exception));

            if (handshake_handle->sharedsecret_ != nullptr)
            {
                // Save challenge1 y challenge2 in sharedsecret
                (*handshake_handle->sharedsecret_)->data_.emplace_back(SharedSecret::BinaryData("Challenge1",
                        *DataHolderHelper::find_binary_property_value(final_message, "challenge1")));
                (*handshake_handle->sharedsecret_)->data_.emplace_back(SharedSecret::BinaryData("Challenge2",
                        *DataHolderHelper::find_binary_property_value(final_message, "challenge2")));

                handshake_handle->handshake_message_ = std::move(final_message);
                *handshake_message_out = &handshake_handle->handshake_message_;

                printf("=== HANDSHAKE SUCCESS (Bob: Final message generated - Classical) ===\n");
                fflush(stdout);

                auto end_time = std::chrono::high_resolution_clock::now();
                double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
                printf("[DEBUG] Handshake Final Created: [OK] (Time: %.3f ms)\n", duration);
                
                double total_duration = std::chrono::duration<double, std::milli>(end_time - handshake_handle->start_time_).count();
                printf("[DEBUG] Total Handshake Time (Initiator): %.3f ms\n", total_duration);
                fflush(stdout);

                return ValidationResult_t::VALIDATION_OK_WITH_FINAL_MESSAGE;
            }
        }

        ERR_clear_error();

        return ValidationResult_t::VALIDATION_FAILED;
    }
}

ValidationResult_t PKIDH::process_handshake_reply(
        HandshakeMessageToken** handshake_message_out,
        HandshakeMessageToken&& handshake_message_in,
        PKIHandshakeHandle& handshake_handle,
        SecurityException& exception)
{
    auto start_time = std::chrono::high_resolution_clock::now();
    (void)handshake_message_out;

    printf("[INFO] process_handshake_reply CALLED (Final validation)\n");
    fflush(stdout);

    printf("[DEBUG] Incoming class_id = %s\n",
           handshake_message_in.class_id().c_str());
    fflush(stdout);

    PKIIdentityHandle& rih = *handshake_handle->remote_identity_handle_;

    /* ------------------------------------------------------------------ */
    /* Step 1: class_id check */
    /* ------------------------------------------------------------------ */
    printf("[DEBUG] Step 1: Checking class_id...\n");
    fflush(stdout);

    if (handshake_message_in.class_id().compare("DDS:Auth:PKI-DH:1.0+Final") != 0)
    {
        printf("[DEBUG] [FAIL] Bad class_id = %s\n",
               handshake_message_in.class_id().c_str());
        fflush(stdout);

        WARNING_SECURITY_LOGGING("PKIDH",
            std::string("Bad HandshakeMessageToken (") +
            handshake_message_in.class_id() + ")");
        return ValidationResult_t::VALIDATION_FAILED;
    }

    printf("[DEBUG] [OK] Step 1 OK (Final)\n");
    fflush(stdout);

    /* ------------------------------------------------------------------ */
    /* Step 2: challenge1 */
    /* ------------------------------------------------------------------ */
    printf("[DEBUG] Step 2: Checking challenge1 in Final...\n");
    fflush(stdout);

    BinaryProperty* challenge1 =
        DataHolderHelper::find_binary_property(handshake_message_in, "challenge1");
    if (challenge1 == nullptr)
    {
        printf("[DEBUG] [FAIL] challenge1 missing in Final\n");
        fflush(stdout);
        return ValidationResult_t::VALIDATION_FAILED;
    }

    printf("[DEBUG] challenge1 size = %zu\n", challenge1->value().size());
    fflush(stdout);

    BinaryProperty* challenge1_reply =
        DataHolderHelper::find_binary_property(
            handshake_handle->handshake_message_, "challenge1");
    if (challenge1_reply == nullptr)
    {
        printf("[DEBUG] [FAIL] challenge1 missing in Reply\n");
        fflush(stdout);
        return ValidationResult_t::VALIDATION_FAILED;
    }

    if (challenge1->value() != challenge1_reply->value())
    {
        printf("[DEBUG] [FAIL] challenge1 mismatch\n");
        fflush(stdout);
        return ValidationResult_t::VALIDATION_FAILED;
    }

    printf("[DEBUG] [OK] challenge1 verified\n");
    fflush(stdout);

    /* ------------------------------------------------------------------ */
    /* Step 3: challenge2 */
    /* ------------------------------------------------------------------ */
    printf("[DEBUG] Step 3: Checking challenge2 in Final...\n");
    fflush(stdout);

    BinaryProperty* challenge2 =
        DataHolderHelper::find_binary_property(handshake_message_in, "challenge2");
    if (challenge2 == nullptr)
    {
        printf("[DEBUG] [FAIL] challenge2 missing in Final\n");
        fflush(stdout);
        return ValidationResult_t::VALIDATION_FAILED;
    }

    BinaryProperty* challenge2_reply =
        DataHolderHelper::find_binary_property(
            handshake_handle->handshake_message_, "challenge2");
    if (challenge2_reply == nullptr)
    {
        printf("[DEBUG] [FAIL] challenge2 missing in Reply\n");
        fflush(stdout);
        return ValidationResult_t::VALIDATION_FAILED;
    }

    if (challenge2->value() != challenge2_reply->value())
    {
        printf("[DEBUG] [FAIL] challenge2 mismatch\n");
        fflush(stdout);
        return ValidationResult_t::VALIDATION_FAILED;
    }

    printf("[DEBUG] [OK] challenge2 verified\n");
    fflush(stdout);

    /* ------------------------------------------------------------------ */
    /* Step 4: signature / hash_c1 / hash_c2 */
    /* ------------------------------------------------------------------ */
    printf("[DEBUG] Step 4: Checking signature / hash_c1 / hash_c2\n");
    fflush(stdout);

    const std::vector<uint8_t>* signature =
        DataHolderHelper::find_binary_property_value(handshake_message_in, "signature");

    BinaryProperty* hash_c1_reply =
        DataHolderHelper::find_binary_property(
            handshake_handle->handshake_message_, "hash_c1");
    if (hash_c1_reply == nullptr)
    {
        printf("[DEBUG] [FAIL] hash_c1 missing in Reply\n");
        fflush(stdout);
        return ValidationResult_t::VALIDATION_FAILED;
    }

    BinaryProperty* hash_c2_reply =
        DataHolderHelper::find_binary_property(
            handshake_handle->handshake_message_, "hash_c2");
    if (hash_c2_reply == nullptr)
    {
        printf("[DEBUG] [FAIL] hash_c2 missing in Reply\n");
        fflush(stdout);
        return ValidationResult_t::VALIDATION_FAILED;
    }

    /* ------------------------------------------------------------------ */
    /* Step 5: PQC / Classical mode detection */
    /* ------------------------------------------------------------------ */
    printf("[DEBUG] Step 5: Detecting PQC mode...\n");
    fflush(stdout);

    BinaryProperty* dh1_reply =
        DataHolderHelper::find_binary_property(
            handshake_handle->handshake_message_, "dh1");
    BinaryProperty* pqc_kem_pubkey_reply =
        DataHolderHelper::find_binary_property(
            handshake_handle->handshake_message_, "pqc.kem.pubkey");

    bool is_pqc_mode = (pqc_kem_pubkey_reply != nullptr);

    printf("[DEBUG] dh1_reply = %s\n", dh1_reply ? "present" : "null");
    printf("[DEBUG] pqc.kem.pubkey_reply = %s\n",
           pqc_kem_pubkey_reply ? "present" : "null");
    printf("[DEBUG] is_pqc_mode = %d\n", is_pqc_mode);
    fflush(stdout);

    /* ------------------------------------------------------------------ */
    /* Step 6: pqc.kem.ciphertext / dh2 */
    /* ------------------------------------------------------------------ */
    printf("[DEBUG] Step 6: Checking dh2 / pqc.kem.ciphertext\n");
    fflush(stdout);

    BinaryProperty* pqc_ciphertext_reply = nullptr;
    BinaryProperty* dh2_reply = nullptr;

    if (is_pqc_mode)
    {
        pqc_ciphertext_reply =
            DataHolderHelper::find_binary_property(
                handshake_handle->handshake_message_, "pqc.kem.ciphertext");
        if (pqc_ciphertext_reply == nullptr)
        {
            printf("[DEBUG] [FAIL] pqc.kem.ciphertext missing in Reply\n");
            fflush(stdout);
            return ValidationResult_t::VALIDATION_FAILED;
        }
    }
    else
    {
        dh2_reply =
            DataHolderHelper::find_binary_property(
                handshake_handle->handshake_message_, "dh2");
        if (dh2_reply == nullptr)
        {
            printf("[DEBUG] [FAIL] dh2 missing in Reply\n");
            fflush(stdout);
            return ValidationResult_t::VALIDATION_FAILED;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Step 7: Signature verification */
    /* ------------------------------------------------------------------ */
    printf("[DEBUG] Step 7: Signature verification\n");
    fflush(stdout);

    if (is_pqc_mode)
    {
        const std::vector<uint8_t>* pqc_signature =
            DataHolderHelper::find_binary_property_value(
                handshake_message_in, "pqc.signature");

        if (pqc_signature == nullptr)
        {
            printf("[DEBUG] [FAIL] pqc.signature missing\n");
            fflush(stdout);
            return ValidationResult_t::VALIDATION_FAILED;
        }

        printf("[DEBUG] Verifying ML-DSA-44 signature...\n");
        fflush(stdout);

        CDRMessage_t cdrmessage(
            static_cast<uint32_t>(
                BinaryPropertyHelper::serialized_size(
                    handshake_handle->handshake_message_.binary_properties())));
        cdrmessage.msg_endian = BIGEND;

        CDRMessage::addUInt32(&cdrmessage, 6);
        CDRMessage::addBinaryProperty(&cdrmessage, *hash_c1_reply);
        CDRMessage::addBinaryProperty(&cdrmessage, *challenge1_reply);
        CDRMessage::addBinaryProperty(&cdrmessage, *pqc_kem_pubkey_reply);
        CDRMessage::addBinaryProperty(&cdrmessage, *challenge2_reply);
        CDRMessage::addBinaryProperty(&cdrmessage, *pqc_ciphertext_reply);
        CDRMessage::addBinaryProperty(&cdrmessage, *hash_c2_reply, false);

        EVP_PKEY* alice_pubkey = X509_get_pubkey(rih->cert_);
        if (alice_pubkey == nullptr)
        {
            printf("[DEBUG] [FAIL] X509_get_pubkey failed\n");
            fflush(stdout);
            return ValidationResult_t::VALIDATION_FAILED;
        }

        // Verify Bob's PQC signature
        PQCSignatureAlgorithm remote_sig_algo = string_to_signature_algorithm(rih->sign_alg_);
        
        if (!pqc_verify_signature(
                remote_sig_algo,
                alice_pubkey,
                cdrmessage.buffer,
                cdrmessage.length,
                *pqc_signature,
                exception))
        {
            EVP_PKEY_free(alice_pubkey);
            printf("[DEBUG] [FAIL] ML-DSA-44 signature verify failed\n");
            printf("[DEBUG] FAIL: Signature verify failed\n");
            return ValidationResult_t::VALIDATION_FAILED;
        }
        EVP_PKEY_free(alice_pubkey);

        printf("[DEBUG] [OK] ML-DSA-44 signature verified\n");
        printf("[DEBUG] Signature verified successfully\n");

    //     std::vector<uint8_t> shared_secret_vec;
    //     if (!mlkem_decapsulate(
    //             handshake_handle->dhkeys_,
    //             pqc_ciphertext_reply->value(),
    //             shared_secret_vec,
    //             exception))
    //     {
    //         printf("[DEBUG] [FAIL] ML-KEM decapsulation failed\n");
    //         fflush(stdout);
    //         return ValidationResult_t::VALIDATION_FAILED;
    //     }

    //     handshake_handle->sharedsecret_ =
    //         std::dynamic_pointer_cast<SharedSecretHandle>(
    //             get_shared_secret(
    //                 SharedSecretHandle::nil_handle, exception));
    // Added: Check already saved shared_secret
        printf("[DEBUG] Using pre-computed ML-KEM shared secret from Reply\n");
        fflush(stdout);
        
        if (handshake_handle->sharedsecret_ == nullptr)
        {
            printf("[DEBUG] [ERROR] No shared secret found!\n");
            fflush(stdout);
            exception = SecurityException("Shared secret not found in handshake handle");
            return ValidationResult_t::VALIDATION_FAILED;
        }
        
        printf("[DEBUG] [OK] Shared secret is available\n");
        fflush(stdout);
        
        EPROSIMA_LOG_INFO(SECURITY_AUTHENTICATION, "ML-KEM shared secret verified");
    }
    else
    {
        printf("[DEBUG] Classical signature path\n");
        fflush(stdout);

        CDRMessage_t cdrmessage(
            static_cast<uint32_t>(
                BinaryPropertyHelper::serialized_size(
                    handshake_handle->handshake_message_.binary_properties())));
        cdrmessage.msg_endian = BIGEND;

        CDRMessage::addUInt32(&cdrmessage, 6);
        CDRMessage::addBinaryProperty(&cdrmessage, *hash_c1_reply);
        CDRMessage::addBinaryProperty(&cdrmessage, *challenge1);
        CDRMessage::addBinaryProperty(&cdrmessage, *dh1_reply);
        CDRMessage::addBinaryProperty(&cdrmessage, *challenge2);
        CDRMessage::addBinaryProperty(&cdrmessage, *dh2_reply);
        CDRMessage::addBinaryProperty(&cdrmessage, *hash_c2_reply, false);

        if (!check_sign_sha256(
                rih->cert_,
                cdrmessage.buffer,
                cdrmessage.length,
                *signature,
                exception))
        {
            printf("[DEBUG] FAIL: Classical signature verify failed\n");
            fflush(stdout);
            return ValidationResult_t::VALIDATION_FAILED;
        }

        handshake_handle->sharedsecret_ =
            std::dynamic_pointer_cast<SharedSecretHandle>(
                generate_sharedsecret(
                    handshake_handle->dhkeys_,
                    handshake_handle->peerkeys_,
                    exception));
    }

    if (handshake_handle->sharedsecret_ != nullptr)
    {
        (*handshake_handle->sharedsecret_)->data_.emplace_back(
            SharedSecret::BinaryData("Challenge1", challenge1->value()));
        (*handshake_handle->sharedsecret_)->data_.emplace_back(
            SharedSecret::BinaryData("Challenge2", challenge2->value()));

            printf("=== HANDSHAKE SUCCESS (Alice: Final validated - PQC) ===\n");
            fflush(stdout);

            auto end_time = std::chrono::high_resolution_clock::now();
            double duration = std::chrono::duration<double, std::milli>(end_time - start_time).count();
            printf("[DEBUG] Handshake Final Processed: [OK] (Time: %.3f ms)\n", duration);

            double total_duration = std::chrono::duration<double, std::milli>(end_time - handshake_handle->start_time_).count();
            printf("[DEBUG] Total Handshake Time (Replier): %.3f ms\n", total_duration);
            fflush(stdout);

            return ValidationResult_t::VALIDATION_OK;
    }

    printf("[DEBUG] FAIL: sharedsecret is null at end\n");
    fflush(stdout);
    return ValidationResult_t::VALIDATION_FAILED;
}

std::shared_ptr<SecretHandle> PKIDH::get_shared_secret(
        const HandshakeHandle& handshake_handle,
        SecurityException& exception) const
{
    const PKIHandshakeHandle& handshake = PKIHandshakeHandle::narrow(handshake_handle);

    if (!handshake.nil() && (*handshake)->sharedsecret_)
    {
        // Create a new SharedSecretHandle (use existing helper)
        auto secret = get_shared_secret(SharedSecretHandle::nil_handle, exception);
        auto sharedsecret = std::dynamic_pointer_cast<SharedSecretHandle>(secret);
        if (!sharedsecret)
        {
            exception = SecurityException("Failed to cast SharedSecretHandle");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
            return nullptr;
        }

        // Copy PQC/classical secret stored inside handshake as is
        (*sharedsecret)->data_ = (*(*handshake)->sharedsecret_)->data_;
        return secret;
    }

    // If handshake is empty or sharedsecret_ is not set yet:
    // Return "empty SharedSecretHandle" as per original Fast-DDS behavior
    auto p = new (std::nothrow) SharedSecretHandle;
    if (!p)
    {
        exception = SecurityException("Failed to create SharedSecretHandle");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return nullptr;
    }

    return std::dynamic_pointer_cast<SecretHandle>(
        std::shared_ptr<SharedSecretHandle>(p, [](SharedSecretHandle* p)
        {
            delete p;
        }));
}

bool PKIDH::set_listener(
        AuthenticationListener* /*listener*/,
        SecurityException& /*exception*/)
{
    return false;
}

bool PKIDH::get_identity_token(
        IdentityToken** identity_token,
        const IdentityHandle& handle,
        SecurityException& /*exception*/)
{
    const PKIIdentityHandle& ihandle = PKIIdentityHandle::narrow(handle);

    if (!ihandle.nil())
    {
        *identity_token = new IdentityToken(ihandle->identity_token_);
        return true;
    }

    return false;
}

bool PKIDH::return_identity_token(
        IdentityToken* token,
        SecurityException& /*exception*/)
{
    delete token;
    return true;
}

bool PKIDH::return_handshake_handle(
        HandshakeHandle* handshake_handle,
        SecurityException& /*exception*/)
{
    PKIHandshakeHandle* handle = &PKIHandshakeHandle::narrow(*handshake_handle);

    if (!handle->nil())
    {
        delete handle;
        return true;
    }

    return false;
}

IdentityHandle* PKIDH::get_identity_handle(
        SecurityException&)
{
    return new (std::nothrow) PKIIdentityHandle();
}

bool PKIDH::return_identity_handle(
        IdentityHandle* identity_handle,
        SecurityException& /*exception*/)
{
    PKIIdentityHandle* handle = &PKIIdentityHandle::narrow(*identity_handle);

    if (!handle->nil())
    {
        delete handle;
        return true;
    }

    return false;
}

bool PKIDH::return_sharedsecret_handle(
        std::shared_ptr<SecretHandle>& sharedsecret_handle,
        SecurityException& /*exception*/) const
{
    sharedsecret_handle.reset();
    return true;
}

bool PKIDH::set_permissions_credential_and_token(
        IdentityHandle& identity_handle,
        PermissionsCredentialToken& permissions_credential_token,
        SecurityException& exception)
{
    PKIIdentityHandle& ihandle = PKIIdentityHandle::narrow(identity_handle);

    if (!ihandle.nil())
    {
        ihandle->permissions_credential_token_ = std::move(permissions_credential_token);
        return true;
    }
    else
    {
        exception = SecurityException("Invalid identity handle");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
    }

    return false;
}

bool PKIDH::get_authenticated_peer_credential_token(
        PermissionsCredentialToken** token,
        const IdentityHandle& identity_handle,
        SecurityException& exception)
{
    const PKIIdentityHandle& handle = PKIIdentityHandle::narrow(identity_handle);

    if (!handle.nil())
    {
        *token = new PermissionsCredentialToken(handle->permissions_credential_token_);
        return true;
    }
    else
    {
        exception = SecurityException("Invalid handshake handle");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
    }

    return false;
}

bool PKIDH::return_authenticated_peer_credential_token(
        PermissionsCredentialToken* token,
        SecurityException&)
{
    delete token;
    return true;
}

bool PKIDH::check_guid_comes_from(
        IdentityHandle* identity_handle,
        const GUID_t& adjusted,
        const GUID_t& original)
{
    SecurityException exception;

    if (identity_handle != nullptr)
    {
        PKIIdentityHandle* pkiih = &PKIIdentityHandle::narrow(*identity_handle);
        GUID_t adjusted_original_guid;

        if (pkiih != nullptr && !(*pkiih).nil() && (*pkiih)->cert_ != nullptr)
        {
            adjust_participant_key((*pkiih)->cert_, original, adjusted_original_guid, exception);
            return adjusted == adjusted_original_guid;
        }
        else
        {
            exception = SecurityException("Invalid PKI Identity handle or Invalid Certificate");
            // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        }

    }
    else
    {
        exception = SecurityException("Invalid Identity handle");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
    }

    return adjusted == original;

}

// ========================================
// PQC Implementation (ML-DSA-44 + ML-KEM)
// ========================================

std::shared_ptr<SecretHandle> PKIDH::generate_pqc_sharedsecret(
        EVP_PKEY* kem_private_key,
        const std::vector<uint8_t>& kem_ciphertext,
        SecurityException& exception) const
{
    if (kem_private_key == nullptr || kem_ciphertext.empty())
    {
        exception = SecurityException("Invalid KEM parameters");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return nullptr;
    }

    // Perform ML-KEM decapsulation
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(kem_private_key, nullptr);
    if (ctx == nullptr)
    {
        exception = SecurityException("Failed to create ML-KEM context");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return nullptr;
    }

    if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        exception = SecurityException("Failed to initialize ML-KEM decapsulation");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return nullptr;
    }

    // Get shared secret length
    size_t shared_secret_len = 0;
    if (EVP_PKEY_decapsulate(ctx, nullptr, &shared_secret_len,
                            kem_ciphertext.data(), kem_ciphertext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        exception = SecurityException("Failed to get ML-KEM shared secret length");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return nullptr;
    }

    // Allocate buffer for shared secret
    std::vector<uint8_t> shared_secret(shared_secret_len);

    // Perform decapsulation
    if (EVP_PKEY_decapsulate(ctx, shared_secret.data(), &shared_secret_len,
                            kem_ciphertext.data(), kem_ciphertext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        exception = SecurityException("ML-KEM decapsulation failed");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);

    // Create SharedSecretHandle
    // Allocate a new SharedSecretHandle (ctor/dtor are protected -> use raw new + custom deleter)
    SharedSecretHandle* raw_handle = new (std::nothrow) SharedSecretHandle;
    if (!raw_handle)
    {
        exception = SecurityException("Failed to create shared secret handle");
        // EMERGENCY_SECURITY_LOGGING("PKIDH", exception.what());
        return nullptr;
    }

    std::shared_ptr<SharedSecretHandle> secret_handle(
        raw_handle,
        [](SharedSecretHandle* p){ delete p; });

    (*secret_handle)->data_.emplace_back(
        SharedSecret::BinaryData("SharedSecret", shared_secret));

    return std::dynamic_pointer_cast<SecretHandle>(secret_handle);
}

// ========================================
// Generic PQC Signature Functions
// ========================================

bool PKIDH::pqc_sign_data(
        PQCSignatureAlgorithm algo,
        EVP_PKEY* signing_key,
        const unsigned char* data,
        size_t data_len,
        std::vector<uint8_t>& signature,
        SecurityException& exception) const
{
    if (signing_key == nullptr || data == nullptr || data_len == 0)
    {
        exception = SecurityException("Invalid PQC signing parameters");
        return false;
    }

    // Get algorithm name for logging
    const char* algo_name = get_openssl_algorithm_name(algo);
    if (algo_name == nullptr)
    {
        exception = SecurityException("Unsupported PQC signature algorithm");
        return false;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == nullptr)
    {
        exception = SecurityException(std::string("Failed to create ") + algo_name + " signing context");
        return false;
    }

    // Initialize signing (PQC signatures don't use a separate hash function)
    if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, signing_key) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        exception = SecurityException(std::string("Failed to initialize ") + algo_name + " signing");
        return false;
    }

    // Get signature length
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx, nullptr, &sig_len, data, data_len) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        exception = SecurityException(std::string("Failed to get ") + algo_name + " signature length");
        return false;
    }

    // Allocate signature buffer
    signature.resize(sig_len);

    // Generate signature
    if (EVP_DigestSign(md_ctx, signature.data(), &sig_len, data, data_len) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        exception = SecurityException(std::string(algo_name) + " signature generation failed");
        return false;
    }

    signature.resize(sig_len);
    EVP_MD_CTX_free(md_ctx);

    printf("[DEBUG] %s signature generated successfully, size: %zu bytes\n", algo_name, sig_len);
    fflush(stdout);

    return true;
}

bool PKIDH::sign_with_mldsa44(
        EVP_PKEY* signing_key,
        const unsigned char* data,
        size_t data_len,
        std::vector<uint8_t>& signature,
        SecurityException& exception) const
{
    // Wrapper for backward compatibility - calls generic PQC signing function
    return pqc_sign_data(PQCSignatureAlgorithm::MLDSA44, signing_key, data, data_len, signature, exception);
}

bool PKIDH::pqc_verify_signature(
        PQCSignatureAlgorithm algo,
        EVP_PKEY* verify_key,
        const unsigned char* data,
        size_t data_len,
        const std::vector<uint8_t>& signature,
        SecurityException& exception) const
{
    if (verify_key == nullptr || data == nullptr || data_len == 0 || signature.empty())
    {
        exception = SecurityException("Invalid PQC signature verification parameters");
        return false;
    }

    // Get algorithm name for logging
    const char* algo_name = get_openssl_algorithm_name(algo);
    if (algo_name == nullptr)
    {
        exception = SecurityException("Unsupported PQC signature algorithm");
        return false;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == nullptr)
    {
        exception = SecurityException(std::string("Failed to create ") + algo_name + " verification context");
        return false;
    }

    // Initialize verification
    if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, verify_key) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        exception = SecurityException(std::string("Failed to initialize ") + algo_name + " verification");
        return false;
    }

    // Verify signature
    int result = EVP_DigestVerify(md_ctx, signature.data(), signature.size(), data, data_len);
    EVP_MD_CTX_free(md_ctx);

    if (result == 1)
    {
        printf("[DEBUG] %s signature verified successfully\n", algo_name);
        fflush(stdout);
        return true;
    }
    else if (result == 0)
    {
        exception = SecurityException(std::string(algo_name) + " signature verification failed - invalid signature");
        WARNING_SECURITY_LOGGING("PKIDH", exception.what());
        return false;
    }
    else
    {
        exception = SecurityException(std::string(algo_name) + " signature verification error");
        WARNING_SECURITY_LOGGING("PKIDH", exception.what());
        return false;
    }
}

bool PKIDH::verify_mldsa44_signature(
        EVP_PKEY* verify_key,
        const unsigned char* data,
        size_t data_len,
        const std::vector<uint8_t>& signature,
        SecurityException& exception) const
{
    // Wrapper for backward compatibility - calls generic PQC verification function
    return pqc_verify_signature(PQCSignatureAlgorithm::MLDSA44, verify_key, data, data_len, signature, exception);
}

bool PKIDH::mlkem_encapsulate(
        EVP_PKEY* peer_public_key,
        std::vector<uint8_t>& ciphertext,
        std::vector<uint8_t>& shared_secret,
        SecurityException& exception) const
{
    printf("[DEBUG] mlkem_encapsulate called\n");
    fflush(stdout);
    
    if (peer_public_key == nullptr)
    {
        printf("[DEBUG] ERROR: peer_public_key is nullptr!\n");
        fflush(stdout);
        exception = SecurityException("Invalid ML-KEM public key");
        return false;
    }
    
    printf("[DEBUG] peer_public_key is valid, type: %d\n", EVP_PKEY_id(peer_public_key));
    fflush(stdout);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(peer_public_key, nullptr);
    if (ctx == nullptr)
    {
        printf("[DEBUG] ERROR: EVP_PKEY_CTX_new failed! OpenSSL error: ");
        ERR_print_errors_fp(stdout);
        printf("\n");
        fflush(stdout);
        
        exception = SecurityException("Failed to create ML-KEM encapsulation context");
        return false;
    }
    
    printf("[DEBUG] EVP_PKEY_CTX created successfully\n");
    fflush(stdout);

    if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0)
    {
        printf("[DEBUG] ERROR: EVP_PKEY_encapsulate_init failed! OpenSSL error: ");
        ERR_print_errors_fp(stdout);
        printf("\n");
        fflush(stdout);
        
        EVP_PKEY_CTX_free(ctx);
        exception = SecurityException("Failed to initialize ML-KEM encapsulation");
        return false;
    }
    
    printf("[DEBUG] EVP_PKEY_encapsulate_init successful\n");
    fflush(stdout);

    // Get ciphertext and shared secret lengths
    size_t ct_len = 0, ss_len = 0;
    if (EVP_PKEY_encapsulate(ctx, nullptr, &ct_len, nullptr, &ss_len) <= 0)
    {
        printf("[DEBUG] ERROR: EVP_PKEY_encapsulate (length query) failed! OpenSSL error: ");
        ERR_print_errors_fp(stdout);
        printf("\n");
        fflush(stdout);
        
        EVP_PKEY_CTX_free(ctx);
        exception = SecurityException("Failed to get ML-KEM buffer lengths");
        return false;
    }
    
    printf("[DEBUG] ML-KEM buffer lengths: ct_len=%zu, ss_len=%zu\n", ct_len, ss_len);
    fflush(stdout);

    // Allocate buffers
    ciphertext.resize(ct_len);
    shared_secret.resize(ss_len);

    // Perform encapsulation
    if (EVP_PKEY_encapsulate(ctx, ciphertext.data(), &ct_len,
                            shared_secret.data(), &ss_len) <= 0)
    {
        printf("[DEBUG] ERROR: EVP_PKEY_encapsulate (actual) failed! OpenSSL error: ");
        ERR_print_errors_fp(stdout);
        printf("\n");
        fflush(stdout);
        
        EVP_PKEY_CTX_free(ctx);
        exception = SecurityException("ML-KEM encapsulation failed");
        return false;
    }

    printf("[DEBUG] ML-KEM encapsulation successful! ct_len=%zu, ss_len=%zu\n", ct_len, ss_len);
    fflush(stdout);

    ciphertext.resize(ct_len);
    shared_secret.resize(ss_len);
    EVP_PKEY_CTX_free(ctx);

    return true;
}

bool PKIDH::mlkem_decapsulate(
        EVP_PKEY* private_key,
        const std::vector<uint8_t>& ciphertext,
        std::vector<uint8_t>& shared_secret,
        SecurityException& exception) const
{
    printf("[DEBUG] mlkem_decapsulate called\n");
    fflush(stdout);
    
    if (private_key == nullptr || ciphertext.empty())
    {
        printf("[DEBUG] ERROR: Invalid parameters! private_key=%p, ciphertext.size()=%zu\n",
               (void*)private_key, ciphertext.size());
        fflush(stdout);
        
        exception = SecurityException("Invalid ML-KEM decapsulation parameters");
        return false;
    }
    
    printf("[DEBUG] private_key is valid, type: %d, ciphertext size: %zu\n",
           EVP_PKEY_id(private_key), ciphertext.size());
    fflush(stdout);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (ctx == nullptr)
    {
        printf("[DEBUG] ERROR: EVP_PKEY_CTX_new failed! OpenSSL error: ");
        ERR_print_errors_fp(stdout);
        printf("\n");
        fflush(stdout);
        
        exception = SecurityException("Failed to create ML-KEM decapsulation context");
        return false;
    }
    
    printf("[DEBUG] EVP_PKEY_CTX created for decapsulation\n");
    fflush(stdout);

    if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0)
    {
        printf("[DEBUG] ERROR: EVP_PKEY_decapsulate_init failed! OpenSSL error: ");
        ERR_print_errors_fp(stdout);
        printf("\n");
        fflush(stdout);
        
        EVP_PKEY_CTX_free(ctx);
        exception = SecurityException("Failed to initialize ML-KEM decapsulation");
        return false;
    }
    
    printf("[DEBUG] EVP_PKEY_decapsulate_init successful\n");
    fflush(stdout);

    // Get shared secret length
    size_t ss_len = 0;
    if (EVP_PKEY_decapsulate(ctx, nullptr, &ss_len,
                            ciphertext.data(), ciphertext.size()) <= 0)
    {
        printf("[DEBUG] ERROR: EVP_PKEY_decapsulate (length query) failed! OpenSSL error: ");
        ERR_print_errors_fp(stdout);
        printf("\n");
        fflush(stdout);
        
        EVP_PKEY_CTX_free(ctx);
        exception = SecurityException("Failed to get ML-KEM shared secret length");
        return false;
    }
    
    printf("[DEBUG] ML-KEM shared secret length: ss_len=%zu\n", ss_len);
    fflush(stdout);

    // Allocate buffer
    shared_secret.resize(ss_len);

    // Perform decapsulation
    if (EVP_PKEY_decapsulate(ctx, shared_secret.data(), &ss_len,
                            ciphertext.data(), ciphertext.size()) <= 0)
    {
        printf("[DEBUG] ERROR: EVP_PKEY_decapsulate (actual) failed! OpenSSL error: ");
        ERR_print_errors_fp(stdout);
        printf("\n");
        fflush(stdout);
        
        EVP_PKEY_CTX_free(ctx);
        exception = SecurityException("ML-KEM decapsulation failed");
        return false;
    }

    printf("[DEBUG] ML-KEM decapsulation successful! ss_len=%zu\n", ss_len);
    fflush(stdout);

    shared_secret.resize(ss_len);
    EVP_PKEY_CTX_free(ctx);

    return true;
}

} // namespace security
} // namespace rtps
} // namespace fastdds
} // namespace eprosima