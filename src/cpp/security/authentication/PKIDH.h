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
 * @file PKIDH.h
 */
#ifndef _SECURITY_AUTHENTICATION_PKIDH_H_
#define _SECURITY_AUTHENTICATION_PKIDH_H_

#include <fastdds/rtps/security/authentication/Authentication.h>
#include <fastdds/rtps/security/common/SharedSecretHandle.h>
#include <fastdds/rtps/common/Guid.h>

#include <openssl/evp.h>

#include <security/authentication/PKIHandshakeHandle.h>
#include <memory>
#include <vector>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

namespace detail
{
    class Pkcs11Provider;
}

class PKIDH : public Authentication
{
public:

    PKIDH();

    
    ~PKIDH() override;

    /**
     * @brief Validates a local identity credential set.
     */
    ValidationResult_t validate_local_identity(
            IdentityHandle** local_identity_handle,
            GUID_t& adjusted_participant_key,
            const uint32_t domain_id,
            const RTPSParticipantAttributes& participant_attr,
            const GUID_t& candidate_participant_key,
            SecurityException& exception) override;

    /**
     * @brief Validates a remote identity credential set.
     */
    ValidationResult_t validate_remote_identity(
            IdentityHandle** remote_identity_handle,
            const IdentityHandle& local_identity_handle,
            const IdentityToken& remote_identity_token,
            const GUID_t& remote_participant_key,
            SecurityException& exception) override;

    /**
     * @brief Starts the handshake as the initiator.
     */
    ValidationResult_t begin_handshake_request(
            HandshakeHandle** handshake_handle,
            HandshakeMessageToken** handshake_message,
            const IdentityHandle& initiator_identity_handle,
            IdentityHandle& replier_identity_handle,
            const CDRMessage_t& cdr_participant_data,
            SecurityException& exception) override;

    /**
     * @brief Starts the handshake as the replier.
     */
    ValidationResult_t begin_handshake_reply(
            HandshakeHandle** handshake_handle,
            HandshakeMessageToken** handshake_message_out,
            HandshakeMessageToken&& handshake_message_in,
            IdentityHandle& initiator_identity_handle,
            const IdentityHandle& replier_identity_handle,
            const CDRMessage_t& cdr_participant_data,
            SecurityException& exception) override;

    /**
     * @brief Processes a handshake message.
     */
    ValidationResult_t process_handshake(
            HandshakeMessageToken** handshake_message_out,
            HandshakeMessageToken&& handshake_message_in,
            HandshakeHandle& handshake_handle,
            SecurityException& exception) override;

    /**
     * @brief Get the shared secret.
     */
    std::shared_ptr<SecretHandle> get_shared_secret(
            const HandshakeHandle& handshake_handle,
            SecurityException& exception) const override;

    /**
     * @brief Set an authentication listener.
     */
    bool set_listener(
            AuthenticationListener* listener,
            SecurityException& exception) override;

    /**
     * @brief Get the identity token.
     */
    bool get_identity_token(
            IdentityToken** identity_token,
            const IdentityHandle& handle,
            SecurityException& exception) override;

    /**
     * @brief Return the identity token.
     */
    bool return_identity_token(
            IdentityToken* token,
            SecurityException& exception) override;

    /**
     * @brief Return the handshake handle.
     */
    bool return_handshake_handle(
            HandshakeHandle* handshake_handle,
            SecurityException& exception) override;

    /**
     * @brief Get an identity handle.
     */
    IdentityHandle* get_identity_handle(
            SecurityException& exception) override;

    /**
     * @brief Return the identity handle.
     */
    bool return_identity_handle(
            IdentityHandle* identity_handle,
            SecurityException& exception) override;

    /**
     * @brief Return the shared secret handle.
     */
    bool return_sharedsecret_handle(
            std::shared_ptr<SecretHandle>& sharedsecret_handle,
            SecurityException& exception) const override;

    /**
     * @brief Set permissions credential token in an identity handle.
     */
    bool set_permissions_credential_and_token(
            IdentityHandle& identity_handle,
            PermissionsCredentialToken& permissions_credential_token,
            SecurityException& exception) override;

    /**
     * @brief Get the peer permissions credential token.
     */
    bool get_authenticated_peer_credential_token(
            PermissionsCredentialToken** token,
            const IdentityHandle& identity_handle,
            SecurityException& exception) override;

    /**
     * @brief Return the peer permissions credential token.
     */
    bool return_authenticated_peer_credential_token(
            PermissionsCredentialToken* token,
            SecurityException& exception) override;

    /**
     * @brief Check whether a GUID comes from another.
     */
    bool check_guid_comes_from(
            IdentityHandle* identity_handle,
            const GUID_t& adjusted,
            const GUID_t& original) override;

    // ========================================
    // PQC helper functions (ML-DSA-44 + ML-KEM)
    // ========================================

    /**
     * @brief Generate a PQC shared secret using ML-KEM decapsulation.
     *
     * This is a helper used in the PQC handshake path.
     */
    std::shared_ptr<SecretHandle> generate_pqc_sharedsecret(
            EVP_PKEY* kem_private_key,
            const std::vector<uint8_t>& kem_ciphertext,
            SecurityException& exception) const;

    /**
     * @brief Generic PQC signature function (supports ML-DSA-44, Falcon-512, SPHINCS-128F).
     */
    bool pqc_sign_data(
            PQCSignatureAlgorithm algo,
            EVP_PKEY* signing_key,
            const unsigned char* data,
            size_t data_len,
            std::vector<uint8_t>& signature,
            SecurityException& exception) const;

    /**
     * @brief Generic PQC signature verification (supports ML-DSA-44, Falcon-512, SPHINCS-128F).
     */
    bool pqc_verify_signature(
            PQCSignatureAlgorithm algo,
            EVP_PKEY* verify_key,
            const unsigned char* data,
            size_t data_len,
            const std::vector<uint8_t>& signature,
            SecurityException& exception) const;

    /**
     * @brief Sign handshake data using ML-DSA-44 (backward compatibility wrapper).
     */
    bool sign_with_mldsa44(
            EVP_PKEY* signing_key,
            const unsigned char* data,
            size_t data_len,
            std::vector<uint8_t>& signature,
            SecurityException& exception) const;

    /**
     * @brief Verify ML-DSA-44 signature (backward compatibility wrapper).
     */
    bool verify_mldsa44_signature(
            EVP_PKEY* verify_key,
            const unsigned char* data,
            size_t data_len,
            const std::vector<uint8_t>& signature,
            SecurityException& exception) const;

    /**
     * @brief ML-KEM encapsulation helper.
     */
    bool mlkem_encapsulate(
            EVP_PKEY* peer_public_key,
            std::vector<uint8_t>& ciphertext,
            std::vector<uint8_t>& shared_secret,
            SecurityException& exception) const;

    /**
     * @brief ML-KEM decapsulation helper.
     */
    bool mlkem_decapsulate(
            EVP_PKEY* private_key,
            const std::vector<uint8_t>& ciphertext,
            std::vector<uint8_t>& shared_secret,
            SecurityException& exception) const;

    std::unique_ptr<detail::Pkcs11Provider> pkcs11_provider;

private:

    /**
     * @brief Classic DH/ECDH-based shared secret generation function.
     *        Declared to match the implementation in PKIDH.cpp.
     */
    std::shared_ptr<SecretHandle> generate_sharedsecret(
            EVP_PKEY* private_key,
            EVP_PKEY* public_key,
            SecurityException& exception) const;

    /**
     * @brief Internal function for processing Handshake Request.
     *        Declared to match the implementation signature in PKIDH.cpp.
     */
    ValidationResult_t process_handshake_request(
            HandshakeMessageToken** handshake_message_out,
            HandshakeMessageToken&& handshake_message_in,
            PKIHandshakeHandle& handshake_handle,
            SecurityException& exception);

    /**
     * @brief Internal function for processing Handshake Reply.
     *        Declared to match the implementation signature in PKIDH.cpp.
     */
    ValidationResult_t process_handshake_reply(
            HandshakeMessageToken** handshake_message_out,
            HandshakeMessageToken&& handshake_message_in,
            PKIHandshakeHandle& handshake_handle,
            SecurityException& exception);

    AuthenticationListener* listener_ { nullptr };
};

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima

#endif // _SECURITY_AUTHENTICATION_PKIDH_H_