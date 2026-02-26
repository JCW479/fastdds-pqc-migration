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
 * @file PKIHandshakeHandle.h
 */

#ifndef _SECURITY_AUTHENTICATION_PKIHANDSHAKEHANDLE_H_
#define _SECURITY_AUTHENTICATION_PKIHANDSHAKEHANDLE_H_

#include <security/authentication/PKIIdentityHandle.h>
#include <chrono>

#include <fastdds/rtps/security/common/Handle.h>
#include <fastdds/rtps/common/Token.h>
#include <fastdds/rtps/security/authentication/Handshake.h>

#include <fastdds/rtps/security/common/SharedSecretHandle.h>

#include <openssl/evp.h>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

class PKIHandshake
{
public:

    PKIHandshake()
        : local_identity_handle_(nullptr)
        , remote_identity_handle_(nullptr)
        , dhkeys_(nullptr)   // Used as KEM private key (Bsk) in PQC mode
        , peerkeys_(nullptr) // Used as KEM peer public key (Bpk) in PQC mode
    {
    }

    ~PKIHandshake()
    {
        if (dhkeys_ != nullptr)
        {
            EVP_PKEY_free(dhkeys_);
        }

        if (peerkeys_ != nullptr)
        {
            EVP_PKEY_free(peerkeys_);
        }
    }

    static const char* const class_id_;

    const PKIIdentityHandle* local_identity_handle_;
    PKIIdentityHandle* remote_identity_handle_;

    EVP_PKEY* dhkeys_;   // DH/ECDH or ML-KEM private key
    EVP_PKEY* peerkeys_; // DH/ECDH or ML-KEM peer public key

    std::string kagree_alg_; // "DH+MODP-2048-256", "ECDH+prime256v1-CEUM", or "ML-KEM-768"

    HandshakeMessageToken handshake_message_;

    std::shared_ptr<SharedSecretHandle> sharedsecret_;

    std::chrono::high_resolution_clock::time_point start_time_;
};

class PKIDH;

typedef HandleImpl<PKIHandshake, PKIDH> PKIHandshakeHandle;

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima

#endif // _SECURITY_AUTHENTICATION_PKIHANDSHAKEHANDLE_H_