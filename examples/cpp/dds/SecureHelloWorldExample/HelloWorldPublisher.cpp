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

/**
 * @file HelloWorldPublisher.cpp
 *
 */

#include "HelloWorldPublisher.h"

#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/subscriber/SampleInfo.hpp>

#include <cstdlib>
#include <string>

using namespace eprosima::fastdds::dds;

HelloWorldPublisher::HelloWorldPublisher()
    : participant_(nullptr)
    , publisher_(nullptr)
    , topic_(nullptr)
    , writer_(nullptr)
    , type_(new HelloWorldPubSubType())
{
}

bool HelloWorldPublisher::init()
{
    hello_.index(0);
    hello_.message("HelloWorld");

    // CREATE THE PARTICIPANT
    DomainParticipantQos pqos;
    DomainParticipantFactory::get_instance()->get_default_participant_qos(pqos);

    // --- Decide handshake mode (dual-mode) ---
    // FASTDDS_HANDSHAKE_MODE=PQC  -> PQC handshake + PQC identity chain
    // otherwise                  -> classical handshake + classical identity chain
    const char* mode_env = std::getenv("FASTDDS_HANDSHAKE_MODE");
    const bool use_pqc = (mode_env != nullptr) && (std::string(mode_env) == "PQC");

    // --- Authentication plugin (PKI-DH / your modified PKIDH lives behind this) ---
    pqos.properties().properties().emplace_back("dds.sec.auth.plugin", "builtin.PKI-DH");

    if (use_pqc)
    {
        // Trigger PQC handshake path in your modified PKIDH
        pqos.properties().properties().emplace_back(
                "dds.sec.auth.builtin.PKI-DH.preferred_key_agreement",
                "ML-KEM-512");

        // Identity chain for handshake (PQC: ML-DSA)
        pqos.properties().properties().emplace_back(
                "dds.sec.auth.builtin.PKI-DH.identity_ca",
                "file://certs/auth_pqc/pqc_ca_cert.pem");
        pqos.properties().properties().emplace_back(
                "dds.sec.auth.builtin.PKI-DH.identity_certificate",
                "file://certs/auth_pqc/pub_cert.pem");
        pqos.properties().properties().emplace_back(
                "dds.sec.auth.builtin.PKI-DH.private_key",
                "file://certs/auth_pqc/pub_key.pem");
    }
    else
    {
        // Classical identity chain for handshake (stock PKI-DH)
        pqos.properties().properties().emplace_back(
                "dds.sec.auth.builtin.PKI-DH.identity_ca",
                "file://certs/auth_classical/maincacert.pem");
        pqos.properties().properties().emplace_back(
                "dds.sec.auth.builtin.PKI-DH.identity_certificate",
                "file://certs/auth_classical/mainpubcert.pem");
        pqos.properties().properties().emplace_back(
                "dds.sec.auth.builtin.PKI-DH.private_key",
                "file://certs/auth_classical/mainpubkey.pem");
    }

    // --- AccessControl plugin (A-plan: keep classical CMS) ---
    pqos.properties().properties().emplace_back("dds.sec.access.plugin", "builtin.Access-Permissions");

    // CA used to validate governance/permissions CMS signatures
    pqos.properties().properties().emplace_back(
        "dds.sec.access.builtin.Access-Permissions.permissions_ca",
        "file://certs/maincacert.pem");

    pqos.properties().properties().emplace_back(
            "dds.sec.access.builtin.Access-Permissions.governance",
            "file://certs/governance.smime");

    pqos.properties().properties().emplace_back(
            "dds.sec.access.builtin.Access-Permissions.permissions",
            "file://certs/permissions.smime");

    // --- Crypto plugin (AES-GCM-GMAC) ---
    pqos.properties().properties().emplace_back("dds.sec.crypto.plugin", "builtin.AES-GCM-GMAC");

    participant_ = DomainParticipantFactory::get_instance()->create_participant(0, pqos);

    if (participant_ == nullptr)
    {
        return false;
    }

    // REGISTER THE TYPE
    type_.register_type(participant_);

    // CREATE THE PUBLISHER
    publisher_ = participant_->create_publisher(PUBLISHER_QOS_DEFAULT);

    if (publisher_ == nullptr)
    {
        return false;
    }

    // CREATE THE TOPIC
    topic_ = participant_->create_topic("HelloWorldTopic", "HelloWorld", TOPIC_QOS_DEFAULT);

    if (topic_ == nullptr)
    {
        return false;
    }

    // CREATE THE DATAWRITER
    DataWriterQos wqos;
    wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    wqos.history().kind = KEEP_LAST_HISTORY_QOS;
    wqos.history().depth = 20;
    wqos.resource_limits().max_samples = 50;
    wqos.resource_limits().max_samples_per_instance = 20;
    wqos.reliable_writer_qos().times.heartbeatPeriod.seconds = 2;
    wqos.reliable_writer_qos().times.heartbeatPeriod.nanosec = 200 * 1000 * 1000;

    writer_ = publisher_->create_datawriter(topic_, wqos, &listener_);

    if (writer_ == nullptr)
    {
        return false;
    }

    return true;
}

HelloWorldPublisher::~HelloWorldPublisher()
{
    if (writer_ != nullptr)
    {
        publisher_->delete_datawriter(writer_);
    }
    if (publisher_ != nullptr)
    {
        participant_->delete_publisher(publisher_);
    }
    if (topic_ != nullptr)
    {
        participant_->delete_topic(topic_);
    }
    DomainParticipantFactory::get_instance()->delete_participant(participant_);
}

void HelloWorldPublisher::PubListener::on_publication_matched(
        eprosima::fastdds::dds::DataWriter*,
        const eprosima::fastdds::dds::PublicationMatchedStatus& info)
{
    if (info.current_count_change == 1)
    {
        matched_ = info.total_count;
        first_connected_ = true;
        std::cout << "Publisher matched." << std::endl;
    }
    else if (info.current_count_change == -1)
    {
        matched_ = info.total_count;
        std::cout << "Publisher unmatched." << std::endl;
    }
    else
    {
        std::cout << info.current_count_change
                  << " is not a valid value for PublicationMatchedStatus current count change" << std::endl;
    }
}

void HelloWorldPublisher::run(
        uint32_t samples)
{
    for (uint32_t i = 0; i < samples; ++i)
    {
        if (!publish())
        {
            --i;
        }
        else
        {
            std::cout << "Message: " << hello_.message() << " with index: " << hello_.index() << " SENT" << std::endl;
        }
    }
}

bool HelloWorldPublisher::publish()
{
    if (listener_.matched_ > 0 || listener_.first_connected_)
    {
        hello_.index(hello_.index() + 1);
        writer_->write(&hello_);
        return true;
    }
    return false;
}