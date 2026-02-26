// Copyright 2024 Proyectos y Sistemas de Mantenimiento SL (eProsima).
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
 * @file HandshakeBenchmark.cpp
 *
 */

#include "HelloWorldPublisher.h"
#include "HelloWorldSubscriber.h"

#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastrtps/log/Log.h>

#include <chrono>
#include <vector>
#include <numeric>
#include <iostream>
#include <thread>
#include <cmath>

using namespace eprosima;
using namespace fastdds::dds;

int main(int argc, char** argv)
{
    int iterations = 10;
    if (argc > 1)
    {
        iterations = std::stoi(argv[1]);
    }

    std::cout << "Starting Handshake Benchmark with " << iterations << " iterations..." << std::endl;
    std::cout << "Each iteration measures time from Participant creation to Discovery Match." << std::endl;

    std::vector<double> latencies;
    auto total_start = std::chrono::steady_clock::now();

    for (int i = 0; i < iterations; ++i)
    {
        // Scope for RAII destruction of participants
        {
            auto iter_start = std::chrono::steady_clock::now();

            HelloWorldSubscriber sub;
            HelloWorldPublisher pub;

            bool sub_init = sub.init();
            bool pub_init = pub.init();

            if (!sub_init || !pub_init)
            {
                std::cerr << "Failed to init participants at iteration " << i << std::endl;
                return 1;
            }

            // Wait for match
            while (sub.listener_.matched_ == 0)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            auto iter_end = std::chrono::steady_clock::now();
            std::chrono::duration<double, std::milli> diff = iter_end - iter_start;
            latencies.push_back(diff.count());

            // std::cout << "Iteration " << i << ": " << diff.count() << " ms" << std::endl;
        }
        // Participants are destroyed here. 
        // We might want a small sleep to ensure ports are freed if OS is slow, though typically not needed for random ports.
        // But FastDDS examples use default domain 0 so they might conflict if reused too fast?
        // Different participants in same process should be fine on same domain.
    }

    auto total_end = std::chrono::steady_clock::now();
    std::chrono::duration<double> total_diff = total_end - total_start;

    // Calculate stats
    double sum = std::accumulate(latencies.begin(), latencies.end(), 0.0);
    double avg = sum / latencies.size();
    double min = *std::min_element(latencies.begin(), latencies.end());
    double max = *std::max_element(latencies.begin(), latencies.end());
    
    // Std dev
    double sq_sum = std::inner_product(latencies.begin(), latencies.end(), latencies.begin(), 0.0);
    double stdev = std::sqrt(sq_sum / latencies.size() - avg * avg);

    std::cout << "\nBenchmark Results (ms):" << std::endl;
    std::cout << "-----------------------" << std::endl;
    std::cout << "Iterations: " << iterations << std::endl;
    std::cout << "Total Elapsed Time: " << total_diff.count() << " s" << std::endl;
    std::cout << "Average Latency: " << avg << " ms" << std::endl;
    std::cout << "Min Latency: " << min << " ms" << std::endl;
    std::cout << "Max Latency: " << max << " ms" << std::endl;
    std::cout << "Std Dev: " << stdev << " ms" << std::endl;

    return 0;
}
