# PQC-enabled Fast DDS

## 1. Overview

This project integrates post-quantum cryptography (PQC) into the authentication and key exchange procedures of Fast DDS for ROS2.

Based on a PQC authentication and key exchange protocol proposed in prior research, we compared CycloneDDS and Fast DDS and implemented the required changes in Fast DDS.

## 2. Challenges

- Different security implementations in CycloneDDS and Fast DDS.
- Additional message fields required for KEM public keys and ciphertexts.
- Larger authentication messages due to PQC keys and signatures.
- Performance and memory overhead as the number of participants increases.

## 3. Contributions

- Analyzed DDS authentication and cryptographic library integration.
- Implemented PQC authentication and KEM-based key exchange in Fast DDS.
- Added message fields for KEM public keys and ciphertexts.
- Allocated serialization buffers based on the actual data size.
- Evaluated handshake time, packet size, and memory usage.

## 4. Implementation

| Component | Change |
|---|---|
| Authentication | Integrated PQC signatures into the handshake |
| Key exchange | Added KEM operations |
| Messages | Added KEM public key and ciphertext fields |
| Algorithm selection | Supported conventional and PQC processing paths |
| Serialization | Allocated buffers based on serialized data size |

## 5. Build and Run

1. Install the required cryptographic libraries.
2. Build Fast DDS with the required security options.
3. Generate test keys and certificates.
4. Configure security settings and select algorithms.
5. Run the publisher and subscriber.
6. Check handshake completion and message delivery.

Detailed dependency versions and commands will be added after verification.
