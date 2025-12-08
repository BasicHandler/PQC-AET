Algorithmic Expression and Security Hardening of a PQC-Hardened Authenticated Encrypted Transport Protocol (PQC-AET)
Section I: PQC-AET Protocol: Foundational Abstraction and Security Objectives
1.1. Contextual Security Requirements and Operational Model
The design of the PQC-Hardened Authenticated Encrypted Transport Protocol (PQC-AET) is predicated upon providing perpetual confidentiality and integrity in environments subject to pervasive, well-resourced adversarial monitoring. This context includes zones facing state-level censorship, where computing devices are routinely targeted, and network infrastructure (ISPs, local vendors distributing non-audited OS forks) cannot be trusted. The core objective is to ensure that communications for high-risk users, such as journalists, remain secure even if devices are compromised or if data is harvested now for future decryption (the "fetch now-decrypt later" threat model).
TCB Confinement (Zero-Trust Forwarders)
A fundamental architectural constraint is the minimal reliance on client device integrity. The strategy dictates that the Trusted Computing Base (TCB) must be strictly confined to the cryptographic endpoints: the remote cloud service and a dedicated, organization-controlled hardware monitor or dongle. Client devices, specifically mobile phones used as connectivity conduits, are functionally reduced to "dumb transports". These forwarders are explicitly prohibited from accessing, interpreting, or persistently storing key material or plaintext data. The analysis of this configuration suggests that isolating the TCB minimizes the attack surface against common vectors such as operating system malware, vendor backdoors, and insecure application memory handling. This architectural isolation is a critical defense mechanism when device compromise is a non-negotiable threat.
PQC Mandate (Fetch-Now-Decrypt-Later Mitigation)
The selection of a Post-Quantum Cryptography (PQC) Key Encapsulation Mechanism (KEM), specifically Kyber1024, is a mandatory requirement for mitigating the existential threat posed by cryptographically relevant quantum computers (CRQCs). While classical cryptography remains secure against current computational capabilities, the anticipated development of CRQCs necessitates pre-emptive adoption of PQC algorithms. The implementation of Kyber1024 ensures that all session keys established today will remain confidential even if the ciphertext is captured and stored indefinitely by an adversary awaiting quantum capabilities. This strategy directly addresses the "fetch now-decrypt later" threat, guaranteeing perpetual confidentiality for communications established using the PQC-AET protocol.
1.2. Protocol Primitives and Cryptographic Suite Selection
The PQC-AET protocol is constructed using a layered cryptographic suite, each primitive selected for its demonstrated security properties and suitability for high-assurance, ephemeral transport.
PQC Key Exchange: Kyber1024 KEM
Kyber1024, sourced via the pqcrypto_kyber crate , serves as the foundational element for establishing a shared secret between the two endpoints. The KEM structure provides efficient asymmetric key agreement, yielding a high-entropy Shared Secret (SS) that forms the basis of all subsequent session keys. The implementation utilizes ephemeral key pairs, ensuring Perfect Forward Secrecy (PFS) in the event that long-term signing keys are compromised.
Symmetric Cryptography: XChaCha20-Poly1305 AEAD
The authenticated encryption layer employs XChaCha20-Poly1305. This choice is deliberate, favoring robust nonce management over marginal performance gains. Standard ChaCha20-Poly1305 utilizes a 12-byte nonce, which can be vulnerable to reuse in high-volume, multi-session environments. XChaCha20-Poly1305 extends the nonce size to 24 bytes , significantly reducing the probability of catastrophic nonce collision, especially vital in stateful streaming protocols such as encrypted VNC or frame transfers, which characterize the target use case. The security of AEAD is paramount, providing both confidentiality (XChaCha20) and authenticity/integrity (Poly1305) for the transport payload.
Key Derivation Function (KDF): HKDF-SHA256
The raw Shared Secret (SS) produced by Kyber1024 is never used directly as a symmetric key. Instead, the HKDF (HMAC-based Key Derivation Function) employing SHA256 is mandated. HKDF provides cryptographic whitening, ensures strong domain separation between derived keys, and enables the mandatory binding of the derived keys to specific session metadata and context (e.g., role, session ID, and protocol version). This prevents cryptographic overlap, ensuring that a compromise of one derived key (e.g., the key confirmation MAC key) does not automatically compromise another (e.g., the encryption key).
Section II: Formal Definition of the PQC-AET Handshake
The PQC-AET handshake formally establishes the shared secret and critical session metadata necessary for HKDF context binding and subsequent transport integrity.
2.1. Handshake State Transitions and Required Metadata
The KEMSession structure, derived from the audit material, formalizes the necessary metadata to ensure non-ambiguous key derivation and session auditing. This metadata must be generated from a robust entropy source where applicable, ensuring that the integrity of the handshake is contextually bound to the exchange.
Session Metadata Table
Parameter
Source File/Structure
Purpose
Size/Type
KEM ID (ID_{KEM})
KEMSession.kem_id
Identifies PQC algorithm and security level (e.g., "KYBER1024").
&'static str
Session ID (ID_{Sess})
KEMSession.session_id
Unique, random identifier for context binding and audit logging.
16 bytes (CSPRNG)
Timestamp (T_{TS})
KEMSession.timestamp
Record of session initiation time.
u64
Shared Secret (SS)
Decapsulation Output
Input Key Material (IKM) for the subsequent HKDF stage.
32 bytes

The inclusion of the Session ID (ID_{Sess}) is non-trivial; it must be generated using a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG), specifically using getrandom , to ensure unguessability and non-reproducibility across sessions. This unique identifier serves a dual purpose: first, as a mandatory input for HKDF context, and second, as the primary identifier in any non-secret-bearing audit logs.
2.2. Handshake Flow Abstraction (\text{Handshake})
The KEM process is abstracted into rigorous functional notations, strictly adhering to the security principle that all cryptographic operations must utilize secure memory primitives (SecureStore) and explicit error management (Result).
Initiator Encapsulation (\mathcal{I} \to \mathcal{R})
The initiator (\mathcal{I}) generates its ephemeral key pair and encapsulates the shared secret using the receiver's public key (PK_{\mathcal{R}}):
The critical security constraint at this stage is the immediate containment of SS. Upon generation, the raw Shared Secret bytes must be transferred immediately to a memory structure managed by the \text{SecureStore} primitive. This transfer is necessary to ensure that the SS is protected by memory locking (mlock) and is zeroized automatically upon scope termination, preventing the raw material from dwelling in the general heap or being accidentally copied.
Receiver Decapsulation (\mathcal{R}) and Error Management
The receiver (\mathcal{R}) uses its ephemeral secret key (SK_{\mathcal{R}}) to recover the shared secret:
The functional implementation of both \text{perform\_encapsulation} and \text{perform\_decapsulation} must strictly utilize \text{Result<T, E>} return types. The original implementation, which relied on unsafe expect or unwrap calls, was flagged for causing system aborts (panics) upon invalid input (e.g., malformed public keys or truncated ciphertext). This reliance on panics poses a significant security risk because a panic potentially bypasses essential Drop implementations, which are responsible for memory cleanup routines.
By enforcing the use of Result, the cryptographic library ensures that any failure in key conversion (\text{from\_bytes} of PK or CT) is handled gracefully. The consequence is that the SessionManager state machine receives an explicit error signal, allowing the protocol to trigger the controlled, atomic destruction (zeroization and unmapping) of any partially generated secrets via the mandated SecureStore::drop implementation before returning from the function scope. This guarantees that cryptographic failure does not simultaneously induce a key leakage failure.
Section III: Algorithmic Expression of Secure Memory Management and Side-Channel Mitigation
The most rigorous aspect of the PQC-AET protocol is the implementation of secure memory management, formalized by the enhanced SecureStore and its underlying VolatilePage primitive. This addresses the primary side-channel threat vectors related to memory inspection and paging.
3.1. Abstraction of Secure Volatile Page Primitive (\text{VolatilePage})
The VolatilePage primitive is designed to interact directly with the operating system kernel to control the physical location and lifetime of sensitive data.
Secure Allocation and Initialization (Algorithm \text{VolatilePageAlloc})
The allocation algorithm explicitly avoids standard heap allocation routines to minimize external dependencies and maintain tight control over memory hygiene:
Allocation (A_{alloc}): Memory is obtained using libc::mmap with flags MAP_ANON | MAP_PRIVATE. This ensures the memory is anonymous (not backed by a file) and is private to the process, isolating it from accidental access by other threads or processes.
Initialization (A_{init}): Immediately following allocation, the memory is explicitly zeroized using ptr::write_bytes(ptr, 0u8, size). This step is crucial; it explicitly prevents the use of uninitialized memory, which was a risk in the original Vec::with_capacity + set_len implementation, where the memory could contain residual data from prior operations.
Memory Locking (A_{lock}): The function libc::mlock(ptr, size) is called to lock the pages into physical RAM. This is the explicit mitigation against paging attacks, guaranteeing that the operating system kernel cannot write the cryptographic secrets to disk swap space, which would leave a persistent artifact accessible via forensic analysis.
The architectural choice to combine mmap, explicit zeroization, and mlock is a multilayered defense strategy. mlock defends against passive OS mechanisms (swapping), while explicit zeroization and controlled deallocation defend against active memory forensics (reading residual RAM contents). Furthermore, system integrity requires that the primary binary or module initialization must also execute system calls, such as setting resource limits (\text{setrlimit}), to disable core dumps (RLIMIT_CORE = 0), preventing the entire process memory state from being written to disk upon critical failure.
Controlled Access Model
To prevent accidental key exposure through slices or copies, the direct expose() and expose_mut() methods are removed. Access to the raw secret bytes is strictly mediated through a closure-based accessor pattern:
This model ensures that the reference to the sensitive slice only exists within the controlled lifetime of the supplied closure F. Upon F's completion, the reference immediately falls out of scope, eliminating the possibility of a persistent reference escaping control and causing inadvertent key duplication on the heap, which is a common vector for memory leakage.
3.2. Secure Deallocation and Zeroization Guarantee (Algorithm \text{VolatilePageDrop})
The cryptographic destruction process, formalized by the Drop trait implementation for VolatilePage, is executed in a precise sequence to ensure security precedes resource release.
Zeroization (D_{zero}): The memory region is actively overwritten using Zeroize. This is the cryptographic destruction phase, ensuring the data in physical RAM is irrecoverable.
Unlocking (D_{unlock}): libc::munlock() is called to release the OS memory lock, confirming that the pages are no longer pinned in physical memory.
Deallocation (D_{unmap}): Finally, libc::munmap() returns the memory pages to the operating system.
This sequence guarantees atomic destruction: zeroization is confirmed while the memory is still under the process's control, followed by the release of OS resources.
Section IV: Rigorous Key Derivation Function (KDF) Abstraction
The raw Shared Secret (SS) obtained from Kyber1024 must undergo robust Key Derivation using HKDF-SHA256 to achieve necessary domain separation and binding integrity.
4.1. Formal Necessity of HKDF-SHA256
Using the SS directly as the key for XChaCha20-Poly1305 is fundamentally insecure. Cryptographic protocols demand that high-entropy inputs like KEM outputs are processed through a KDF to derive context-specific keys. HKDF-SHA256 is chosen to transform the 32-byte SS into a Pseudo-Random Key (PRK) and subsequently expand this into orthogonal session keys, isolating the use of key material across different cryptographic primitives.
4.2. HKDF Flow Definition (Extract and Expand)
The key derivation process is structured in two parts:
A. Extract Stage:
The Input Key Material (SS) is extracted securely via the \text{SecureStore.with\_secret()} accessor, ensuring the raw secret is only accessible during the extraction operation. A non-secret \text{Salt} (e.g., configuration value) may be included to increase divergence.
B. Expand Stage and Context Binding:
The Output Key Material (OKM) is expanded to 88 bytes (L=88), based on the total length required for the three derived transport keys. The \text{Info} string is the core of contextual integrity, composed of static and dynamic data elements:
$$\text{Info} = ID_{Protocol} |
| ID_{Sess} | | \text{Role} | | \text{KEM_Metadata}$$
The inclusion of the directional \text{Role} (Client/Server) in \text{Info} guarantees that the keys derived by the initiator are cryptographically orthogonal to the keys derived by the receiver. This deliberate binding prevents accidental directional key reuse or ambiguity, which is an advanced security measure often overlooked in simpler protocols. Furthermore, the inclusion of the unique ID_{Sess} ensures that even if the same PK_{peer} is used across multiple sessions, the resulting OKM will be entirely distinct, preventing downgrade or replay attacks where an adversary attempts to force the use of an older session key.
4.3. Transport Key Separation (Orthogonal Keys)
The 88-byte OKM is deterministically separated into three specific key domains required for the PQC-AET transport functionality.
Transport Key Derivation Table
Key Identifier
Length (Bytes)
Purpose
PQC-AET Usage
K_{enc}
32
Encryption Key
XChaCha20-Poly1305 Symmetric Key.
K_{nonce}
24
Nonce Base
Input prefix for directional Nonce Generation.
K_{mac}
32
Authentication Key
HMAC/MAC Key for Key Confirmation Sub-Protocol.

Section V: The Authenticated Encrypted Transport Layer (XChaCha20-Poly1305)
The transport layer leverages XChaCha20-Poly1305, managed by the SymmetricCipher wrapper, requiring rigorous nonce construction and key confirmation mechanisms to maintain high integrity throughout the session lifetime.
5.1. Nonce Management and Directional Sequence Counters
The PQC-AET protocol must employ a strict nonce policy to prevent the catastrophic failure associated with nonce reuse in stream ciphers. The K_{nonce} base (24 bytes) derived from HKDF is combined with a directional sequence counter to generate the final unique nonce N.
Directional Counters
The SymmetricCipher implementation must maintain two separate, non-overlapping sequence counters: Seq_{send} and Seq_{recv}.
Seq_{send} is incremented prior to every \text{AeadEncrypt} operation.
Seq_{recv} is incremented only upon successful \text{AeadDecrypt} verification.
This separation ensures that independent communication flows in a full-duplex session do not share counter state, eliminating a source of potential nonce collision.
Nonce Generation (\text{NonceGen})
The full 24-byte nonce N is generated by XORing the current directional u64 sequence counter (encoded in little-endian format) into the last 8 bytes of the 24-byte K_{nonce} base.
$$N = K_{nonce} \oplus (\text{LE_Encode}(Seq_{i}) |
| 0^{16})$$
A compulsory protocol requirement is that all counter increments utilize checked_add. If Seq_{i} reaches saturation (2^{64}-1), a NonceOverflow error must be immediately returned, forcing session termination and key zeroization. This mechanism prevents key reuse by establishing a hard, verifiable limit on the amount of data encrypted under a single key set.
5.2. Key Confirmation Sub-Protocol
The Key Confirmation Message (KCM) is a mandatory step following key derivation to ensure that both the initiator (\mathcal{I}) and the receiver (\mathcal{R}) derived identical transport key sets (K_{trans}) from the KEM and HKDF processes.
Confirmation Value (KCM)
The KCM is computed using HMAC-SHA256, keyed by K_{mac}, over a defined context string and a hash of the entire handshake transcript (T_{transcript}): $$KCM \leftarrow \text{HMAC-SHA256}(K_{mac}, \text{Confirmation_Context} |
| T_{transcript})$$
T_{transcript} typically includes the public keys and the ciphertext exchanged. K_{mac} is sourced securely from the HKDF output.
Verification and Atomic Abort
After computing KCM_{own}, the peers exchange their respective confirmation values. The receiver verifies KCM_{peer} against its locally computed value. If the verification fails—indicating a discrepancy in the SS or an error in the HKDF context—the session must immediately transition to an error state. This results in the atomic termination and secure destruction of all key material via the controlled Drop routines. The key confirmation step provides an integrity check on the entire asymmetric exchange process before the session transitions to the active transport phase.
Section VI: Operational Security and Session Management Abstraction
The SessionManager state machine, defined in sessionmanager.rs , governs the secure lifecycle and rotation of the key material, enforcing rigorous memory safety and move semantics.
6.1. The SessionManager State Machine and Key Lifecycle
The SessionManager encapsulates all mutable session state, ensuring that sensitive data is properly initialized, accessed, and destroyed.
Initialization and Termination
The \text{SessionManager::new}() function is responsible for initial setup, including the generation of the ephemeral Kyber keypair. The resulting secret key (SK) must be immediately stored in a VolatilePage (implicitly via SecureStore), guaranteeing its protection by memory locking from the moment of creation.
The \text{end\_session}() method formalizes the secure termination. It must explicitly nullify optional fields containing secrets (shared_secret = None, symmetric_cipher = None). Since shared_secret and the keys contained within symmetric_cipher utilize SecureStore, their zeroization is guaranteed upon Drop. However, if the owner's secret key (SK_{own}) is maintained as a raw Vec<u8> for the initial key generation, it requires an explicit manual zeroization call (self.own_secret_key.fill(0)) before the memory is released, covering any local memory not already managed by SecureStore.
Secure Access Enforcement
The refactoring of the handshake methods mandates that all direct access to the Shared Secret bytes must use the closure pattern. For example, within client_handshake and server_handshake, instead of using self.shared_secret.as_ref().unwrap().expose() (which risks exposing slices indefinitely) , the implementation must call \text{SecureStore.with\_secret}(). This ensures that the secret bytes are exposed only for the minimum duration necessary for the \text{HKDF-Extract} operation, thereby confining the exposure temporally.
6.2. Algorithmic Expression of Proactive Key Rotation Policy (\text{rotate\_keys})
Proactive key rotation is essential to maintain PFS resilience against passive harvesting and to limit the maximum plaintext volume encrypted under a single key set.
Policy Thresholds
Key rotation is triggered by the method \text{should\_rotate\_keys}(), which evaluates against two independent, configurable thresholds defined in the configuration :
If either threshold is met, rotation is required, initiating a full key exchange to derive a fresh Shared Secret.
Rotation Flow (Secure Re-Encapsulation and Atomic Swap)
The \text{rotate\_keys} algorithm ensures that old key material is zeroized precisely when the new material is established, preventing any transition state where both keys coexist unprotected, or where an old key might be reused.
New Key Generation: (PK'_{new}, SK'_{new}) \leftarrow \text{generate\_ephemeral\_keypair}(). The existing SK_{old} is explicitly zeroized and replaced.
Re-Encapsulation: If the peer's public key (PK_{peer}) is known, a new encapsulation is performed: CT'_{KEM} \leftarrow \text{perform\_encapsulation}(PK_{peer}).
New Secret Derivation: The new \text{KEMSession} yields SS'_{new}, which is immediately derived via HKDF into K'_{trans} keys.
Atomic Swap and Cleanup: The critical principle governing the swap is the enforcement of non-Clone semantics on SecureStore. The audit specifically identifies the danger of cloning SecureStore in the rotation logic, as this duplicates the sensitive material; if the old state is dropped, the cloned state remains uncleaned. By enforcing non-Clone and relying on move semantics, the old \text{SecureStore} instance is consumed and replaced by the new instance. The Drop implementation for the old secret is guaranteed to execute atomically during this replacement, ensuring zeroization and memory release before the new session state becomes fully operational. This move-based design guarantees that ownership is transferred precisely and destruction of the preceding secret state is mandatory.

Section VII: Conclusion and Formal Security Guarantees
7.1. Summary of PQC-AET Security Guarantees
The PQC-AET protocol, engineered for operation in highly compromised environments, achieves a robust set of security assurances:
Post-Quantum Confidentiality: Guaranteed by the choice of Kyber1024 KEM, mitigating the "fetch now-decrypt later" threat model.
Perfect Forward Secrecy (PFS): Ensured through the use of ephemeral Kyber key pairs and proactive, policy-driven key rotation based on volume or time thresholds.
Integrity and Authenticity: Provided by XChaCha20-Poly1305 AEAD and the mandatory Key Confirmation Sub-Protocol, which verifies the integrity of the HKDF derivation process.
Side-Channel Resilience: Achieved by defense-in-depth memory hygiene, including the use of libc::mlock to prevent memory paging, explicit zeroization via the Zeroize trait, and the controlled access model enforced by the SecureStore::with_secret closure pattern.
7.2. Algorithmic Expression and Abstraction of the PQC-AET Protocol (Final Synthesis)
The unified protocol, encompassing key management, handshake, and transport, is formally synthesized as a sequence of atomic, secure operations that strictly adhere to integrity checks and memory confinement.
Initialization Phase (Key Generation and Secure Storage):
Handshake Phase (Key Establishment and Confirmation): $$ \text{Handshake} \to \left{ \begin{array}{ll} (CT_{KEM}, SS) \leftarrow \text{Kyber.Encapsulate}(PK_{peer}) & (\text{Initiator}) \ SS' \leftarrow \text{Kyber.Decapsulate}(CT_{KEM}, SK_{own}) & (\text{Receiver}) \end{array} \right. $$$$ K_{trans} \leftarrow \text{HKDF-SHA256}(SS, \text{Info}{\text{Role}})$$$$\text{Status} \leftarrow \text{Verify}(\text{KeyConfirmation}(K{mac})) \text{ (enforce integrity)}$$
Active Phase (Authenticated Encrypted Transport):
$$ \text{RotationCheck} \leftarrow \text{if } (T_{elapsed} \lor V_{transferred}) \text{ then } \text{rotate_keys}() \text{ (enforce PFS) } $$
Termination Phase (Cleanup):
7.3. Recommendations for Future Work
While the current PQC-AET design is robust against memory and quantum threats, its security profile can be further enhanced through the integration of explicit peer authentication and rigorous testing.
Signature Integration (AKEM)
The current implementation relies solely on KEM for key establishment, which does not inherently provide authentication of the public key. This vulnerability allows for a potential active Man-in-the-Middle (MITM) attack if an adversary can inject a false public key during transport. Future work should integrate a quantum-resistant digital signature scheme (e.g., Dilithium, or using a hybrid approach with Ed25519) to create a fully Authenticated KEM (AKEM). The server must sign its PK_{Kyber} along with the session metadata (ID_{Sess}) using its long-term signature key. The client must verify this signature against a pre-provisioned root key or fingerprint before proceeding with encapsulation, thereby eliminating active MITM threats at the handshake layer.
Cross-Platform Secure Memory Implementation
The current secure memory design relies heavily on Unix-specific primitives (mmap, mlock, libc). To broaden deployment capability, especially for platforms like Windows, a development path for conditional compilation wrappers utilizing native equivalents (e.g., VirtualLock and secure allocation APIs) is necessary. This will ensure that the essential memory hygiene guarantees are maintained across all target operating environments.
Fuzzing and Code Verification
Although the refactoring mandates robust error handling via Result and eliminates unsafe expect/unwrap calls, formal verification of input robustness is mandatory. Implementing comprehensive fuzzing campaigns, specifically targeting the \text{perform\_decapsulation} and \text{AeadDecrypt} functions with malformed, truncated, or random inputs, should be integrated into the continuous integration (CI) pipeline. This proactive testing, potentially utilizing tools like cargo-fuzz and Miri , ensures the protocol remains resilient against unexpected panics or data leaks when subjected to hostile inputs.
