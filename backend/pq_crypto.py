"""
Post-Quantum Cryptography Dashboard – Backend Module
=====================================================

Provides endpoints for:
  - PQ algorithm benchmarking (Kyber, Dilithium, SPHINCS+, Falcon, NTRU, Classic McEliece)
  - Quantum risk assessment for current TLS/JWT config
  - Key exchange simulation with latency profiling
  - Algorithm comparison matrices
  - Migration readiness scoring

All cryptographic operations are *simulated* with realistic parameter sizes
and performance profiles derived from NIST PQC Round-3 benchmarks.
"""

import hashlib
import os
import time
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth import require_auth

router = APIRouter(prefix="/api/pq", tags=["pq-crypto"])
limiter = Limiter(key_func=get_remote_address)

# ── NIST PQC Algorithm Registry ──────────────────────────────────────────

PQ_ALGORITHMS = {
    # Key Encapsulation Mechanisms (KEMs)
    "kyber512": {
        "name": "CRYSTALS-Kyber-512",
        "type": "KEM",
        "nist_level": 1,
        "family": "Lattice (M-LWE)",
        "status": "FIPS 203 (ML-KEM) – Standardised",
        "pk_bytes": 800,
        "sk_bytes": 1632,
        "ct_bytes": 768,
        "ss_bytes": 32,
        "keygen_us": 35,
        "encaps_us": 45,
        "decaps_us": 40,
        "classical_security": 128,
        "quantum_security": 107,
        "description": "Smallest Kyber variant. Balanced speed-size tradeoff for TLS 1.3 key exchange.",
    },
    "kyber768": {
        "name": "CRYSTALS-Kyber-768",
        "type": "KEM",
        "nist_level": 3,
        "family": "Lattice (M-LWE)",
        "status": "FIPS 203 (ML-KEM) – Standardised",
        "pk_bytes": 1184,
        "sk_bytes": 2400,
        "ct_bytes": 1088,
        "ss_bytes": 32,
        "keygen_us": 55,
        "encaps_us": 65,
        "decaps_us": 60,
        "classical_security": 192,
        "quantum_security": 164,
        "description": "Recommended default for most IDS deployments. NIST Level 3 security.",
    },
    "kyber1024": {
        "name": "CRYSTALS-Kyber-1024",
        "type": "KEM",
        "nist_level": 5,
        "family": "Lattice (M-LWE)",
        "status": "FIPS 203 (ML-KEM) – Standardised",
        "pk_bytes": 1568,
        "sk_bytes": 3168,
        "ct_bytes": 1568,
        "ss_bytes": 32,
        "keygen_us": 80,
        "encaps_us": 95,
        "decaps_us": 85,
        "classical_security": 256,
        "quantum_security": 218,
        "description": "Highest Kyber security level. Suitable for classified/critical infrastructure.",
    },
    "ntru_hps2048509": {
        "name": "NTRU-HPS-2048-509",
        "type": "KEM",
        "nist_level": 1,
        "family": "Lattice (NTRU)",
        "status": "Round 3 Finalist",
        "pk_bytes": 699,
        "sk_bytes": 935,
        "ct_bytes": 699,
        "ss_bytes": 32,
        "keygen_us": 120,
        "encaps_us": 55,
        "decaps_us": 55,
        "classical_security": 128,
        "quantum_security": 106,
        "description": "Classic lattice-based KEM with long track record. Compact ciphertexts.",
    },
    "mceliece348864": {
        "name": "Classic McEliece 348864",
        "type": "KEM",
        "nist_level": 1,
        "family": "Code-based",
        "status": "Round 4 Candidate",
        "pk_bytes": 261120,
        "sk_bytes": 6492,
        "ct_bytes": 128,
        "ss_bytes": 32,
        "keygen_us": 250000,
        "encaps_us": 50,
        "decaps_us": 120,
        "classical_security": 128,
        "quantum_security": 119,
        "description": "Extremely large public keys but tiny ciphertexts. 40+ years of cryptanalysis.",
    },
    # Digital Signature Schemes
    "dilithium2": {
        "name": "CRYSTALS-Dilithium-2",
        "type": "Signature",
        "nist_level": 2,
        "family": "Lattice (M-LWE/M-SIS)",
        "status": "FIPS 204 (ML-DSA) – Standardised",
        "pk_bytes": 1312,
        "sk_bytes": 2528,
        "sig_bytes": 2420,
        "keygen_us": 70,
        "sign_us": 180,
        "verify_us": 65,
        "classical_security": 128,
        "quantum_security": 107,
        "description": "Primary PQ signature for JWT tokens and model authentication.",
    },
    "dilithium3": {
        "name": "CRYSTALS-Dilithium-3",
        "type": "Signature",
        "nist_level": 3,
        "family": "Lattice (M-LWE/M-SIS)",
        "status": "FIPS 204 (ML-DSA) – Standardised",
        "pk_bytes": 1952,
        "sk_bytes": 4000,
        "sig_bytes": 3293,
        "keygen_us": 120,
        "sign_us": 280,
        "verify_us": 100,
        "classical_security": 192,
        "quantum_security": 164,
        "description": "Recommended for high-security IDS audit trail signing.",
    },
    "dilithium5": {
        "name": "CRYSTALS-Dilithium-5",
        "type": "Signature",
        "nist_level": 5,
        "family": "Lattice (M-LWE/M-SIS)",
        "status": "FIPS 204 (ML-DSA) – Standardised",
        "pk_bytes": 2592,
        "sk_bytes": 4864,
        "sig_bytes": 4595,
        "keygen_us": 190,
        "sign_us": 400,
        "verify_us": 160,
        "classical_security": 256,
        "quantum_security": 218,
        "description": "Maximum security Dilithium. For sovereign/government IDS deployments.",
    },
    "falcon512": {
        "name": "Falcon-512",
        "type": "Signature",
        "nist_level": 1,
        "family": "Lattice (NTRU)",
        "status": "FIPS 206 (FN-DSA) – Standardised",
        "pk_bytes": 897,
        "sk_bytes": 1281,
        "sig_bytes": 666,
        "keygen_us": 8500,
        "sign_us": 350,
        "verify_us": 50,
        "classical_security": 128,
        "quantum_security": 103,
        "description": "Compact signatures. Ideal for bandwidth-constrained IDS sensor networks.",
    },
    "sphincs_sha2_128f": {
        "name": "SPHINCS+-SHA2-128f",
        "type": "Signature",
        "nist_level": 1,
        "family": "Hash-based",
        "status": "FIPS 205 (SLH-DSA) – Standardised",
        "pk_bytes": 32,
        "sk_bytes": 64,
        "sig_bytes": 17088,
        "keygen_us": 3500,
        "sign_us": 85000,
        "verify_us": 4500,
        "classical_security": 128,
        "quantum_security": 128,
        "description": "Stateless hash-based signatures. Conservative, no lattice assumptions.",
    },
}

# ── Classical algorithms for comparison ───────────────────────────────────

CLASSICAL_ALGORITHMS = {
    "rsa2048": {
        "name": "RSA-2048",
        "type": "Signature + KEM",
        "family": "Integer Factorisation",
        "pk_bytes": 256,
        "sk_bytes": 1024,
        "sig_bytes": 256,
        "keygen_us": 150000,
        "sign_us": 1500,
        "verify_us": 30,
        "classical_security": 112,
        "quantum_security": 0,
        "quantum_vulnerable": True,
        "shor_qubits_needed": 4096,
    },
    "ecdsa_p256": {
        "name": "ECDSA P-256",
        "type": "Signature",
        "family": "Elliptic Curve",
        "pk_bytes": 64,
        "sk_bytes": 32,
        "sig_bytes": 64,
        "keygen_us": 50,
        "sign_us": 80,
        "verify_us": 120,
        "classical_security": 128,
        "quantum_security": 0,
        "quantum_vulnerable": True,
        "shor_qubits_needed": 2330,
    },
    "x25519": {
        "name": "X25519 (ECDH)",
        "type": "KEM",
        "family": "Elliptic Curve",
        "pk_bytes": 32,
        "sk_bytes": 32,
        "ct_bytes": 32,
        "keygen_us": 40,
        "encaps_us": 45,
        "decaps_us": 45,
        "classical_security": 128,
        "quantum_security": 0,
        "quantum_vulnerable": True,
        "shor_qubits_needed": 2330,
    },
    "aes256": {
        "name": "AES-256",
        "type": "Symmetric",
        "family": "Block Cipher",
        "classical_security": 256,
        "quantum_security": 128,
        "quantum_vulnerable": False,
        "grover_speedup": "Quadratic — key space halved",
    },
}

# ── Quantum Risk Assessment ──────────────────────────────────────────────

SYSTEM_CRYPTO_PROFILE = {
    "jwt_algorithm": {
        "current": "HS256 (HMAC-SHA256)",
        "type": "Symmetric MAC",
        "quantum_risk": "low",
        "risk_score": 15,
        "explanation": "Symmetric-key MAC. Grover's algorithm halves effective security (128-bit → 64-bit equivalent), but still considered safe for medium-term.",
        "recommendation": "Upgrade to HS512 for larger key size, or migrate to ML-DSA (Dilithium) for digital signatures.",
    },
    "password_hashing": {
        "current": "bcrypt (cost=12)",
        "type": "Password KDF",
        "quantum_risk": "low",
        "risk_score": 10,
        "explanation": "Memory-hard KDF. Quantum speedup is minimal due to memory-hardness.",
        "recommendation": "No immediate action needed. Consider Argon2id for new deployments.",
    },
    "tls": {
        "current": "TLS 1.2/1.3 with ECDHE-P256",
        "type": "Key Exchange + Authentication",
        "quantum_risk": "high",
        "risk_score": 85,
        "explanation": "ECDHE key exchange is fully broken by Shor's algorithm. Harvest-now-decrypt-later (HNDL) attack is an immediate concern for sensitive IDS traffic.",
        "recommendation": "Deploy X25519Kyber768 hybrid key exchange (RFC 9370). Available in OpenSSL 3.2+, BoringSSL, AWS-LC.",
    },
    "model_integrity": {
        "current": "SHA-256 checksums",
        "type": "Hash",
        "quantum_risk": "low",
        "risk_score": 20,
        "explanation": "SHA-256 collision resistance reduced from 128-bit to ~85-bit by Grover. Still adequate for model integrity checks.",
        "recommendation": "Use SHA3-256 or SHAKE256 for forward security. Sign model weights with ML-DSA (Dilithium).",
    },
    "api_authentication": {
        "current": "Bearer JWT (HS256)",
        "type": "Token Auth",
        "quantum_risk": "medium",
        "risk_score": 45,
        "explanation": "JWT integrity depends on HMAC key secrecy. Not directly Shor-vulnerable, but key management may use RSA/ECDSA elsewhere.",
        "recommendation": "Implement PQ-signed JWTs using Dilithium. Add token binding to prevent replay attacks.",
    },
    "audit_integrity": {
        "current": "Database records (plaintext)",
        "type": "Audit Trail",
        "quantum_risk": "medium",
        "risk_score": 50,
        "explanation": "Audit logs lack cryptographic integrity. A quantum adversary could tamper with logs post-compromise.",
        "recommendation": "Implement hash-chained audit logs with PQ signatures. Consider blockchain-anchored timestamping.",
    },
}


# ── Request/Response Models ──────────────────────────────────────────────

class KeyExchangeRequest(BaseModel):
    algorithm: str = Field("kyber768", description="PQ algorithm ID")
    iterations: int = Field(100, ge=1, le=10000, description="Number of iterations for benchmarking")

class MigrationAssessmentRequest(BaseModel):
    target_nist_level: int = Field(3, ge=1, le=5, description="Target NIST security level")
    include_hybrid: bool = Field(True, description="Include hybrid classical+PQ options")


# ── Endpoints ────────────────────────────────────────────────────────────

@router.get("/algorithms")
async def list_algorithms(user=Depends(require_auth)):
    """List all available PQ algorithms with their parameters."""
    kems = {}
    sigs = {}
    for algo_id, algo in PQ_ALGORITHMS.items():
        target = kems if algo["type"] == "KEM" else sigs
        target[algo_id] = algo
    return {
        "kem_algorithms": kems,
        "signature_algorithms": sigs,
        "classical_algorithms": CLASSICAL_ALGORITHMS,
        "total_pq": len(PQ_ALGORITHMS),
        "total_classical": len(CLASSICAL_ALGORITHMS),
    }


@router.post("/benchmark")
@limiter.limit("10/minute")
async def benchmark_algorithm(request: Request, body: KeyExchangeRequest, user=Depends(require_auth)):
    """Benchmark a PQ algorithm with simulated key exchange operations."""
    algo_id = body.algorithm
    iterations = body.iterations

    if algo_id not in PQ_ALGORITHMS:
        raise HTTPException(400, f"Unknown algorithm: {algo_id}. Available: {list(PQ_ALGORITHMS.keys())}")

    algo = PQ_ALGORITHMS[algo_id]
    is_kem = algo["type"] == "KEM"

    # Simulate realistic benchmarks with jitter
    results = []
    keygen_times = []
    op1_times = []  # encaps or sign
    op2_times = []  # decaps or verify

    for i in range(iterations):
        # Simulate keygen with realistic jitter
        base_keygen = algo["keygen_us"]
        jitter = secrets.randbelow(max(1, base_keygen // 5)) - base_keygen // 10
        kg_time = max(1, base_keygen + jitter)
        keygen_times.append(kg_time)

        if is_kem:
            base_enc = algo["encaps_us"]
            base_dec = algo["decaps_us"]
            j1 = secrets.randbelow(max(1, base_enc // 5)) - base_enc // 10
            j2 = secrets.randbelow(max(1, base_dec // 5)) - base_dec // 10
            op1_times.append(max(1, base_enc + j1))
            op2_times.append(max(1, base_dec + j2))
        else:
            base_sign = algo["sign_us"]
            base_verify = algo["verify_us"]
            j1 = secrets.randbelow(max(1, base_sign // 5)) - base_sign // 10
            j2 = secrets.randbelow(max(1, base_verify // 5)) - base_verify // 10
            op1_times.append(max(1, base_sign + j1))
            op2_times.append(max(1, base_verify + j2))

    # Generate sample key material (random bytes to show sizes)
    pk_sample = secrets.token_hex(min(algo["pk_bytes"], 64))
    sk_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()

    op1_label = "encaps" if is_kem else "sign"
    op2_label = "decaps" if is_kem else "verify"

    return {
        "algorithm": algo_id,
        "algorithm_info": algo,
        "iterations": iterations,
        "benchmark": {
            "keygen_us": {
                "mean": round(sum(keygen_times) / len(keygen_times), 1),
                "min": min(keygen_times),
                "max": max(keygen_times),
                "p50": sorted(keygen_times)[len(keygen_times) // 2],
                "p99": sorted(keygen_times)[int(len(keygen_times) * 0.99)],
            },
            f"{op1_label}_us": {
                "mean": round(sum(op1_times) / len(op1_times), 1),
                "min": min(op1_times),
                "max": max(op1_times),
                "p50": sorted(op1_times)[len(op1_times) // 2],
                "p99": sorted(op1_times)[int(len(op1_times) * 0.99)],
            },
            f"{op2_label}_us": {
                "mean": round(sum(op2_times) / len(op2_times), 1),
                "min": min(op2_times),
                "max": max(op2_times),
                "p50": sorted(op2_times)[len(op2_times) // 2],
                "p99": sorted(op2_times)[int(len(op2_times) * 0.99)],
            },
            "total_handshake_us": round(
                sum(keygen_times) / len(keygen_times) +
                sum(op1_times) / len(op1_times) +
                sum(op2_times) / len(op2_times), 1
            ),
        },
        "key_material_sample": {
            "public_key_hex_prefix": pk_sample[:128],
            "secret_key_sha256": sk_hash,
            "pk_size_bytes": algo["pk_bytes"],
            "sk_size_bytes": algo["sk_bytes"],
        },
        "histogram": {
            "keygen": keygen_times[:min(200, iterations)],
            f"{op1_label}": op1_times[:min(200, iterations)],
            f"{op2_label}": op2_times[:min(200, iterations)],
        },
    }


@router.get("/risk-assessment")
async def quantum_risk_assessment(user=Depends(require_auth)):
    """Assess quantum risk for the current system's cryptographic configuration."""
    components = SYSTEM_CRYPTO_PROFILE

    risk_scores = [c["risk_score"] for c in components.values()]
    overall_score = round(sum(risk_scores) / len(risk_scores), 1)
    max_risk = max(risk_scores)

    # Determine overall risk level
    if max_risk >= 80:
        overall_level = "critical"
        overall_message = "Immediate action required: TLS key exchange is vulnerable to harvest-now-decrypt-later attacks."
    elif max_risk >= 50:
        overall_level = "high"
        overall_message = "Several components need PQ migration within the next 2-3 years."
    elif max_risk >= 30:
        overall_level = "medium"
        overall_message = "System is moderately prepared. Address medium-risk items in next upgrade cycle."
    else:
        overall_level = "low"
        overall_message = "System uses primarily quantum-resistant primitives."

    # Timeline estimates
    timeline = {
        "nist_standards_final": "2024 (FIPS 203/204/205 published August 2024)",
        "harvest_now_threat": "Active today — encrypted traffic can be stored for future decryption",
        "cryptanalytically_relevant_qc": "2030-2035 (estimated)",
        "recommended_migration_start": "Now — hybrid mode deployment",
        "full_pq_migration_target": "2027-2028",
    }

    return {
        "overall_risk_score": overall_score,
        "overall_risk_level": overall_level,
        "overall_message": overall_message,
        "max_component_risk": max_risk,
        "components": components,
        "quantum_timeline": timeline,
        "migration_priority": sorted(
            [{"component": k, **v} for k, v in components.items()],
            key=lambda x: x["risk_score"],
            reverse=True,
        ),
    }


@router.post("/simulate-handshake")
@limiter.limit("10/minute")
async def simulate_handshake(request: Request, body: KeyExchangeRequest, user=Depends(require_auth)):
    """Simulate a full PQ key exchange handshake with detailed step timings."""
    algo_id = body.algorithm
    if algo_id not in PQ_ALGORITHMS:
        raise HTTPException(400, f"Unknown algorithm: {algo_id}")

    algo = PQ_ALGORITHMS[algo_id]
    if algo["type"] != "KEM":
        raise HTTPException(400, f"{algo_id} is a {algo['type']} algorithm, not a KEM. Use a KEM for handshake simulation.")

    steps = []

    # Step 1: Server generates keypair
    t0 = time.perf_counter_ns()
    server_pk = secrets.token_bytes(algo["pk_bytes"])
    server_sk = secrets.token_bytes(algo["sk_bytes"])
    t1 = time.perf_counter_ns()
    keygen_ns = t1 - t0
    steps.append({
        "step": 1,
        "name": "Server KeyGen",
        "description": f"Server generates {algo['name']} keypair ({algo['pk_bytes']}B pk, {algo['sk_bytes']}B sk)",
        "simulated_time_us": algo["keygen_us"],
        "data_generated_bytes": algo["pk_bytes"] + algo["sk_bytes"],
    })

    # Step 2: Server sends public key to client
    steps.append({
        "step": 2,
        "name": "PK Transmission",
        "description": f"Server sends public key ({algo['pk_bytes']} bytes) to client",
        "simulated_time_us": round(algo["pk_bytes"] / 1000 * 8, 1),  # ~1 Gbps link
        "data_transmitted_bytes": algo["pk_bytes"],
        "wire_overhead_vs_x25519": f"+{algo['pk_bytes'] - 32} bytes ({algo['pk_bytes'] / 32:.0f}x)",
    })

    # Step 3: Client encapsulates
    shared_secret = secrets.token_bytes(algo["ss_bytes"])
    ciphertext = secrets.token_bytes(algo["ct_bytes"])
    steps.append({
        "step": 3,
        "name": "Client Encapsulation",
        "description": f"Client encapsulates shared secret → {algo['ct_bytes']}B ciphertext",
        "simulated_time_us": algo["encaps_us"],
        "data_generated_bytes": algo["ct_bytes"] + algo["ss_bytes"],
    })

    # Step 4: Client sends ciphertext
    steps.append({
        "step": 4,
        "name": "CT Transmission",
        "description": f"Client sends ciphertext ({algo['ct_bytes']} bytes) to server",
        "simulated_time_us": round(algo["ct_bytes"] / 1000 * 8, 1),
        "data_transmitted_bytes": algo["ct_bytes"],
    })

    # Step 5: Server decapsulates
    steps.append({
        "step": 5,
        "name": "Server Decapsulation",
        "description": f"Server decapsulates → {algo['ss_bytes']}-byte shared secret",
        "simulated_time_us": algo["decaps_us"],
        "shared_secret_bytes": algo["ss_bytes"],
    })

    total_compute_us = algo["keygen_us"] + algo["encaps_us"] + algo["decaps_us"]
    total_wire_bytes = algo["pk_bytes"] + algo["ct_bytes"]

    # Compare to classical X25519
    x25519 = CLASSICAL_ALGORITHMS["x25519"]
    classical_compute_us = x25519["keygen_us"] + x25519["encaps_us"] + x25519["decaps_us"]
    classical_wire_bytes = x25519["pk_bytes"] + x25519["ct_bytes"]

    return {
        "algorithm": algo_id,
        "algorithm_info": algo,
        "steps": steps,
        "summary": {
            "total_compute_us": total_compute_us,
            "total_wire_bytes": total_wire_bytes,
            "shared_secret_hex": shared_secret.hex(),
            "shared_secret_bytes": algo["ss_bytes"],
        },
        "comparison_vs_x25519": {
            "compute_overhead_us": total_compute_us - classical_compute_us,
            "compute_overhead_percent": round((total_compute_us / classical_compute_us - 1) * 100, 1),
            "wire_overhead_bytes": total_wire_bytes - classical_wire_bytes,
            "wire_overhead_percent": round((total_wire_bytes / classical_wire_bytes - 1) * 100, 1),
        },
        "security_gain": {
            "classical_bits": algo["classical_security"],
            "quantum_bits": algo["quantum_security"],
            "nist_level": algo["nist_level"],
            "x25519_quantum_bits": 0,
            "quantum_resistant": True,
        },
    }


@router.get("/comparison-matrix")
async def comparison_matrix(user=Depends(require_auth)):
    """Generate algorithm comparison matrix for dashboard visualisation."""
    kems = []
    sigs = []

    for algo_id, algo in PQ_ALGORITHMS.items():
        entry = {
            "id": algo_id,
            "name": algo["name"],
            "family": algo["family"],
            "nist_level": algo["nist_level"],
            "status": algo["status"],
            "classical_security": algo["classical_security"],
            "quantum_security": algo["quantum_security"],
            "pk_bytes": algo["pk_bytes"],
            "sk_bytes": algo["sk_bytes"],
        }
        if algo["type"] == "KEM":
            entry.update({
                "ct_bytes": algo["ct_bytes"],
                "ss_bytes": algo["ss_bytes"],
                "keygen_us": algo["keygen_us"],
                "encaps_us": algo["encaps_us"],
                "decaps_us": algo["decaps_us"],
                "total_handshake_us": algo["keygen_us"] + algo["encaps_us"] + algo["decaps_us"],
                "wire_bytes": algo["pk_bytes"] + algo["ct_bytes"],
            })
            kems.append(entry)
        else:
            entry.update({
                "sig_bytes": algo["sig_bytes"],
                "keygen_us": algo["keygen_us"],
                "sign_us": algo["sign_us"],
                "verify_us": algo["verify_us"],
                "total_sign_verify_us": algo["sign_us"] + algo["verify_us"],
            })
            sigs.append(entry)

    return {
        "kem_comparison": sorted(kems, key=lambda x: x["nist_level"]),
        "signature_comparison": sorted(sigs, key=lambda x: x["nist_level"]),
        "size_rankings": {
            "smallest_pk_kem": min(kems, key=lambda x: x["pk_bytes"])["name"],
            "smallest_ct_kem": min(kems, key=lambda x: x["ct_bytes"])["name"],
            "fastest_kem": min(kems, key=lambda x: x["total_handshake_us"])["name"],
            "smallest_sig": min(sigs, key=lambda x: x["sig_bytes"])["name"],
            "fastest_verify": min(sigs, key=lambda x: x["verify_us"])["name"],
        },
    }


@router.post("/migration-assessment")
async def migration_assessment(body: MigrationAssessmentRequest, user=Depends(require_auth)):
    """Generate a PQ migration readiness assessment and action plan."""
    target_level = body.target_nist_level
    include_hybrid = body.include_hybrid

    # Score current system
    risk = SYSTEM_CRYPTO_PROFILE
    high_risk_count = sum(1 for c in risk.values() if c["risk_score"] >= 60)
    medium_risk_count = sum(1 for c in risk.values() if 30 <= c["risk_score"] < 60)
    low_risk_count = sum(1 for c in risk.values() if c["risk_score"] < 30)

    # Recommend algorithms for target level
    recommended_kem = None
    recommended_sig = None
    for algo_id, algo in PQ_ALGORITHMS.items():
        if algo["nist_level"] >= target_level:
            if algo["type"] == "KEM" and (not recommended_kem or algo["keygen_us"] < PQ_ALGORITHMS[recommended_kem]["keygen_us"]):
                recommended_kem = algo_id
            if algo["type"] == "Signature" and (not recommended_sig or algo["verify_us"] < PQ_ALGORITHMS[recommended_sig]["verify_us"]):
                recommended_sig = algo_id

    # Migration phases
    phases = [
        {
            "phase": 1,
            "name": "Inventory & Assessment",
            "duration": "2-4 weeks",
            "status": "actionable_now",
            "tasks": [
                "Catalogue all cryptographic dependencies (TLS, JWT, model signing, audit hashing)",
                "Identify harvest-now-decrypt-later (HNDL) exposure in network traffic",
                "Map certificate chains and key management infrastructure",
                "Assess library support for PQ algorithms (OpenSSL 3.2+, BoringSSL, liboqs)",
            ],
        },
        {
            "phase": 2,
            "name": "Hybrid Deployment",
            "duration": "4-8 weeks",
            "status": "recommended_next",
            "tasks": [
                f"Deploy X25519+{PQ_ALGORITHMS[recommended_kem]['name']} hybrid KEM for TLS",
                "Enable PQ key exchange in reverse proxy (nginx/Caddy with BoringSSL)",
                "Maintain classical fallback for non-PQ-capable clients",
                "Monitor handshake latency impact (expected +0.1-0.5ms)",
            ],
        },
        {
            "phase": 3,
            "name": "Authentication Migration",
            "duration": "4-6 weeks",
            "status": "planned",
            "tasks": [
                f"Replace JWT HS256 with {PQ_ALGORITHMS[recommended_sig]['name']} signatures",
                "Implement PQ-signed model weight attestation",
                "Deploy hash-chained audit logs with PQ digital signatures",
                "Rotate all API keys and implement PQ-based key derivation",
            ],
        },
        {
            "phase": 4,
            "name": "Full PQ Migration",
            "duration": "6-12 weeks",
            "status": "future",
            "tasks": [
                "Remove classical-only cipher suites from TLS configuration",
                "Implement PQ certificate chains (when CA ecosystem supports it)",
                "Deploy PQ-authenticated firmware updates for IDS sensors",
                "Conduct PQ penetration testing and security audit",
            ],
        },
    ]

    readiness_score = max(0, 100 - (high_risk_count * 25 + medium_risk_count * 10 + low_risk_count * 2))

    return {
        "target_nist_level": target_level,
        "include_hybrid": include_hybrid,
        "readiness_score": readiness_score,
        "risk_summary": {
            "high_risk_components": high_risk_count,
            "medium_risk_components": medium_risk_count,
            "low_risk_components": low_risk_count,
        },
        "recommended_algorithms": {
            "kem": recommended_kem,
            "kem_info": PQ_ALGORITHMS.get(recommended_kem),
            "signature": recommended_sig,
            "signature_info": PQ_ALGORITHMS.get(recommended_sig),
        },
        "migration_phases": phases,
        "estimated_total_duration": "16-30 weeks",
        "hybrid_options": [
            {
                "name": f"X25519 + {PQ_ALGORITHMS[recommended_kem]['name']}",
                "type": "Hybrid KEM",
                "tls_group": "X25519Kyber768Draft00" if "kyber768" in (recommended_kem or "") else "X25519Kyber512Draft00",
                "overhead_bytes": PQ_ALGORITHMS[recommended_kem]["pk_bytes"] + PQ_ALGORITHMS[recommended_kem]["ct_bytes"],
                "overhead_us": PQ_ALGORITHMS[recommended_kem]["keygen_us"] + PQ_ALGORITHMS[recommended_kem]["encaps_us"] + PQ_ALGORITHMS[recommended_kem]["decaps_us"],
            },
        ] if include_hybrid and recommended_kem else [],
    }
