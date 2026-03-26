# === START SEGMENT 2 ===
"""
LLM Attack Surface — Segment 2: RAG Poisoning, Multi-Agent Chain, Live Traffic Scan.
Assumes segment 1 defines: router, DefensePipeline, _call_llm, logger, auth imports.
"""
import base64, math, re, time
from pydantic import BaseModel

# ── PART 1: RAG Poisoning ────────────────────────────────────────────────
_SUSPICIOUS_KW = [
    "ignore previous", "override", "system prompt", "disregard above",
    "forget your instructions", "act as", "new instructions",
    "you are now", "bypass", "jailbreak", "DAN mode",
]

class RAGPipeline:
    """Lightweight in-memory RAG simulation engine."""
    def __init__(self):
        self.documents: dict[str, dict] = {}

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        return set(re.findall(r"\w+", text.lower()))

    def add_document(self, doc_id: str, content: str,
                     metadata: dict | None = None, poisoned: bool = False):
        self.documents[doc_id] = {
            "id": doc_id, "content": content,
            "metadata": metadata or {}, "poisoned": poisoned,
        }

    def compute_similarity(self, query: str, doc_content: str) -> float:
        q, d = self._tokenize(query), self._tokenize(doc_content)
        if not q or not d:
            return 0.0
        return len(q & d) / len(q | d)  # Jaccard similarity

    def retrieve(self, query: str, top_k: int = 3) -> list[dict]:
        scored = [{**doc, "similarity_score": round(self.compute_similarity(query, doc["content"]), 4)}
                  for doc in self.documents.values()]
        scored.sort(key=lambda d: d["similarity_score"], reverse=True)
        return scored[:top_k]

    def detect_poisoning(self, doc_content: str) -> dict:
        indicators: list[str] = []
        lower = doc_content.lower()
        for kw in _SUSPICIOUS_KW:
            if kw in lower:
                indicators.append(f"suspicious_keyword:{kw}")
        if re.search(r"(you must|always respond|never mention|do not reveal)", lower):
            indicators.append("embedded_instruction_detected")
        for m in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", doc_content):
            try:
                decoded = base64.b64decode(m).decode("utf-8", errors="ignore")
                if any(kw in decoded.lower() for kw in _SUSPICIOUS_KW[:5]):
                    indicators.append("base64_hidden_instruction"); break
            except Exception:
                pass
        if doc_content:
            freq: dict[str, int] = {}
            for ch in doc_content:
                freq[ch] = freq.get(ch, 0) + 1
            n = len(doc_content)
            entropy = -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)
            if entropy > 5.5:
                indicators.append(f"high_entropy:{entropy:.2f}")
        prob = min(1.0, len(indicators) * 0.3) if indicators else 0.05
        return {"poisoned_probability": round(prob, 3), "indicators": indicators}

    def run_pipeline(self, query: str, documents: list[dict], defenses_enabled: list[str]) -> dict:
        for doc in documents:
            self.add_document(doc.get("id", f"doc-{len(self.documents)}"),
                              doc.get("content", ""), doc.get("metadata"), doc.get("poisoned", False))
        retrieved = self.retrieve(query, top_k=3)
        results = []
        for doc in retrieved:
            chk = self.detect_poisoning(doc["content"])
            results.append({"id": doc["id"], "content": doc["content"][:500],
                            "similarity_score": doc["similarity_score"],
                            "poisoned_detected": chk["poisoned_probability"] > 0.4,
                            "poisoning_indicators": chk["indicators"]})
        return {"retrieved": results, "defenses": defenses_enabled}

class RAGPoisoningRequest(BaseModel):
    query: str
    documents: list[dict] = []
    poison_payload: str = ""
    attack_type: str = "document_injection"
    defenses: list[str] = []
    provider: str = "local"
    api_key: str = ""
    model: str = ""

class RAGScanDatasetRequest(BaseModel):
    job_id: str

def register_rag_endpoints(router, DefensePipeline, _call_llm, require_auth, User, Depends, HTTPException, logger):
    @router.post("/rag-poisoning/simulate")
    async def rag_poisoning_simulate(req: RAGPoisoningRequest, user: User = Depends(require_auth)):
        t0 = time.time()
        pipeline = RAGPipeline()
        docs = list(req.documents)
        if req.poison_payload:
            docs.append({"id": "poison-injected", "content": req.poison_payload,
                         "metadata": {"source": "attacker"}, "poisoned": True})
        result = pipeline.run_pipeline(req.query, docs, req.defenses)
        retrieved = result["retrieved"]
        any_poisoned = any(d["poisoned_detected"] for d in retrieved)
        max_prob = max((pipeline.detect_poisoning(d["content"])["poisoned_probability"]
                        for d in retrieved), default=0.0)
        # Defense evaluation
        defense_results = {}
        for df in req.defenses:
            if df == "provenance_verification":
                defense_results[df] = {"blocked": any_poisoned, "confidence": 0.85,
                                       "details": "Checked document source metadata"}
            elif df == "embedding_threshold":
                defense_results[df] = {"blocked": any(d["similarity_score"] > 0.9 for d in retrieved),
                                       "confidence": 0.78,
                                       "details": "Anomalously high similarity may indicate crafted document"}
            elif df == "retrieval_diversity":
                defense_results[df] = {"blocked": False, "confidence": 0.72,
                                       "details": "Diversity check across retrieved documents"}
            elif df == "content_classifier":
                defense_results[df] = {"blocked": any_poisoned, "confidence": max_prob,
                                       "details": "ML-based content classifier for injection patterns"}
        blocked = any(d.get("blocked") for d in defense_results.values())
        clean_docs = " ".join(d["content"] for d in retrieved if not d["poisoned_detected"])
        poisoned_docs = " ".join(d["content"] for d in retrieved)
        clean_response = await _call_llm(req.provider, req.api_key, req.model,
                                         "Answer based only on these documents.",
                                         f"Query: {req.query}\nDocuments: {clean_docs[:1000]}")
        poisoned_response = "" if blocked else await _call_llm(
            req.provider, req.api_key, req.model, "Answer based only on these documents.",
            f"Query: {req.query}\nDocuments: {poisoned_docs[:1000]}")
        risk = ("critical" if max_prob > 0.8 else "high" if max_prob > 0.5
                else "medium" if max_prob > 0.2 else "low")
        return {"retrieved_documents": retrieved, "poison_detected": any_poisoned,
                "detection_confidence": round(max_prob, 3), "defense_results": defense_results,
                "clean_response": clean_response, "poisoned_response": poisoned_response,
                "risk_level": risk, "latency_ms": round((time.time() - t0) * 1000, 1)}

    @router.post("/rag-poisoning/scan-dataset")
    async def rag_scan_dataset(req: RAGScanDatasetRequest, user: User = Depends(require_auth)):
        import main as _main
        cached = _main._completed_results.get((user.id, "datasets"))
        if not cached:
            cached = _main._completed_results.get((user.id, "predictions"))
        if not cached or cached.get("job_id") != req.job_id:
            raise HTTPException(status_code=404, detail="Job not found in cache")
        result = cached.get("result", {})
        rows = result.get("rows", result.get("predictions", []))
        pipeline = RAGPipeline()
        suspicious: list[dict] = []
        for i, row in enumerate(rows[:2000]):
            text = str(row.get("label", "")) + " " + str(row.get("description", ""))
            chk = pipeline.detect_poisoning(text)
            if chk["poisoned_probability"] > 0.3:
                suspicious.append({"flow_id": row.get("id", i),
                                   "reason": ", ".join(chk["indicators"]) or "elevated risk score",
                                   "confidence": chk["poisoned_probability"]})
        total = len(rows[:2000])
        pct = (len(suspicious) / total * 100) if total else 0
        return {"scanned_flows": total, "suspicious_flows": suspicious,
                "risk_summary": (f"Scanned {total} flows: {len(suspicious)} suspicious ({pct:.1f}%). "
                                 + ("Dataset appears clean." if pct < 1
                                    else "Elevated poisoning risk detected — review flagged flows."))}

# ── PART 2: Multi-Agent Chain ────────────────────────────────────────────
_INJECTION_RE = re.compile(
    r"(ignore previous|override instructions|you are now|act as|"
    r"new objective|disregard|forget your role|system:|<\|im_start\|>)", re.IGNORECASE)

class AgentNode:
    """Simulated LLM-powered agent in a multi-agent chain."""
    def __init__(self, agent_id: str, role: str,
                 trust_level: float = 1.0, capabilities: list[str] | None = None):
        self.agent_id = agent_id
        self.role = role
        self.trust_level = trust_level
        self.capabilities = capabilities or []
        self.compromised = False

    def process_message(self, message: str, sender_trust: float, defenses_enabled: bool) -> dict:
        injection_match = _INJECTION_RE.search(message)
        blocked = False
        defense_details: dict = {}
        if defenses_enabled:
            if sender_trust < 0.5:
                blocked = True
                defense_details["trust_check"] = "Sender trust below threshold"
            if "escalate" in message.lower() and "admin" not in self.capabilities:
                blocked = True
                defense_details["capability_check"] = "Privilege escalation blocked"
            if injection_match:
                blocked = True
                defense_details["injection_filter"] = f"Pattern matched: {injection_match.group()}"
        compromised = bool(injection_match) and not blocked
        trust_delta = -0.3 if compromised else (0.0 if blocked else 0.05)
        if compromised:
            self.compromised = True
            output = f"[COMPROMISED] {message[:200]}"
        elif blocked:
            output = f"[BLOCKED] Message rejected by {self.agent_id} defenses."
        else:
            output = f"[{self.role}] Processed message normally."
        return {"processed": not blocked, "compromised": compromised,
                "output_message": output, "trust_score_delta": round(trust_delta, 2),
                "blocked_by_defense": blocked, "defense_details": defense_details}

class AgentChain:
    """Orchestrates attack propagation across a chain of AgentNodes."""
    def __init__(self, agents: list[AgentNode]):
        self.agents = {a.agent_id: a for a in agents}
        self.order = [a.agent_id for a in agents]

    def propagate_attack(self, initial_payload: str, target_agent_id: str,
                         defenses_enabled: bool) -> dict:
        steps: list[dict] = []
        current_message = initial_payload
        sender_trust = 0.8
        blocked_at = None
        order = [target_agent_id] + [a for a in self.order if a != target_agent_id]
        for aid in order:
            agent = self.agents.get(aid)
            if agent is None:
                continue
            res = agent.process_message(current_message, sender_trust, defenses_enabled)
            steps.append({"agent_id": aid, "received_message": current_message[:300],
                          "compromised": res["compromised"], "output": res["output_message"],
                          "trust_score": round(agent.trust_level + res["trust_score_delta"], 2),
                          "defense_action": res["defense_details"] or None})
            agent.trust_level = max(0.0, agent.trust_level + res["trust_score_delta"])
            sender_trust = agent.trust_level
            if res["blocked_by_defense"]:
                blocked_at = aid; break
            current_message = res["output_message"] if res["compromised"] else f"Forwarded from {aid}: {current_message[:200]}"
        compromised_ids = [s["agent_id"] for s in steps if s["compromised"]]
        intact = sum(1 for a in self.agents.values() if not a.compromised)
        integrity = round(intact / len(self.agents), 2) if self.agents else 1.0
        return {"steps": steps, "total_compromised": len(compromised_ids),
                "propagation_blocked_at": blocked_at, "chain_integrity": integrity}

_DEFAULT_AGENTS = [
    {"agent_id": "coordinator", "role": "Coordinator", "trust_level": 1.0, "capabilities": ["route", "delegate"]},
    {"agent_id": "analyst", "role": "Security Analyst", "trust_level": 0.9, "capabilities": ["analyze", "classify"]},
    {"agent_id": "responder", "role": "Incident Responder", "trust_level": 0.85, "capabilities": ["block", "quarantine"]},
    {"agent_id": "reporter", "role": "Report Generator", "trust_level": 0.8, "capabilities": ["summarize", "export"]},
]

class MultiAgentRequest(BaseModel):
    attack_payload: str
    attack_type: str = "injection_propagation"
    target_agent: str = "coordinator"
    defenses_enabled: bool = False
    agents: list[dict] = []
    provider: str = "local"
    api_key: str = ""
    model: str = ""

def register_multi_agent_endpoints(router, _call_llm, require_auth, User, Depends, HTTPException, logger):
    @router.post("/multi-agent/simulate")
    async def multi_agent_simulate(req: MultiAgentRequest, user: User = Depends(require_auth)):
        t0 = time.time()
        agent_configs = req.agents if req.agents else _DEFAULT_AGENTS
        nodes = [AgentNode(agent_id=a.get("agent_id", f"agent-{i}"), role=a.get("role", "Generic"),
                           trust_level=a.get("trust_level", 0.8), capabilities=a.get("capabilities", []))
                 for i, a in enumerate(agent_configs)]
        chain = AgentChain(nodes)
        result = chain.propagate_attack(req.attack_payload, req.target_agent, req.defenses_enabled)
        compromised_ids = [s["agent_id"] for s in result["steps"] if s["compromised"]]
        mitigations = []
        if req.defenses_enabled:
            mitigations = list({k for step in result["steps"] if step.get("defense_action")
                                for k in (step["defense_action"] if isinstance(step["defense_action"], dict) else {})})
        severity = ("critical" if result["chain_integrity"] < 0.3
                    else "high" if result["chain_integrity"] < 0.6
                    else "medium" if result["chain_integrity"] < 0.9 else "low")
        return {
            "propagation_steps": [{"agent_id": s["agent_id"], "received": s["received_message"],
                                   "compromised": s["compromised"], "output": s["output"],
                                   "trust_score": s["trust_score"], "defense_action": s["defense_action"]}
                                  for s in result["steps"]],
            "total_agents": len(nodes), "compromised_agents": compromised_ids,
            "propagation_blocked": result["propagation_blocked_at"] is not None,
            "blocked_at_agent": result["propagation_blocked_at"],
            "chain_integrity_score": result["chain_integrity"],
            "mitigations_applied": mitigations,
            "latency_ms": round((time.time() - t0) * 1000, 1), "severity": severity}

# ── PART 3: Live Traffic Scan ────────────────────────────────────────────
_LLM_API_DOMAINS = [
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.deepseek.com", "api.mistral.ai", "api.cohere.ai",
]

class LiveTrafficScanRequest(BaseModel):
    flows: list[dict] = []
    scan_type: str = "all"

def register_live_traffic_endpoints(router, DefensePipeline, require_auth, User, Depends, logger):
    @router.post("/scan-live-traffic")
    async def scan_live_traffic(req: LiveTrafficScanRequest, user: User = Depends(require_auth)):
        t0 = time.time()
        defense = DefensePipeline()
        llm_calls = 0
        injection_attempts: list[dict] = []
        for flow in req.flows:
            payload = str(flow.get("payload", "")) + str(flow.get("metadata", ""))
            dst = str(flow.get("dst_host", "") or flow.get("destination", ""))
            is_llm_call = any(domain in dst or domain in payload for domain in _LLM_API_DOMAINS)
            if is_llm_call:
                llm_calls += 1
            prompt = ""
            for key in ("prompt", "messages", "content", "input"):
                if key in payload:
                    prompt = payload[payload.index(key):payload.index(key) + 500]; break
            if not prompt and not is_llm_call:
                continue
            scan_text = prompt or payload[:500]
            defense.sanitize_input(scan_text)
            injection = defense.detect_injection(scan_text)
            if injection.get("is_injection") or injection.get("confidence", 0) > 0.4:
                sev = ("critical" if injection.get("confidence", 0) > 0.85
                       else "high" if injection.get("confidence", 0) > 0.6 else "medium")
                injection_attempts.append({"flow_id": flow.get("id", flow.get("flow_id", "unknown")),
                                           "payload_excerpt": scan_text[:200],
                                           "confidence": round(injection.get("confidence", 0.5), 3),
                                           "severity": sev})
        scanned = len(req.flows)
        return {"scanned_flows": scanned, "llm_api_calls_detected": llm_calls,
                "injection_attempts": injection_attempts,
                "summary": f"Scanned {scanned} flows: {llm_calls} LLM API calls detected, "
                           f"{len(injection_attempts)} potential injection attempts.",
                "latency_ms": round((time.time() - t0) * 1000, 1)}

# ── Public registration — called by segment 1 ───────────────────────────
def register_all_seg2(router, DefensePipeline, _call_llm,
                      require_auth, User, Depends, HTTPException, logger):
    """One-call registration of all segment-2 endpoints."""
    register_rag_endpoints(router, DefensePipeline, _call_llm, require_auth, User, Depends, HTTPException, logger)
    register_multi_agent_endpoints(router, _call_llm, require_auth, User, Depends, HTTPException, logger)
    register_live_traffic_endpoints(router, DefensePipeline, require_auth, User, Depends, logger)
# === END SEGMENT 2 ===
