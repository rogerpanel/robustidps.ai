import { useState } from 'react'
import { ShieldCheck, ScrollText, AlertTriangle, Scale, Mail, ChevronDown } from 'lucide-react'

interface Props {
  onAccept: () => void
}

export default function EthicalUseAgreement({ onAccept }: Props) {
  const [hasRead, setHasRead] = useState(false)
  const [willReport, setWillReport] = useState(false)

  const canAgree = hasRead && willReport

  return (
    <div className="fixed inset-0 z-[9999] bg-bg-primary/98 backdrop-blur-sm overflow-y-auto p-4">
      <div className="w-full max-w-3xl mx-auto my-8">
        {/* Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center gap-3 mb-3">
            <ShieldCheck className="w-10 h-10 text-accent-blue" />
            <h1 className="font-display font-bold text-2xl text-text-primary">
              RobustIDPS<span className="text-accent-blue">.AI</span>
            </h1>
          </div>
          <div className="flex items-center justify-center gap-2 text-accent-amber">
            <Scale className="w-5 h-5" />
            <h2 className="font-display font-semibold text-lg">Ethical Use Guidance &amp; Caution</h2>
          </div>
        </div>

        {/* Policy Card */}
        <div className="bg-bg-card border border-bg-card rounded-xl shadow-2xl overflow-hidden">
          <div className="max-h-[60vh] overflow-y-auto p-6 md:p-8 space-y-6 text-sm text-text-secondary leading-relaxed">

            {/* Purpose */}
            <section>
              <h3 className="flex items-center gap-2 text-text-primary font-semibold text-base mb-2">
                <ScrollText className="w-4 h-4 text-accent-blue" />
                1. Purpose &amp; Scope
              </h3>
              <p>
                RobustIDPS.AI is an advanced adversarial machine learning and intrusion detection/prevention
                research platform designed <strong className="text-text-primary">exclusively</strong> for:
              </p>
              <ul className="list-disc ml-6 mt-2 space-y-1">
                <li><strong className="text-text-primary">Academic research</strong> — peer-reviewed studies, dissertations, and educational coursework in adversarial ML, cybersecurity, and network defence.</li>
                <li><strong className="text-text-primary">Industrial cybersecurity</strong> — authorised penetration testing, red-team/blue-team exercises, threat modelling, and security posture assessment within organisational boundaries.</li>
                <li><strong className="text-text-primary">Government &amp; defence</strong> — lawful national security research conducted under appropriate oversight and legal frameworks.</li>
                <li><strong className="text-text-primary">Evaluation &amp; benchmarking</strong> — reproducible assessment of IDS/IPS model robustness against adversarial perturbations.</li>
              </ul>
            </section>

            {/* Prohibited Use */}
            <section>
              <h3 className="flex items-center gap-2 text-text-primary font-semibold text-base mb-2">
                <AlertTriangle className="w-4 h-4 text-accent-red" />
                2. Prohibited Use
              </h3>
              <p>The following activities are <strong className="text-accent-red">strictly prohibited</strong>:</p>
              <ul className="list-disc ml-6 mt-2 space-y-1">
                <li>Launching real-world cyberattacks, denial-of-service attacks, or any form of unauthorised network intrusion against systems you do not own or have explicit written permission to test.</li>
                <li>Crafting adversarial samples or evasion techniques intended for deployment against production systems without proper authorisation.</li>
                <li>Using the platform's red-team capabilities, adversarial attack generators, or evasion tooling for malicious purposes, including but not limited to espionage, sabotage, or data theft.</li>
                <li>Circumventing legal, ethical, or institutional review board (IRB/ethics committee) requirements applicable to your jurisdiction.</li>
                <li>Distributing generated adversarial payloads, model weights, or attack methodologies to unauthorised third parties.</li>
                <li>Any activity that violates applicable local, national, or international law.</li>
              </ul>
            </section>

            {/* Regulatory Compliance */}
            <section>
              <h3 className="flex items-center gap-2 text-text-primary font-semibold text-base mb-2">
                <Scale className="w-4 h-4 text-accent-blue" />
                3. Regulatory &amp; Standards Compliance
              </h3>
              <p>All users must operate in accordance with applicable regulatory frameworks, including but not limited to:</p>
              <ul className="list-disc ml-6 mt-2 space-y-1">
                <li><strong className="text-text-primary">ISO/IEC 27001:2022</strong> — Information Security Management Systems (ISMS).</li>
                <li><strong className="text-text-primary">ISO/IEC 27032:2023</strong> — Cybersecurity guidelines and Internet security.</li>
                <li><strong className="text-text-primary">ISO/IEC 27005:2022</strong> — Information security risk management.</li>
                <li><strong className="text-text-primary">ISO/IEC 23894:2023</strong> — Artificial Intelligence risk management.</li>
                <li><strong className="text-text-primary">NIST Cybersecurity Framework (CSF 2.0)</strong> — Identify, Protect, Detect, Respond, Recover.</li>
                <li><strong className="text-text-primary">NIST AI RMF (AI 100-1)</strong> — AI Risk Management Framework.</li>
                <li><strong className="text-text-primary">EU AI Act (2024/1689)</strong> — Risk-based regulation of AI systems within the European Union.</li>
                <li><strong className="text-text-primary">GDPR (2016/679)</strong> — General Data Protection Regulation for personal data handling.</li>
                <li><strong className="text-text-primary">MITRE ATT&amp;CK / ATLAS</strong> — Adversarial threat modelling aligned with recognised knowledge bases.</li>
              </ul>
            </section>

            {/* Responsible AI */}
            <section>
              <h3 className="flex items-center gap-2 text-text-primary font-semibold text-base mb-2">
                <ShieldCheck className="w-4 h-4 text-accent-green" />
                4. Responsible AI &amp; Ethical Principles
              </h3>
              <ul className="list-disc ml-6 space-y-1">
                <li><strong className="text-text-primary">Transparency</strong> — All experimental methodologies should be documented and reproducible.</li>
                <li><strong className="text-text-primary">Fairness</strong> — Adversarial robustness evaluations must not introduce or amplify bias in detection models.</li>
                <li><strong className="text-text-primary">Accountability</strong> — Users bear full responsibility for how they apply tools, results, and generated artefacts from this platform.</li>
                <li><strong className="text-text-primary">Privacy</strong> — Any datasets containing real network traffic or PII must be anonymised and handled per GDPR or equivalent regulations.</li>
                <li><strong className="text-text-primary">Dual-Use Awareness</strong> — Techniques explored on this platform (adversarial attacks, evasion, model poisoning) are inherently dual-use. Users must exercise professional judgement and ensure their work contributes to defensive security.</li>
              </ul>
            </section>

            {/* Data Handling */}
            <section>
              <h3 className="flex items-center gap-2 text-text-primary font-semibold text-base mb-2">
                <ScrollText className="w-4 h-4 text-accent-blue" />
                5. Data Handling &amp; Audit
              </h3>
              <ul className="list-disc ml-6 space-y-1">
                <li>All user actions within the platform are logged for audit purposes in compliance with ISO 27001 Annex A controls.</li>
                <li>Uploaded datasets, model configurations, and experimental results may be subject to review by platform administrators.</li>
                <li>Users must not upload classified, export-controlled, or otherwise restricted data without appropriate clearance and platform-level approval.</li>
              </ul>
            </section>

            {/* Reporting & Contact */}
            <section>
              <h3 className="flex items-center gap-2 text-text-primary font-semibold text-base mb-2">
                <Mail className="w-4 h-4 text-accent-blue" />
                6. Abuse Reporting &amp; Contact
              </h3>
              <p>
                If you become aware of any misuse, abuse, or violation of this policy by any user,
                you are <strong className="text-text-primary">obligated</strong> to report it immediately to the
                application developer and administrator:
              </p>
              <p className="mt-2 text-accent-blue font-medium">
                admin@RobustIDPS.ai
              </p>
              <p className="mt-2">
                Reports may be submitted anonymously. All reports will be investigated, and appropriate action—including
                account suspension, institutional notification, or legal referral—will be taken.
              </p>
            </section>

            {/* Liability */}
            <section>
              <h3 className="flex items-center gap-2 text-text-primary font-semibold text-base mb-2">
                <AlertTriangle className="w-4 h-4 text-accent-amber" />
                7. Limitation of Liability
              </h3>
              <p>
                The developers and administrators of RobustIDPS.AI provide this platform "as-is" for research
                and authorised security purposes. They shall not be held liable for any damages, losses, or
                legal consequences arising from misuse of the platform or its outputs. Users assume full
                responsibility for ensuring their activities comply with all applicable laws and institutional policies.
              </p>
            </section>

            <div className="pt-2 text-xs text-text-secondary/60 text-center">
              <p>RobustIDPS.AI — MEPhI University | PhD Dissertation Implementation by Roger Nick Anaedevha</p>
              <p className="mt-1">Policy version 1.0 — Effective from platform access date</p>
            </div>
          </div>

          {/* Scroll indicator */}
          <div className="flex justify-center py-1 text-text-secondary/40 bg-gradient-to-t from-bg-card to-transparent">
            <ChevronDown className="w-4 h-4 animate-bounce" />
          </div>

          {/* Agreement Section */}
          <div className="border-t border-bg-primary p-6 space-y-4">
            {/* Checkbox: Read and understood */}
            <label className="flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={hasRead}
                onChange={(e) => setHasRead(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-2 border-text-secondary/30 bg-bg-primary text-accent-blue focus:ring-accent-blue/50 cursor-pointer accent-[#3b82f6]"
              />
              <span className="text-sm text-text-secondary group-hover:text-text-primary transition-colors">
                I have <strong className="text-text-primary">read and understand</strong> the Ethical Use Guidance &amp; Caution policy
                outlined above and agree to abide by all stated terms, prohibitions, and regulatory requirements.
              </span>
            </label>

            {/* Checkbox: Report abuse */}
            <label className="flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={willReport}
                onChange={(e) => setWillReport(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-2 border-text-secondary/30 bg-bg-primary text-accent-blue focus:ring-accent-blue/50 cursor-pointer accent-[#3b82f6]"
              />
              <span className="text-sm text-text-secondary group-hover:text-text-primary transition-colors">
                I agree to <strong className="text-text-primary">report any abuse</strong> or policy violations I encounter to the
                application developer and administrator at{' '}
                <span className="text-accent-blue font-medium">admin@RobustIDPS.ai</span>.
              </span>
            </label>

            {/* I Agree Button */}
            <button
              onClick={onAccept}
              disabled={!canAgree}
              className={`w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-semibold transition-all duration-200 ${
                canAgree
                  ? 'bg-accent-blue hover:bg-accent-blue/90 text-white shadow-lg shadow-accent-blue/25 cursor-pointer'
                  : 'bg-bg-primary text-text-secondary/40 cursor-not-allowed'
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              I Agree
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
