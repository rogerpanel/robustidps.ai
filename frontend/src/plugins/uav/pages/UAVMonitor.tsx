import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Plane, Radar, ShieldCheck, Network, Eye, ClipboardCheck, Cpu, AlertTriangle,
} from 'lucide-react'
import PageGuide from '../../../components/PageGuide'
import MCRJSChart from '../components/MCRJSChart'
import SwarmGraphAnimated from '../components/SwarmGraphAnimated'
import CertificateStrip from '../components/CertificateStrip'
import JSOperatingPoint from '../components/JSOperatingPoint'
import { fetchUAVOverview, fetchSwarmSnapshot, fetchCertificates } from '../api'
import type { OverviewResponse, SwarmSnapshot, CertificateResponse } from '../api'

const SUBPAGES = [
  { to: '/uav/perception',     label: 'Perception Tester',     icon: Eye,            desc: 'FGSM / PGD / CW on a single frame' },
  { to: '/uav/gnss',           label: 'GNSS Spoof Monitor',    icon: Radar,          desc: 'Sky plot + C/N₀ + spoof confidence' },
  { to: '/uav/certification',  label: 'Certification Dashboard', icon: ShieldCheck,  desc: 'Lipschitz, RS, PAC-Bayes, DP budget' },
  { to: '/uav/swarm',          label: 'Swarm Graph',            icon: Network,       desc: 'Gₜ at three time slices' },
  { to: '/uav/mission-plan',   label: 'Mission Plan Review',    icon: ClipboardCheck,desc: 'CyberSecLLM zero-shot audit' },
]

export default function UAVMonitor() {
  const [overview, setOverview] = useState<OverviewResponse | null>(null)
  const [swarm, setSwarm] = useState<SwarmSnapshot[]>([])
  const [cert, setCert] = useState<CertificateResponse | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([fetchUAVOverview(), fetchSwarmSnapshot(), fetchCertificates()])
      .then(([o, s, c]) => { setOverview(o); setSwarm(s.snapshots); setCert(c) })
      .catch((e) => setErr(String(e)))
  }, [])

  if (err) return (
    <div className="p-4 bg-accent-red/10 border border-accent-red/30 rounded-md text-sm text-accent-red">
      <AlertTriangle className="inline w-4 h-4 mr-2" />UAV plugin error: {err}
    </div>
  )
  if (!overview || !cert) return <div className="p-4 text-text-secondary">Loading UAV / Aerial Defense…</div>

  const framework = overview.ew_curves.find((c) => c.config_key === 'framework')

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-display font-bold flex items-center gap-2">
            <Plane className="w-5 h-5 text-accent-blue" />
            UAV / Aerial Defense Monitor
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl">
            Chapter 6 framework — three-tier <span className="font-mono">edge / droneport / cloud</span> stack
            atop the M1–M7 + CyberSecLLM kernel. Hero panel: <em>Mission-Completion-Rate vs Jamming-to-Signal Ratio</em>
            on UAV-EW-Bench-2026 ({(overview.benchmark.n_flights ?? 0).toLocaleString()} simulated flights).
          </p>
        </div>
        <div className="text-right text-[10px] text-text-secondary font-mono">
          plugin: <span className="text-text-primary">robustidps_web_app/plugins/uav/</span><br/>
          kernel: unchanged
        </div>
      </div>

      <PageGuide
        title="How to use UAV Monitor"
        steps={[
          { title: 'Read the headline', desc: 'The MCR-vs-J/S chart shows mission completion under jamming for four configurations. The orange dashed line is DO-326A 0.90.' },
          { title: 'Drag the J/S slider', desc: 'Below the chart — set any J/S 0-40 dB; the four tiles snapshot each config\'s MCR + 95% CI at that point with a pass/fail badge.' },
          { title: 'Watch live certificates', desc: 'Lipschitz / Grönwall / RS / PAC-Bayes / (ε,δ)-DP recompute on every visit on a 16-sample synthetic batch.' },
          { title: 'Jump to operator pages', desc: 'The right card links to Perception, GNSS Spoof, Certification, Swarm, Mission Plan — each one drills into a piece of the framework.' },
          { title: 'Ask the SOC Copilot', desc: 'Try "what\'s the framework\'s J/S advantage at 20 dB?" — any of the 4 LLMs will call get_uav_ew_bench_curves and ground the answer in the live data.' },
        ]}
        tip="Hit the sidebar-footer theme toggle (Dark/Print) — Print theme + Cmd-P drops a paper-ready PDF of any UAV page straight into your evidence folder."
      />

      {/* Hero panel — MCR vs J/S */}
      <div className="bg-bg-card rounded-xl p-4 border-t-2 border-accent-orange/40">
        <div className="flex items-baseline justify-between mb-2 gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold">{overview.benchmark.name}</h2>
            <SourceBadge source={overview.ew_source} />
          </div>
          <div className="text-[10px] text-text-secondary font-mono">
            DO-326A threshold: MCR ≥ {overview.benchmark.regulatory_threshold.mcr}
            <span className="mx-2">·</span>
            Operational target: MCR ≥ {overview.benchmark.operational_target.mcr_floor} at J/S ≤ {overview.benchmark.operational_target.js_db_max} dB
          </div>
        </div>
        <MCRJSChart
          curves={overview.ew_curves}
          threshold={overview.benchmark.regulatory_threshold.mcr}
          thresholdLabel={overview.benchmark.regulatory_threshold.name}
        />
        {framework && (
          <div className="mt-2 text-[11px] text-text-secondary">
            <span className="text-accent-blue font-semibold">Phase A framework</span> holds the {overview.benchmark.regulatory_threshold.name} floor
            up to <span className="text-text-primary font-mono">{framework.do_326a_crossing_db} dB J/S</span> —
            vs <span className="font-mono">{overview.ew_curves.find((c) => c.config_key === 'seq2seq')?.do_326a_crossing_db} dB</span> for Seq2Seq Tr.,
            {' '}<span className="font-mono">{overview.ew_curves.find((c) => c.config_key === 'caf_cnn')?.do_326a_crossing_db} dB</span> for CAF-CNN,
            {' '}<span className="font-mono">{overview.ew_curves.find((c) => c.config_key === 'no_def')?.do_326a_crossing_db} dB</span> for unprotected PX4.
          </div>
        )}
      </div>

      {/* Live J/S operating point — drag to query any J/S */}
      <JSOperatingPoint />

      {/* Certificate strip */}
      <div className="bg-bg-card rounded-xl p-4">
        <h2 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5 text-accent-blue" /> Live certificates
        </h2>
        <CertificateStrip cert={cert} />
        <p className="text-[10px] text-text-secondary mt-2">
          Lipschitz–Grönwall (Theorem 6.1) and randomized smoothing (Cohen) recomputed on a 16-sample synthetic batch
          every visit. Operational interpretation: certificates hold the {cert.operational_interpretation.regulatory_floor_label} floor
          at J/S ≤ {cert.operational_interpretation.js_db_floor} dB.
        </p>
      </div>

      {/* Three-up: tiers, swarm snapshot, sub-pages */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-accent-blue" /> Three-tier stack
          </h2>
          <div className="space-y-2">
            {overview.tiers.map((t) => (
              <div key={t.name} className="border border-bg-card/60 rounded-md p-2">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium">{t.name}</span>
                  {t.budget_w && <span className="text-[9px] font-mono text-text-secondary">{'<'} {t.budget_w} W</span>}
                </div>
                <div className="flex flex-wrap gap-1">
                  {t.methods.map((m) => (
                    <span key={m} className="text-[9px] font-mono bg-accent-blue/10 text-accent-blue px-1.5 py-0.5 rounded">{m}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="mt-2 text-[10px] text-text-secondary border-t border-bg-card/40 pt-2 font-mono">
            edge profile · {overview.edge_profile.platform} · {overview.edge_profile.latency_ms_per_frame} ms/frame @ {overview.edge_profile.fps} fps · {overview.edge_profile.ram_mib} MiB · {overview.edge_profile.cpu_pct_one_core}% of one core
          </div>
        </div>

        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2 flex items-center gap-1.5">
            <Network className="w-3.5 h-3.5 text-accent-blue" /> Swarm snapshot Gₜ
          </h2>
          {swarm.length > 0 && <SwarmGraphAnimated snapshots={swarm} />}
        </div>

        <div className="bg-bg-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-2">Operator pages</h2>
          <div className="space-y-1.5">
            {SUBPAGES.map((s) => (
              <Link
                key={s.to} to={s.to}
                className="flex items-start gap-2 p-2 rounded-md hover:bg-bg-secondary/60 transition-colors group"
              >
                <s.icon className="w-4 h-4 mt-0.5 text-accent-blue group-hover:text-accent-orange transition-colors" />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium">{s.label}</div>
                  <div className="text-[10px] text-text-secondary truncate">{s.desc}</div>
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function SourceBadge({ source }: { source?: string }) {
  if (source === 'phase_d_measured') {
    return (
      <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-accent-green/10 text-accent-green border border-accent-green/30 uppercase">
        Phase D · measured
      </span>
    )
  }
  return (
    <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-accent-amber/10 text-accent-amber border border-accent-amber/30 uppercase">
      Phase A · chapter-anchored
    </span>
  )
}
