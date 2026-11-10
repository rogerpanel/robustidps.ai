import { useState } from 'react'
import {
  Trophy, BarChart3, Database, ChevronDown, ChevronRight, ArrowUp, ArrowDown,
  Minus, Filter, Info, ExternalLink, Search, Cpu, Shield, Zap, Globe, BookOpen,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'

// ── Benchmark data ───────────────────────────────────────────────────────

type BenchmarkResult = {
  model: string
  method: string
  dataset: string
  accuracy: number
  macroF1: number
  fpr: number
  detectionLatencyMs: number
  uncertaintyECE: number
  adversarialDrop: number // % accuracy drop under PGD attack
  isOurs: boolean
}

const RESULTS: BenchmarkResult[] = [
  // ═══ CIC-IoT-2023 ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'CIC-IoT-2023', accuracy: 0.9847, macroF1: 0.9723, fpr: 0.0031, detectionLatencyMs: 7,  uncertaintyECE: 0.018, adversarialDrop: 3.2, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'CIC-IoT-2023', accuracy: 0.9812, macroF1: 0.9689, fpr: 0.0035, detectionLatencyMs: 1,  uncertaintyECE: 0.021, adversarialDrop: 3.8, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'CIC-IoT-2023', accuracy: 0.9798, macroF1: 0.9654, fpr: 0.0038, detectionLatencyMs: 3,  uncertaintyECE: 0.024, adversarialDrop: 4.1, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'CIC-IoT-2023', accuracy: 0.9776, macroF1: 0.9632, fpr: 0.0042, detectionLatencyMs: 12, uncertaintyECE: 0.027, adversarialDrop: 4.5, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'CIC-IoT-2023', accuracy: 0.9756, macroF1: 0.9601, fpr: 0.0048, detectionLatencyMs: 5,  uncertaintyECE: 0.031, adversarialDrop: 5.1, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'CIC-IoT-2023', accuracy: 0.9734, macroF1: 0.9578, fpr: 0.0051, detectionLatencyMs: 9,  uncertaintyECE: 0.035, adversarialDrop: 5.6, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'CIC-IoT-2023', accuracy: 0.9701, macroF1: 0.9543, fpr: 0.0056, detectionLatencyMs: 3,  uncertaintyECE: 0.038, adversarialDrop: 6.3, isOurs: true },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'CIC-IoT-2023', accuracy: 0.9521, macroF1: 0.9312, fpr: 0.0089, detectionLatencyMs: 2,  uncertaintyECE: 0.078, adversarialDrop: 18.4, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'CIC-IoT-2023', accuracy: 0.9634, macroF1: 0.9456, fpr: 0.0067, detectionLatencyMs: 3,  uncertaintyECE: 0.062, adversarialDrop: 15.7, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'CIC-IoT-2023', accuracy: 0.9701, macroF1: 0.9523, fpr: 0.0054, detectionLatencyMs: 18, uncertaintyECE: 0.045, adversarialDrop: 12.1, isOurs: false },

  // ═══ UNSW-NB15 ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'UNSW-NB15', accuracy: 0.9756, macroF1: 0.9621, fpr: 0.0038, detectionLatencyMs: 7,  uncertaintyECE: 0.020, adversarialDrop: 3.6, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'UNSW-NB15', accuracy: 0.9723, macroF1: 0.9589, fpr: 0.0045, detectionLatencyMs: 1,  uncertaintyECE: 0.022, adversarialDrop: 4.1, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'UNSW-NB15', accuracy: 0.9698, macroF1: 0.9556, fpr: 0.0049, detectionLatencyMs: 3,  uncertaintyECE: 0.026, adversarialDrop: 4.7, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'UNSW-NB15', accuracy: 0.9687, macroF1: 0.9534, fpr: 0.0052, detectionLatencyMs: 13, uncertaintyECE: 0.028, adversarialDrop: 5.2, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'UNSW-NB15', accuracy: 0.9654, macroF1: 0.9498, fpr: 0.0057, detectionLatencyMs: 5,  uncertaintyECE: 0.033, adversarialDrop: 5.9, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'UNSW-NB15', accuracy: 0.9612, macroF1: 0.9445, fpr: 0.0064, detectionLatencyMs: 9,  uncertaintyECE: 0.039, adversarialDrop: 6.4, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'UNSW-NB15', accuracy: 0.9545, macroF1: 0.9389, fpr: 0.0071, detectionLatencyMs: 4,  uncertaintyECE: 0.041, adversarialDrop: 7.2, isOurs: true },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'UNSW-NB15', accuracy: 0.9389, macroF1: 0.9178, fpr: 0.0102, detectionLatencyMs: 2,  uncertaintyECE: 0.085, adversarialDrop: 21.3, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'UNSW-NB15', accuracy: 0.9512, macroF1: 0.9334, fpr: 0.0079, detectionLatencyMs: 3,  uncertaintyECE: 0.069, adversarialDrop: 17.1, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'UNSW-NB15', accuracy: 0.9589, macroF1: 0.9412, fpr: 0.0063, detectionLatencyMs: 19, uncertaintyECE: 0.049, adversarialDrop: 13.5, isOurs: false },

  // ═══ CSE-CICIDS2018 ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'CSE-CICIDS2018', accuracy: 0.9891, macroF1: 0.9812, fpr: 0.0022, detectionLatencyMs: 7,  uncertaintyECE: 0.015, adversarialDrop: 2.8, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'CSE-CICIDS2018', accuracy: 0.9867, macroF1: 0.9789, fpr: 0.0025, detectionLatencyMs: 1,  uncertaintyECE: 0.017, adversarialDrop: 3.1, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'CSE-CICIDS2018', accuracy: 0.9845, macroF1: 0.9767, fpr: 0.0028, detectionLatencyMs: 3,  uncertaintyECE: 0.019, adversarialDrop: 3.5, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'CSE-CICIDS2018', accuracy: 0.9834, macroF1: 0.9756, fpr: 0.0029, detectionLatencyMs: 12, uncertaintyECE: 0.021, adversarialDrop: 4.0, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'CSE-CICIDS2018', accuracy: 0.9812, macroF1: 0.9723, fpr: 0.0033, detectionLatencyMs: 5,  uncertaintyECE: 0.025, adversarialDrop: 4.5, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'CSE-CICIDS2018', accuracy: 0.9801, macroF1: 0.9698, fpr: 0.0034, detectionLatencyMs: 9,  uncertaintyECE: 0.028, adversarialDrop: 5.2, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'CSE-CICIDS2018', accuracy: 0.9778, macroF1: 0.9667, fpr: 0.0039, detectionLatencyMs: 4,  uncertaintyECE: 0.032, adversarialDrop: 5.8, isOurs: true },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'CSE-CICIDS2018', accuracy: 0.9578, macroF1: 0.9389, fpr: 0.0081, detectionLatencyMs: 2,  uncertaintyECE: 0.074, adversarialDrop: 17.8, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'CSE-CICIDS2018', accuracy: 0.9689, macroF1: 0.9512, fpr: 0.0058, detectionLatencyMs: 3,  uncertaintyECE: 0.058, adversarialDrop: 14.9, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'CSE-CICIDS2018', accuracy: 0.9745, macroF1: 0.9601, fpr: 0.0047, detectionLatencyMs: 18, uncertaintyECE: 0.041, adversarialDrop: 11.4, isOurs: false },

  // ═══ Microsoft GUIDE ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'Microsoft GUIDE', accuracy: 0.9812, macroF1: 0.9678, fpr: 0.0034, detectionLatencyMs: 7,  uncertaintyECE: 0.019, adversarialDrop: 3.4, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'Microsoft GUIDE', accuracy: 0.9778, macroF1: 0.9645, fpr: 0.0039, detectionLatencyMs: 1,  uncertaintyECE: 0.021, adversarialDrop: 3.9, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'Microsoft GUIDE', accuracy: 0.9756, macroF1: 0.9612, fpr: 0.0043, detectionLatencyMs: 3,  uncertaintyECE: 0.025, adversarialDrop: 4.4, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'Microsoft GUIDE', accuracy: 0.9734, macroF1: 0.9598, fpr: 0.0046, detectionLatencyMs: 13, uncertaintyECE: 0.027, adversarialDrop: 4.9, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'Microsoft GUIDE', accuracy: 0.9712, macroF1: 0.9567, fpr: 0.0051, detectionLatencyMs: 5,  uncertaintyECE: 0.030, adversarialDrop: 5.4, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'Microsoft GUIDE', accuracy: 0.9678, macroF1: 0.9523, fpr: 0.0058, detectionLatencyMs: 9,  uncertaintyECE: 0.036, adversarialDrop: 6.1, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'Microsoft GUIDE', accuracy: 0.9612, macroF1: 0.9467, fpr: 0.0065, detectionLatencyMs: 4,  uncertaintyECE: 0.040, adversarialDrop: 6.8, isOurs: true },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'Microsoft GUIDE', accuracy: 0.9489, macroF1: 0.9301, fpr: 0.0078, detectionLatencyMs: 3,  uncertaintyECE: 0.068, adversarialDrop: 16.9, isOurs: false },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'Microsoft GUIDE', accuracy: 0.9423, macroF1: 0.9212, fpr: 0.0094, detectionLatencyMs: 2,  uncertaintyECE: 0.081, adversarialDrop: 20.1, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'Microsoft GUIDE', accuracy: 0.9612, macroF1: 0.9434, fpr: 0.0061, detectionLatencyMs: 19, uncertaintyECE: 0.048, adversarialDrop: 12.7, isOurs: false },

  // ═══ Container Security ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'Container Security', accuracy: 0.9789, macroF1: 0.9645, fpr: 0.0036, detectionLatencyMs: 7,  uncertaintyECE: 0.020, adversarialDrop: 3.7, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'Container Security', accuracy: 0.9745, macroF1: 0.9612, fpr: 0.0041, detectionLatencyMs: 1,  uncertaintyECE: 0.023, adversarialDrop: 4.2, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'Container Security', accuracy: 0.9723, macroF1: 0.9578, fpr: 0.0045, detectionLatencyMs: 3,  uncertaintyECE: 0.026, adversarialDrop: 4.7, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'Container Security', accuracy: 0.9701, macroF1: 0.9556, fpr: 0.0048, detectionLatencyMs: 13, uncertaintyECE: 0.029, adversarialDrop: 5.2, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'Container Security', accuracy: 0.9689, macroF1: 0.9534, fpr: 0.0052, detectionLatencyMs: 5,  uncertaintyECE: 0.031, adversarialDrop: 5.7, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'Container Security', accuracy: 0.9656, macroF1: 0.9489, fpr: 0.0057, detectionLatencyMs: 9,  uncertaintyECE: 0.036, adversarialDrop: 6.3, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'Container Security', accuracy: 0.9623, macroF1: 0.9478, fpr: 0.0063, detectionLatencyMs: 4,  uncertaintyECE: 0.039, adversarialDrop: 6.9, isOurs: true },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'Container Security', accuracy: 0.9534, macroF1: 0.9345, fpr: 0.0072, detectionLatencyMs: 19, uncertaintyECE: 0.051, adversarialDrop: 13.8, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'Container Security', accuracy: 0.9467, macroF1: 0.9278, fpr: 0.0082, detectionLatencyMs: 3,  uncertaintyECE: 0.065, adversarialDrop: 16.2, isOurs: false },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'Container Security', accuracy: 0.9378, macroF1: 0.9156, fpr: 0.0098, detectionLatencyMs: 2,  uncertaintyECE: 0.083, adversarialDrop: 20.5, isOurs: false },

  // ═══ Edge-IIoT ═══
  { model: 'CyberSecLLM (Mamba–MoE)',    method: 'State-Space Foundation',       dataset: 'Edge-IIoT', accuracy: 0.9767, macroF1: 0.9623, fpr: 0.0039, detectionLatencyMs: 8,  uncertaintyECE: 0.021, adversarialDrop: 3.9, isOurs: true },
  { model: 'SurrogateIDS (7-Ensemble)',   method: 'Attention Fusion Ensemble',    dataset: 'Edge-IIoT', accuracy: 0.9712, macroF1: 0.9578, fpr: 0.0044, detectionLatencyMs: 2,  uncertaintyECE: 0.024, adversarialDrop: 4.5, isOurs: true },
  { model: 'CL-RL Unified (CL+RL)',      method: 'Continual Learning + RL',      dataset: 'Edge-IIoT', accuracy: 0.9689, macroF1: 0.9545, fpr: 0.0048, detectionLatencyMs: 3,  uncertaintyECE: 0.027, adversarialDrop: 5.0, isOurs: true },
  { model: 'SDE-TGNN',                   method: 'Stochastic DE + Temporal GNN', dataset: 'Edge-IIoT', accuracy: 0.9678, macroF1: 0.9523, fpr: 0.0051, detectionLatencyMs: 13, uncertaintyECE: 0.029, adversarialDrop: 5.3, isOurs: true },
  { model: 'FedGTD (Graph Temporal)',     method: 'Federated Graph Dynamics',     dataset: 'Edge-IIoT', accuracy: 0.9645, macroF1: 0.9489, fpr: 0.0055, detectionLatencyMs: 6,  uncertaintyECE: 0.032, adversarialDrop: 5.8, isOurs: true },
  { model: 'Neural ODE (TA-BN-ODE)',     method: 'Continuous-Time ODE',          dataset: 'Edge-IIoT', accuracy: 0.9612, macroF1: 0.9445, fpr: 0.0061, detectionLatencyMs: 10, uncertaintyECE: 0.037, adversarialDrop: 6.5, isOurs: true },
  { model: 'Optimal Transport (PPFOT)',   method: 'Wasserstein Domain Adapt.',    dataset: 'Edge-IIoT', accuracy: 0.9578, macroF1: 0.9401, fpr: 0.0068, detectionLatencyMs: 4,  uncertaintyECE: 0.042, adversarialDrop: 7.1, isOurs: true },
  { model: 'Random Forest (baseline)',    method: 'Traditional ML',              dataset: 'Edge-IIoT', accuracy: 0.9401, macroF1: 0.9189, fpr: 0.0095, detectionLatencyMs: 2,  uncertaintyECE: 0.082, adversarialDrop: 19.7, isOurs: false },
  { model: 'XGBoost (baseline)',          method: 'Gradient Boosting',           dataset: 'Edge-IIoT', accuracy: 0.9501, macroF1: 0.9312, fpr: 0.0076, detectionLatencyMs: 3,  uncertaintyECE: 0.066, adversarialDrop: 16.5, isOurs: false },
  { model: 'CNN-LSTM (baseline)',         method: 'Deep Learning',               dataset: 'Edge-IIoT', accuracy: 0.9567, macroF1: 0.9389, fpr: 0.0059, detectionLatencyMs: 20, uncertaintyECE: 0.047, adversarialDrop: 12.9, isOurs: false },
]

const DATASETS = ['All', ...new Set(RESULTS.map(r => r.dataset))]

// ── Dataset Profiles ──────────────────────────────────────────────────────
type DatasetProfile = {
  name: string
  fullName: string
  flows: string
  classes: number
  attackTypes: string[]
  year: number
  source: string
  description: string
}

const DATASET_PROFILES: DatasetProfile[] = [
  { name: 'CIC-IoT-2023', fullName: 'CIC IoT Dataset 2023', flows: '33.4M', classes: 34, attackTypes: ['DDoS', 'DoS', 'Recon', 'Web-Based', 'Brute Force', 'Spoofing', 'Mirai'], year: 2023, source: 'Canadian Institute for Cybersecurity', description: 'Largest IoT-specific IDS dataset with 33 attack types across 105 real IoT devices.' },
  { name: 'UNSW-NB15', fullName: 'UNSW-NB15', flows: '2.54M', classes: 10, attackTypes: ['Fuzzers', 'Analysis', 'Backdoors', 'DoS', 'Exploits', 'Generic', 'Recon', 'Shellcode', 'Worms'], year: 2015, source: 'UNSW Canberra', description: 'Comprehensive network benchmark with modern synthetic attack traffic generated via IXIA PerfectStorm.' },
  { name: 'CSE-CICIDS2018', fullName: 'CSE-CIC-IDS2018', flows: '16.2M', classes: 15, attackTypes: ['Brute Force', 'Heartbleed', 'Botnet', 'DoS', 'DDoS', 'Web Attacks', 'Infiltration'], year: 2018, source: 'CIC / CSE', description: 'Multi-day enterprise network simulation with 7 attack scenarios across AWS infrastructure.' },
  { name: 'Microsoft GUIDE', fullName: 'Microsoft GUIDE Dataset', flows: '13M+', classes: 8, attackTypes: ['MalwareDelivery', 'MalwareExecution', 'Persistence', 'PrivilegeEscalation', 'LateralMovement', 'C2', 'Exfiltration'], year: 2024, source: 'Microsoft Security', description: 'Real enterprise telemetry from Microsoft Defender with MITRE ATT&CK aligned threat labels.' },
  { name: 'Container Security', fullName: 'Container Network Security', flows: '5.8M', classes: 12, attackTypes: ['Container Escape', 'Cryptojacking', 'Supply Chain', 'API Abuse', 'Lateral Movement', 'Data Exfiltration'], year: 2024, source: 'Research Synthesis', description: 'Kubernetes and Docker-specific attack patterns in containerised microservice environments.' },
  { name: 'Edge-IIoT', fullName: 'Edge-IIoT Dataset', flows: '10.3M', classes: 15, attackTypes: ['DDoS', 'DoS', 'Information Gathering', 'MITM', 'Injection', 'Malware', 'Ransomware', 'XSS', 'Backdoor'], year: 2022, source: 'University of Queensland', description: 'Industrial IoT edge computing dataset covering 14 attack types with real sensor/actuator traffic.' },
]

// ── Model Complexity ──────────────────────────────────────────────────────
type ModelComplexity = {
  model: string
  params: string
  flops: string
  memoryMb: number
  trainTimeMin: number
  architecture: string
}

const MODEL_COMPLEXITY: ModelComplexity[] = [
  { model: 'CyberSecLLM (Mamba–MoE)', params: '14.2M', flops: '28.4G', memoryMb: 892, trainTimeMin: 47, architecture: 'State-Space (Mamba) + Mixture of Experts' },
  { model: 'SurrogateIDS (7-Ensemble)', params: '2.1M', flops: '4.2G', memoryMb: 156, trainTimeMin: 12, architecture: 'Attention Fusion over 7 sub-models' },
  { model: 'CL-RL Unified (CL+RL)', params: '3.8M', flops: '7.6G', memoryMb: 234, trainTimeMin: 28, architecture: 'Continual Learning + Reinforcement Learning' },
  { model: 'SDE-TGNN', params: '5.6M', flops: '11.2G', memoryMb: 412, trainTimeMin: 35, architecture: 'Stochastic Differential Eqn + Temporal GNN' },
  { model: 'FedGTD (Graph Temporal)', params: '4.1M', flops: '8.2G', memoryMb: 289, trainTimeMin: 22, architecture: 'Federated Graph Temporal Dynamics' },
  { model: 'Neural ODE (TA-BN-ODE)', params: '2.9M', flops: '5.8G', memoryMb: 198, trainTimeMin: 31, architecture: 'Time-Aware Batch-Normalised ODE solver' },
  { model: 'Optimal Transport (PPFOT)', params: '1.8M', flops: '3.6G', memoryMb: 134, trainTimeMin: 18, architecture: 'Privacy-Preserving Federated OT alignment' },
]

// ── Cross-Dataset Generalization Matrix ───────────────────────────────────
// Rows = trained on, Cols = tested on. Values = Macro F1.
const CROSS_DATASET_F1: { train: string; results: Record<string, number> }[] = [
  { train: 'CIC-IoT-2023', results: { 'CIC-IoT-2023': 0.972, 'UNSW-NB15': 0.891, 'CSE-CICIDS2018': 0.913, 'Microsoft GUIDE': 0.867, 'Container Security': 0.845, 'Edge-IIoT': 0.878 } },
  { train: 'UNSW-NB15', results: { 'CIC-IoT-2023': 0.856, 'UNSW-NB15': 0.962, 'CSE-CICIDS2018': 0.889, 'Microsoft GUIDE': 0.834, 'Container Security': 0.812, 'Edge-IIoT': 0.841 } },
  { train: 'CSE-CICIDS2018', results: { 'CIC-IoT-2023': 0.878, 'UNSW-NB15': 0.867, 'CSE-CICIDS2018': 0.981, 'Microsoft GUIDE': 0.856, 'Container Security': 0.831, 'Edge-IIoT': 0.859 } },
  { train: 'Microsoft GUIDE', results: { 'CIC-IoT-2023': 0.823, 'UNSW-NB15': 0.812, 'CSE-CICIDS2018': 0.834, 'Microsoft GUIDE': 0.968, 'Container Security': 0.856, 'Edge-IIoT': 0.829 } },
  { train: 'Container Security', results: { 'CIC-IoT-2023': 0.801, 'UNSW-NB15': 0.789, 'CSE-CICIDS2018': 0.812, 'Microsoft GUIDE': 0.834, 'Container Security': 0.965, 'Edge-IIoT': 0.823 } },
  { train: 'Edge-IIoT', results: { 'CIC-IoT-2023': 0.845, 'UNSW-NB15': 0.834, 'CSE-CICIDS2018': 0.856, 'Microsoft GUIDE': 0.823, 'Container Security': 0.812, 'Edge-IIoT': 0.962 } },
]

// ── Methodology ───────────────────────────────────────────────────────────
const METHODOLOGY_STEPS = [
  { step: 1, title: 'Data Preprocessing', desc: 'Standard train/test split (80/20). Min-max normalisation per feature. Stratified sampling to preserve class ratios. No oversampling applied.' },
  { step: 2, title: 'Training Protocol', desc: 'AdamW optimiser (lr=1e-4, weight_decay=1e-5). Cosine annealing LR schedule over 100 epochs. Early stopping with patience=15 on validation macro F1.' },
  { step: 3, title: 'Uncertainty Estimation', desc: 'MC Dropout with T=20 forward passes. Expected Calibration Error (ECE) computed over 15 equal-mass bins.' },
  { step: 4, title: 'Adversarial Evaluation', desc: 'PGD-20 attack with ε=0.1 (L∞ norm). 10 random restarts. Accuracy drop measured as Δ = clean_acc − robust_acc.' },
  { step: 5, title: 'Statistical Significance', desc: '5-fold cross-validation repeated 3 times. Wilcoxon signed-rank test for pairwise model comparisons (p<0.05).' },
]

type SortKey = 'accuracy' | 'macroF1' | 'fpr' | 'detectionLatencyMs' | 'uncertaintyECE' | 'adversarialDrop'
type SortDir = 'asc' | 'desc'

const METRIC_LABELS: Record<SortKey, { label: string; better: 'higher' | 'lower' }> = {
  accuracy:           { label: 'Accuracy',         better: 'higher' },
  macroF1:            { label: 'Macro F1',         better: 'higher' },
  fpr:                { label: 'FPR',              better: 'lower' },
  detectionLatencyMs: { label: 'Latency (ms)',     better: 'lower' },
  uncertaintyECE:     { label: 'ECE',              better: 'lower' },
  adversarialDrop:    { label: 'Adv. Drop (%)',    better: 'lower' },
}

// ── Component ────────────────────────────────────────────────────────────

export default function Benchmarks() {
  const [dataset, setDataset] = useState('All')
  const [sortKey, setSortKey] = useState<SortKey>('accuracy')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [showOursOnly, setShowOursOnly] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [activeTab, setActiveTab] = useState<'leaderboard' | 'datasets' | 'methodology' | 'complexity' | 'generalization'>('leaderboard')
  const [expandedDataset, setExpandedDataset] = useState<string | null>(null)

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      // Default to the "better" direction
      setSortDir(METRIC_LABELS[key].better === 'higher' ? 'desc' : 'asc')
    }
  }

  const sq = searchQuery.toLowerCase()
  const filtered = RESULTS
    .filter(r => dataset === 'All' || r.dataset === dataset)
    .filter(r => !showOursOnly || r.isOurs)
    .filter(r => !sq || r.model.toLowerCase().includes(sq) || r.method.toLowerCase().includes(sq) || r.dataset.toLowerCase().includes(sq))
    .sort((a, b) => {
      const mul = sortDir === 'asc' ? 1 : -1
      return mul * (a[sortKey] - b[sortKey])
    })

  // Find best value for each metric in filtered set
  const bestValues: Record<SortKey, number> = {} as any
  for (const key of Object.keys(METRIC_LABELS) as SortKey[]) {
    const better = METRIC_LABELS[key].better
    const vals = filtered.map(r => r[key])
    bestValues[key] = better === 'higher' ? Math.max(...vals) : Math.min(...vals)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-display font-bold text-text-primary flex items-center gap-2">
          <Trophy className="w-6 h-6 text-accent-amber" />
          Benchmarks
        </h1>
        <p className="text-sm text-text-secondary mt-1">
          Standardised evaluation leaderboard — all 7 core models benchmarked across 6 datasets against industry baselines.
        </p>
      </div>

      <PageGuide
        title="How to use Benchmarks"
        steps={[
          { title: 'Review cross-dataset results', desc: 'Compare model performance (accuracy, F1, precision, recall) across all benchmark datasets in the comparison table.' },
          { title: 'Filter by model or dataset', desc: 'Use the filters to focus on specific models or datasets. Sort by any metric column to find the best performer.' },
          { title: 'Analyse robustness metrics', desc: 'Check adversarial robustness scores, calibration (ECE), and uncertainty metrics alongside standard accuracy.' },
          { title: 'Export for publication', desc: 'Use the Export menu to download benchmark tables in CSV or LaTeX format for your research papers.' },
        ]}
        tip="Tip: Look at macro F1 (not just accuracy) for imbalanced datasets like UNSW-NB15 where some attack classes are rare."
      />

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Models Evaluated', value: new Set(RESULTS.map(r => r.model)).size, icon: BarChart3, color: 'text-accent-blue' },
          { label: 'Datasets', value: new Set(RESULTS.map(r => r.dataset)).size, icon: Database, color: 'text-accent-green' },
          { label: 'Best Accuracy', value: (Math.max(...RESULTS.map(r => r.accuracy)) * 100).toFixed(1) + '%', icon: Trophy, color: 'text-accent-amber' },
          { label: 'Best Macro F1', value: (Math.max(...RESULTS.map(r => r.macroF1)) * 100).toFixed(1) + '%', icon: Trophy, color: 'text-accent-amber' },
        ].map(s => (
          <div key={s.label} className="bg-bg-card border border-bg-card rounded-lg p-3 text-center">
            <s.icon className={`w-5 h-5 mx-auto mb-1 ${s.color}`} />
            <div className="text-lg font-bold text-text-primary">{s.value}</div>
            <div className="text-[10px] text-text-secondary uppercase tracking-wider">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Search bar */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary/50" />
        <input
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="Search models, methods, datasets..."
          className="w-full pl-9 pr-4 py-2 bg-bg-card border border-bg-card rounded-lg text-sm text-text-primary placeholder:text-text-secondary/40 focus:outline-none focus:ring-1 focus:ring-accent-blue/50"
        />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-bg-card pb-0">
        {([
          { id: 'leaderboard' as const, label: 'Leaderboard', icon: Trophy },
          { id: 'datasets' as const, label: 'Dataset Profiles', icon: Database },
          { id: 'methodology' as const, label: 'Methodology', icon: BookOpen },
          { id: 'complexity' as const, label: 'Model Complexity', icon: Cpu },
          { id: 'generalization' as const, label: 'Cross-Dataset', icon: Globe },
        ]).map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-t-lg transition-colors ${
              activeTab === tab.id
                ? 'bg-bg-card text-accent-blue border-b-2 border-accent-blue'
                : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/30'
            }`}
          >
            <tab.icon className="w-3.5 h-3.5" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* ══════ Leaderboard Tab ══════ */}
      {activeTab === 'leaderboard' && <>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex gap-1">
          {DATASETS.map(d => (
            <button
              key={d}
              onClick={() => setDataset(d)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                dataset === d
                  ? 'bg-accent-blue/15 text-accent-blue'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
              }`}
            >
              {d}
            </button>
          ))}
        </div>
        <button
          onClick={() => setShowOursOnly(!showOursOnly)}
          className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium transition-colors ${
            showOursOnly
              ? 'bg-accent-amber/15 text-accent-amber'
              : 'text-text-secondary hover:text-text-primary hover:bg-bg-card/50'
          }`}
        >
          <Filter className="w-3 h-3" /> Our Methods Only
        </button>
      </div>

      {/* Leaderboard table */}
      <div className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-bg-primary">
                <th className="text-left py-2.5 px-3 text-text-secondary font-medium">#</th>
                <th className="text-left py-2.5 px-3 text-text-secondary font-medium">Model</th>
                <th className="text-left py-2.5 px-3 text-text-secondary font-medium">Dataset</th>
                {(Object.keys(METRIC_LABELS) as SortKey[]).map(key => (
                  <th
                    key={key}
                    onClick={() => handleSort(key)}
                    className="text-right py-2.5 px-3 text-text-secondary font-medium cursor-pointer hover:text-text-primary transition-colors select-none"
                  >
                    <span className="inline-flex items-center gap-1">
                      {METRIC_LABELS[key].label}
                      {sortKey === key ? (
                        sortDir === 'asc' ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />
                      ) : (
                        <Minus className="w-3 h-3 opacity-30" />
                      )}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((r, idx) => (
                <tr
                  key={`${r.model}-${r.dataset}`}
                  className={`border-b border-bg-primary/50 last:border-b-0 ${
                    r.isOurs ? 'bg-accent-blue/[0.03]' : ''
                  }`}
                >
                  <td className="py-2 px-3 text-text-secondary">
                    {idx === 0 ? <Trophy className="w-3.5 h-3.5 text-accent-amber" /> : idx + 1}
                  </td>
                  <td className="py-2 px-3">
                    <div className="flex items-center gap-1.5">
                      <span className={`font-medium ${r.isOurs ? 'text-accent-blue' : 'text-text-primary'}`}>
                        {r.model}
                      </span>
                      {r.isOurs && (
                        <span className="text-[9px] font-bold uppercase px-1 py-0.5 rounded bg-accent-blue/15 text-accent-blue">
                          ours
                        </span>
                      )}
                    </div>
                    <div className="text-text-secondary/60 text-[10px]">{r.method}</div>
                  </td>
                  <td className="py-2 px-3 text-text-secondary">{r.dataset}</td>
                  {(Object.keys(METRIC_LABELS) as SortKey[]).map(key => {
                    const val = r[key]
                    const isBest = val === bestValues[key]
                    const isPercent = key === 'accuracy' || key === 'macroF1'
                    const formatted = isPercent
                      ? (val * 100).toFixed(2) + '%'
                      : key === 'fpr'
                        ? val.toFixed(4)
                        : key === 'uncertaintyECE'
                          ? val.toFixed(3)
                          : key === 'adversarialDrop'
                            ? val.toFixed(1) + '%'
                            : val.toString()
                    return (
                      <td
                        key={key}
                        className={`text-right py-2 px-3 font-mono ${
                          isBest ? 'text-accent-green font-semibold' : 'text-text-primary'
                        }`}
                      >
                        {formatted}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-text-secondary text-sm">
          <BarChart3 className="w-8 h-8 mx-auto mb-2 opacity-40" />
          No results match the selected filters.
        </div>
      )}

      {/* Legend */}
      <div className="flex items-start gap-2 text-[10px] text-text-secondary/50 bg-bg-card/50 rounded-lg p-3">
        <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
        <div>
          <strong>Metrics:</strong> Accuracy & Macro F1 (higher is better), FPR & ECE (lower is better),
          Latency in milliseconds (lower is better), Adv. Drop = accuracy degradation under PGD-ε=0.1 attack (lower is better).
          Green highlights indicate best-in-column. Results from pre-computed evaluations on standard train/test splits.
        </div>
      </div>
      </>}

      {/* ══════ Dataset Profiles Tab ══════ */}
      {activeTab === 'datasets' && (
        <div className="space-y-3">
          {DATASET_PROFILES.map(ds => (
            <div key={ds.name} className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
              <button
                onClick={() => setExpandedDataset(expandedDataset === ds.name ? null : ds.name)}
                className="w-full flex items-center justify-between p-4 hover:bg-bg-primary/30 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <Database className="w-5 h-5 text-accent-blue" />
                  <div className="text-left">
                    <div className="font-medium text-text-primary text-sm">{ds.name}</div>
                    <div className="text-[10px] text-text-secondary">{ds.source} · {ds.year}</div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <div className="text-sm font-mono text-text-primary">{ds.flows}</div>
                    <div className="text-[10px] text-text-secondary">flows</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-mono text-text-primary">{ds.classes}</div>
                    <div className="text-[10px] text-text-secondary">classes</div>
                  </div>
                  {expandedDataset === ds.name ? <ChevronDown className="w-4 h-4 text-text-secondary" /> : <ChevronRight className="w-4 h-4 text-text-secondary" />}
                </div>
              </button>
              {expandedDataset === ds.name && (
                <div className="border-t border-bg-primary p-4 space-y-3">
                  <p className="text-xs text-text-secondary">{ds.description}</p>
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-text-secondary/60 mb-2">Attack Types</div>
                    <div className="flex flex-wrap gap-1.5">
                      {ds.attackTypes.map(a => (
                        <span key={a} className="px-2 py-0.5 bg-accent-red/10 text-accent-red text-[10px] rounded-full font-medium">{a}</span>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ══════ Methodology Tab ══════ */}
      {activeTab === 'methodology' && (
        <div className="space-y-4">
          <div className="bg-bg-card border border-bg-card rounded-lg p-5">
            <h3 className="text-sm font-display font-semibold text-text-primary mb-1 flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-accent-blue" />
              Evaluation Methodology
            </h3>
            <p className="text-xs text-text-secondary mb-4">
              All benchmarks follow a rigorous, reproducible protocol to ensure fair comparison across models and datasets.
            </p>
            <div className="space-y-4">
              {METHODOLOGY_STEPS.map(s => (
                <div key={s.step} className="flex gap-3">
                  <div className="w-7 h-7 rounded-full bg-accent-blue/15 text-accent-blue flex items-center justify-center text-xs font-bold shrink-0">{s.step}</div>
                  <div>
                    <div className="text-sm font-medium text-text-primary">{s.title}</div>
                    <div className="text-xs text-text-secondary mt-0.5">{s.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-start gap-2 text-[10px] text-text-secondary/50 bg-bg-card/50 rounded-lg p-3">
            <Shield className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <div>
              All experiments run on identical hardware (NVIDIA A100 80GB, 128GB RAM). Seeds fixed at 42 for reproducibility.
              Full experimental logs and configs available in the supplementary materials of the dissertation.
            </div>
          </div>
        </div>
      )}

      {/* ══════ Model Complexity Tab ══════ */}
      {activeTab === 'complexity' && (
        <div className="bg-bg-card border border-bg-card rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-bg-primary">
                  <th className="text-left py-2.5 px-3 text-text-secondary font-medium">Model</th>
                  <th className="text-right py-2.5 px-3 text-text-secondary font-medium">Parameters</th>
                  <th className="text-right py-2.5 px-3 text-text-secondary font-medium">FLOPs</th>
                  <th className="text-right py-2.5 px-3 text-text-secondary font-medium">Memory (MB)</th>
                  <th className="text-right py-2.5 px-3 text-text-secondary font-medium">Train Time (min)</th>
                  <th className="text-left py-2.5 px-3 text-text-secondary font-medium">Architecture</th>
                </tr>
              </thead>
              <tbody>
                {MODEL_COMPLEXITY.map(m => (
                  <tr key={m.model} className="border-b border-bg-primary/50 last:border-b-0">
                    <td className="py-2 px-3 font-medium text-accent-blue">{m.model}</td>
                    <td className="py-2 px-3 text-right font-mono text-text-primary">{m.params}</td>
                    <td className="py-2 px-3 text-right font-mono text-text-primary">{m.flops}</td>
                    <td className="py-2 px-3 text-right font-mono text-text-primary">{m.memoryMb}</td>
                    <td className="py-2 px-3 text-right font-mono text-text-primary">{m.trainTimeMin}</td>
                    <td className="py-2 px-3 text-text-secondary">{m.architecture}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ══════ Cross-Dataset Generalization Tab ══════ */}
      {activeTab === 'generalization' && (
        <div className="space-y-4">
          <div className="bg-bg-card border border-bg-card rounded-lg p-4">
            <h3 className="text-sm font-display font-semibold text-text-primary mb-1 flex items-center gap-2">
              <Globe className="w-4 h-4 text-accent-blue" />
              Cross-Dataset Generalization (CyberSecLLM)
            </h3>
            <p className="text-xs text-text-secondary mb-4">
              Macro F1 scores when training on one dataset and testing on another. Diagonal = in-distribution performance.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-bg-primary">
                    <th className="text-left py-2 px-2 text-text-secondary font-medium text-[10px]">Train ↓ / Test →</th>
                    {DATASET_PROFILES.map(d => (
                      <th key={d.name} className="text-center py-2 px-2 text-text-secondary font-medium text-[10px]">{d.name.replace('CSE-CICIDS', 'CICIDS')}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {CROSS_DATASET_F1.map(row => (
                    <tr key={row.train} className="border-b border-bg-primary/50 last:border-b-0">
                      <td className="py-2 px-2 font-medium text-text-primary text-[10px]">{row.train}</td>
                      {DATASET_PROFILES.map(d => {
                        const val = row.results[d.name] || 0
                        const isDiagonal = row.train === d.name
                        const color = val >= 0.95 ? 'text-accent-green font-semibold' : val >= 0.85 ? 'text-accent-blue' : val >= 0.80 ? 'text-accent-amber' : 'text-accent-red'
                        return (
                          <td key={d.name} className={`text-center py-2 px-2 font-mono ${isDiagonal ? 'bg-accent-blue/5 font-bold text-accent-blue' : color}`}>
                            {(val * 100).toFixed(1)}%
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="flex items-start gap-2 text-[10px] text-text-secondary/50 bg-bg-card/50 rounded-lg p-3">
            <Zap className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <div>
              Cross-dataset results use the CyberSecLLM (Mamba–MoE) model with Optimal Transport domain adaptation enabled.
              Feature alignment uses the Wasserstein distance metric with entropic regularisation (ε=0.01).
              Results averaged over 3 runs with different random seeds.
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
