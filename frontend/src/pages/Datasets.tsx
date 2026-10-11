import { useState } from 'react'
import {
  Database, Cloud, Wifi, Server, Box, Cpu,
  ExternalLink, ChevronDown, ChevronUp, Shield,
  FileText, Layers, Tag, BarChart3,
} from 'lucide-react'
import PageGuide from '../components/PageGuide'

/* ═══════════════════════ Dataset Registry ══════════════════════════════════ */

interface AttackClass {
  name: string
  category: 'ddos' | 'recon' | 'bruteforce' | 'spoofing' | 'web' | 'malware' | 'dos' | 'injection' | 'botnet' | 'exploit' | 'anomaly' | 'other'
}

interface FeatureGroup {
  name: string
  count: number
  examples: string[]
}

interface PreprocessingStep {
  step: number
  name: string
  description: string
}

interface Dataset {
  id: string
  name: string
  records: string
  recordsRaw: number
  attackTypes: number
  features: number
  domain: string
  domainIcon: typeof Cloud
  domainColor: string
  year: number
  source: string
  collection: 'cloud' | 'network'
  description: string
  attackClasses: AttackClass[]
  featureGroups: FeatureGroup[]
  preprocessing: PreprocessingStep[]
  labelColumn: string
  labelType: string
  compatibleModels: string[]
  sampleSize: string
  fileFormat: string
  notes: string
}

const DATASETS: Dataset[] = [
  {
    id: 'cic-iot-2023',
    name: 'CIC-IoT-2023',
    records: '46.6M',
    recordsRaw: 46_600_000,
    attackTypes: 33,
    features: 46,
    domain: 'IoT Networks',
    domainIcon: Wifi,
    domainColor: '#3B82F6',
    year: 2023,
    source: 'Canadian Institute for Cybersecurity',
    collection: 'network',
    description: 'Large-scale IoT network traffic dataset with 33 attack types covering DDoS, reconnaissance, brute-force, spoofing, web attacks, and malware across heterogeneous IoT device topologies.',
    attackClasses: [
      { name: 'DDoS-TCP_Flood', category: 'ddos' }, { name: 'DDoS-UDP_Flood', category: 'ddos' },
      { name: 'DDoS-ICMP_Flood', category: 'ddos' }, { name: 'DDoS-SYN_Flood', category: 'ddos' },
      { name: 'DDoS-PSHACK_Flood', category: 'ddos' }, { name: 'DDoS-HTTP_Flood', category: 'ddos' },
      { name: 'DDoS-SlowLoris', category: 'ddos' }, { name: 'DDoS-SlowHTTPTest', category: 'ddos' },
      { name: 'Recon-PortScan', category: 'recon' }, { name: 'Recon-OSScan', category: 'recon' },
      { name: 'Recon-PingSweep', category: 'recon' }, { name: 'Recon-HostDiscovery', category: 'recon' },
      { name: 'BruteForce-SSH', category: 'bruteforce' }, { name: 'BruteForce-FTP', category: 'bruteforce' },
      { name: 'BruteForce-Web', category: 'bruteforce' }, { name: 'BruteForce-Telnet', category: 'bruteforce' },
      { name: 'Spoofing-ARP', category: 'spoofing' }, { name: 'Spoofing-DNS', category: 'spoofing' },
      { name: 'Spoofing-DHCP', category: 'spoofing' },
      { name: 'WebAttack-SQLi', category: 'web' }, { name: 'WebAttack-XSS', category: 'web' },
      { name: 'WebAttack-CSRF', category: 'web' }, { name: 'WebAttack-CmdInjection', category: 'web' },
      { name: 'Malware-Backdoor', category: 'malware' }, { name: 'Malware-Ransomware', category: 'malware' },
      { name: 'Malware-Trojan', category: 'malware' },
      { name: 'DoS-Hulk', category: 'dos' }, { name: 'DoS-GoldenEye', category: 'dos' },
      { name: 'DoS-Slowloris', category: 'dos' },
      { name: 'Mirai-greeth_flood', category: 'botnet' }, { name: 'Mirai-greip_flood', category: 'botnet' },
      { name: 'Mirai-udpplain', category: 'botnet' }, { name: 'Mirai-ackflooding', category: 'botnet' },
    ],
    featureGroups: [
      { name: 'Flow Statistics', count: 12, examples: ['flow_duration', 'flow_bytes_sec', 'flow_pkts_sec', 'fwd_pkts_tot', 'bwd_pkts_tot'] },
      { name: 'Packet Length', count: 8, examples: ['pkt_len_min', 'pkt_len_max', 'pkt_len_mean', 'pkt_len_std'] },
      { name: 'Flag Counts', count: 8, examples: ['fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt'] },
      { name: 'Timing Features', count: 6, examples: ['flow_iat_mean', 'flow_iat_std', 'fwd_iat_tot', 'bwd_iat_mean'] },
      { name: 'Header Info', count: 6, examples: ['src_port', 'dst_port', 'protocol', 'header_len_fwd', 'header_len_bwd'] },
      { name: 'Sub-flow & Bulk', count: 6, examples: ['subflow_fwd_pkts', 'subflow_bwd_bytes', 'bulk_rate_fwd', 'bulk_rate_bwd'] },
    ],
    preprocessing: [
      { step: 1, name: 'Drop Identifiers', description: 'Remove flow_id, src_ip, dst_ip, timestamp columns' },
      { step: 2, name: 'Handle Inf/NaN', description: 'Replace inf with NaN, then drop or impute NaN rows (< 0.1%)' },
      { step: 3, name: 'Encode Labels', description: 'LabelEncoder on multi-class "label" column (34 classes inc. Benign)' },
      { step: 4, name: 'StandardScaler', description: 'Z-score normalisation on all 46 numerical features' },
      { step: 5, name: 'Feature Alignment', description: 'Pad or truncate to model input dimension (46 → model dim)' },
    ],
    labelColumn: 'label',
    labelType: 'Multi-class (34 including Benign)',
    compatibleModels: ['SurrogateIDS', 'Neural ODE', 'Optimal Transport', 'FedGTD', 'SDE-TGNN', 'CyberSecLLM'],
    sampleSize: '~10K rows per class (balanced sample)',
    fileFormat: 'CSV (multiple files, one per attack scenario)',
    notes: 'Primary evaluation dataset. Largest IoT-specific collection. Models are natively trained on this.',
  },
  {
    id: 'cse-cicids2018',
    name: 'CSE-CICIDS2018',
    records: '16.2M',
    recordsRaw: 16_200_000,
    attackTypes: 7,
    features: 79,
    domain: 'Enterprise',
    domainIcon: Server,
    domainColor: '#A855F7',
    year: 2018,
    source: 'Canadian Institute for Cybersecurity',
    collection: 'network',
    description: 'Enterprise network traffic generated in a controlled environment with 7 major attack categories. Uses CICFlowMeter-generated features. Standard benchmark for enterprise IDS evaluation.',
    attackClasses: [
      { name: 'Brute Force', category: 'bruteforce' },
      { name: 'DoS/DDoS', category: 'ddos' },
      { name: 'Web Attacks', category: 'web' },
      { name: 'Infiltration', category: 'exploit' },
      { name: 'Bot', category: 'botnet' },
      { name: 'PortScan', category: 'recon' },
      { name: 'Heartbleed', category: 'exploit' },
    ],
    featureGroups: [
      { name: 'Flow Statistics', count: 18, examples: ['Flow Duration', 'Total Fwd Packets', 'Total Bwd Packets', 'Flow Bytes/s'] },
      { name: 'Packet Length', count: 14, examples: ['Fwd Packet Length Max', 'Bwd Packet Length Mean', 'Packet Length Std'] },
      { name: 'Flag Features', count: 11, examples: ['FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count'] },
      { name: 'IAT Features', count: 12, examples: ['Flow IAT Mean', 'Fwd IAT Total', 'Bwd IAT Mean', 'Flow IAT Std'] },
      { name: 'Header & Segment', count: 10, examples: ['Fwd Header Length', 'Bwd Header Length', 'Min Seg Size Forward'] },
      { name: 'Sub-flow & Active', count: 14, examples: ['Subflow Fwd Packets', 'Active Mean', 'Idle Mean', 'Init Fwd Win Bytes'] },
    ],
    preprocessing: [
      { step: 1, name: 'Drop Identifiers', description: 'Remove Flow ID, Source IP, Destination IP, Timestamp' },
      { step: 2, name: 'Handle Inf/NaN', description: 'Replace inf with NaN, drop rows with NaN (~0.3% of data)' },
      { step: 3, name: 'Encode Labels', description: 'LabelEncoder on "Label" column (8 classes inc. Benign)' },
      { step: 4, name: 'StandardScaler', description: 'Z-score normalisation on all 79 numerical features' },
      { step: 5, name: 'Feature Alignment', description: 'Select top-46 by mutual information, or zero-pad to match model dim' },
    ],
    labelColumn: 'Label',
    labelType: 'Multi-class (8 including Benign)',
    compatibleModels: ['SurrogateIDS', 'Neural ODE', 'Optimal Transport', 'FedGTD', 'SDE-TGNN', 'CyberSecLLM'],
    sampleSize: '~5K rows per class (stratified)',
    fileFormat: 'CSV (day-based splits)',
    notes: 'Classic enterprise benchmark. 79 CICFlowMeter features — requires feature selection or padding for 46-dim models.',
  },
  {
    id: 'unsw-nb15',
    name: 'UNSW-NB15',
    records: '2.5M',
    recordsRaw: 2_500_000,
    attackTypes: 9,
    features: 49,
    domain: 'Hybrid',
    domainIcon: Layers,
    domainColor: '#22C55E',
    year: 2015,
    source: 'UNSW Canberra Cyber',
    collection: 'network',
    description: 'Hybrid real + synthetic network traffic dataset with 9 contemporary attack families. Generated using IXIA PerfectStorm tool. Covers both traditional and modern attack vectors.',
    attackClasses: [
      { name: 'Fuzzers', category: 'exploit' },
      { name: 'Analysis', category: 'recon' },
      { name: 'Backdoors', category: 'malware' },
      { name: 'DoS', category: 'dos' },
      { name: 'Exploits', category: 'exploit' },
      { name: 'Generic', category: 'other' },
      { name: 'Reconnaissance', category: 'recon' },
      { name: 'Shellcode', category: 'injection' },
      { name: 'Worms', category: 'malware' },
    ],
    featureGroups: [
      { name: 'Flow/Connection', count: 12, examples: ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate'] },
      { name: 'Content Features', count: 10, examples: ['sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss'] },
      { name: 'Time Features', count: 8, examples: ['sinpkt', 'dinpkt', 'sjit', 'djit', 'tcprtt', 'synack'] },
      { name: 'General Purpose', count: 10, examples: ['ct_state_ttl', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm'] },
      { name: 'Protocol/Service', count: 9, examples: ['proto', 'service', 'state', 'is_sm_ips_ports', 'is_ftp_login'] },
    ],
    preprocessing: [
      { step: 1, name: 'Drop Identifiers', description: 'Remove srcip, dstip, sport, dsport, id columns' },
      { step: 2, name: 'Encode Categoricals', description: 'One-hot encode proto, service, state columns' },
      { step: 3, name: 'Handle Inf/NaN', description: 'Impute missing values with median, clip outliers at 99th percentile' },
      { step: 4, name: 'StandardScaler', description: 'Z-score normalisation on all numerical features' },
      { step: 5, name: 'Feature Alignment', description: 'Map 49 features to model input dimension via selection or padding' },
    ],
    labelColumn: 'attack_cat / label',
    labelType: 'Multi-class (10 including Normal) + binary label',
    compatibleModels: ['SurrogateIDS', 'Neural ODE', 'Optimal Transport', 'FedGTD', 'SDE-TGNN', 'CyberSecLLM'],
    sampleSize: '~2K rows per class',
    fileFormat: 'CSV (UNSW-NB15_1.csv through _4.csv)',
    notes: 'Good balance of attack diversity. Smaller size enables fast iteration. Both binary and multi-class labels available.',
  },
  {
    id: 'microsoft-guide',
    name: 'Microsoft GUIDE',
    records: '13.7M',
    recordsRaw: 13_700_000,
    attackTypes: 15,
    features: 51,
    domain: 'Cloud/Enterprise',
    domainIcon: Cloud,
    domainColor: '#F59E0B',
    year: 2023,
    source: 'Microsoft Security Research',
    collection: 'cloud',
    description: 'Cloud and enterprise security telemetry dataset with 15 attack categories from Microsoft Defender. Features include process-level, network, and registry events in cloud-native environments.',
    attackClasses: [
      { name: 'Ransomware', category: 'malware' }, { name: 'Trojan', category: 'malware' },
      { name: 'Cryptominer', category: 'malware' }, { name: 'PUA (Potentially Unwanted)', category: 'other' },
      { name: 'Backdoor', category: 'malware' }, { name: 'Worm', category: 'malware' },
      { name: 'Dropper', category: 'malware' }, { name: 'Downloader', category: 'malware' },
      { name: 'Exploit Kit', category: 'exploit' }, { name: 'Phishing Payload', category: 'web' },
      { name: 'Credential Theft', category: 'bruteforce' }, { name: 'Lateral Movement', category: 'recon' },
      { name: 'Data Exfiltration', category: 'other' }, { name: 'C2 Communication', category: 'botnet' },
      { name: 'Fileless Attack', category: 'exploit' },
    ],
    featureGroups: [
      { name: 'Process Features', count: 12, examples: ['process_name_hash', 'parent_process_hash', 'cmd_line_length', 'elevation_type'] },
      { name: 'Network Indicators', count: 10, examples: ['connection_count', 'unique_dst_ips', 'port_entropy', 'dns_query_count'] },
      { name: 'File System', count: 9, examples: ['file_write_count', 'file_rename_count', 'temp_file_ratio', 'exe_drop_count'] },
      { name: 'Registry Events', count: 8, examples: ['reg_persistence_keys', 'reg_write_count', 'autorun_modified'] },
      { name: 'Temporal Features', count: 7, examples: ['hour_of_day', 'time_since_boot', 'event_frequency', 'burst_score'] },
      { name: 'Cloud Metadata', count: 5, examples: ['resource_group_hash', 'subscription_id_hash', 'region', 'vm_size'] },
    ],
    preprocessing: [
      { step: 1, name: 'Hash Identifiers', description: 'Machine GUIDs and user SIDs already hashed by Microsoft' },
      { step: 2, name: 'Encode Categoricals', description: 'Label-encode or hash categorical columns (region, vm_size, etc.)' },
      { step: 3, name: 'Handle Missing', description: 'Forward-fill temporal features, zero-fill count features' },
      { step: 4, name: 'StandardScaler', description: 'Z-score normalisation on all 51 numerical features' },
      { step: 5, name: 'Feature Alignment', description: 'Map 51 features to model input dimension' },
    ],
    labelColumn: 'IncidentGrade / threat_type',
    labelType: 'Multi-class (16 including Benign)',
    compatibleModels: ['SurrogateIDS', 'Neural ODE', 'Optimal Transport', 'FedGTD', 'SDE-TGNN', 'CyberSecLLM'],
    sampleSize: '~3K rows per class',
    fileFormat: 'CSV / Parquet',
    notes: 'Cloud-native telemetry — tests model generalisation beyond network flow data. Process + registry features require different preprocessing.',
  },
  {
    id: 'container-security',
    name: 'Container Security',
    records: '3.2M',
    recordsRaw: 3_200_000,
    attackTypes: 8,
    features: 93,
    domain: 'Microservices',
    domainIcon: Box,
    domainColor: '#EF4444',
    year: 2023,
    source: 'Container Security Research',
    collection: 'cloud',
    description: 'Microservices and container orchestration security dataset capturing Kubernetes cluster attacks, container escapes, supply chain compromises, and lateral movement in containerised environments.',
    attackClasses: [
      { name: 'Container Escape', category: 'exploit' },
      { name: 'Cryptojacking', category: 'malware' },
      { name: 'Supply Chain Attack', category: 'injection' },
      { name: 'Privilege Escalation', category: 'exploit' },
      { name: 'Pod-to-Pod Lateral', category: 'recon' },
      { name: 'Image Tampering', category: 'injection' },
      { name: 'Resource Abuse', category: 'anomaly' },
      { name: 'API Server Exploit', category: 'web' },
    ],
    featureGroups: [
      { name: 'Container Metrics', count: 18, examples: ['cpu_usage_pct', 'mem_usage_bytes', 'net_rx_bytes', 'net_tx_bytes', 'blk_read_ops'] },
      { name: 'System Calls', count: 20, examples: ['syscall_count', 'unique_syscalls', 'execve_count', 'mount_count', 'ptrace_count'] },
      { name: 'Network Activity', count: 15, examples: ['connections_in', 'connections_out', 'dns_queries', 'unique_dst_pods', 'egress_bytes'] },
      { name: 'K8s API Events', count: 14, examples: ['api_requests', 'rbac_violations', 'secret_access_count', 'configmap_changes'] },
      { name: 'Image/Registry', count: 10, examples: ['image_pull_count', 'layer_count', 'vuln_cve_count', 'image_age_days'] },
      { name: 'Process Tree', count: 16, examples: ['process_count', 'child_processes', 'shell_spawns', 'script_executions', 'network_binaries'] },
    ],
    preprocessing: [
      { step: 1, name: 'Drop Identifiers', description: 'Remove pod_id, container_id, node_name, namespace (use hash if needed)' },
      { step: 2, name: 'Aggregate Syscalls', description: 'Aggregate raw syscall traces into frequency vectors per time window' },
      { step: 3, name: 'Handle Missing', description: 'K8s API features may be sparse — zero-fill for non-applicable containers' },
      { step: 4, name: 'RobustScaler', description: 'RobustScaler preferred (heavy outliers from resource abuse attacks)' },
      { step: 5, name: 'Feature Alignment', description: 'PCA or feature selection from 93 to model input dimension' },
    ],
    labelColumn: 'attack_label',
    labelType: 'Multi-class (9 including Normal)',
    compatibleModels: ['SurrogateIDS', 'Neural ODE', 'Optimal Transport', 'FedGTD', 'SDE-TGNN', 'CyberSecLLM'],
    sampleSize: '~2K rows per class',
    fileFormat: 'CSV / JSON Lines',
    notes: 'Highest feature dimensionality (93). Requires PCA or feature selection. Tests model capacity with high-dimensional input.',
  },
  {
    id: 'edge-iiot',
    name: 'Edge-IIoT',
    records: '2.0M',
    recordsRaw: 2_000_000,
    attackTypes: 12,
    features: 69,
    domain: 'Edge/Industrial',
    domainIcon: Cpu,
    domainColor: '#06B6D4',
    year: 2022,
    source: 'Edge-IIoT Research',
    collection: 'cloud',
    description: 'Edge computing and Industrial IoT security dataset covering SCADA/ICS attacks, sensor manipulation, and edge-device compromises in industrial control system environments.',
    attackClasses: [
      { name: 'MITM Attack', category: 'spoofing' },
      { name: 'Modbus Injection', category: 'injection' },
      { name: 'Sensor Spoofing', category: 'spoofing' },
      { name: 'DoS (PLC Flood)', category: 'dos' },
      { name: 'Reconnaissance (SCADA)', category: 'recon' },
      { name: 'Firmware Tampering', category: 'injection' },
      { name: 'Command Injection', category: 'injection' },
      { name: 'Data Exfiltration', category: 'other' },
      { name: 'Replay Attack', category: 'spoofing' },
      { name: 'Protocol Abuse', category: 'anomaly' },
      { name: 'Ransomware (OT)', category: 'malware' },
      { name: 'Supply Chain', category: 'injection' },
    ],
    featureGroups: [
      { name: 'Network Flow', count: 14, examples: ['flow_duration', 'total_fwd_pkts', 'total_bwd_pkts', 'flow_bytes_sec'] },
      { name: 'Modbus/ICS Protocol', count: 12, examples: ['modbus_func_code', 'register_address', 'coil_write_count', 'read_holding_regs'] },
      { name: 'Sensor Readings', count: 10, examples: ['temperature', 'pressure', 'flow_rate', 'voltage', 'current'] },
      { name: 'Edge Device Metrics', count: 12, examples: ['cpu_usage', 'memory_usage', 'disk_io', 'uptime', 'process_count'] },
      { name: 'Timing Features', count: 10, examples: ['inter_arrival_time', 'polling_interval', 'response_time', 'cycle_deviation'] },
      { name: 'Protocol Metadata', count: 11, examples: ['protocol_type', 'src_port', 'dst_port', 'payload_entropy', 'header_anomaly_score'] },
    ],
    preprocessing: [
      { step: 1, name: 'Drop Identifiers', description: 'Remove device_id, plc_address, timestamp columns' },
      { step: 2, name: 'Encode Protocols', description: 'One-hot encode Modbus function codes and protocol types' },
      { step: 3, name: 'Normalise Sensors', description: 'Min-max scale sensor readings (physical unit ranges differ widely)' },
      { step: 4, name: 'StandardScaler', description: 'Z-score normalisation on network and device metric features' },
      { step: 5, name: 'Feature Alignment', description: 'Feature selection from 69 to model input dimension' },
    ],
    labelColumn: 'Attack_type',
    labelType: 'Multi-class (13 including Normal)',
    compatibleModels: ['SurrogateIDS', 'Neural ODE', 'Optimal Transport', 'FedGTD', 'SDE-TGNN', 'CyberSecLLM'],
    sampleSize: '~1.5K rows per class',
    fileFormat: 'CSV',
    notes: 'ICS/SCADA-specific — evaluates model performance on industrial protocol attacks. Sensor features add physical-domain context.',
  },
]

const COLLECTION_INFO = {
  network: {
    label: 'General Network Traffic',
    doi: 'https://doi.org/10.34740/kaggle/dsv/12483891',
    datasets: ['cic-iot-2023', 'cse-cicids2018', 'unsw-nb15'],
    color: '#3B82F6',
    description: 'Traditional network flow datasets covering IoT, enterprise, and hybrid environments with malicious packets, labels, and attack feature vectors.',
  },
  cloud: {
    label: 'Cloud, Microservices & Edge',
    doi: 'https://doi.org/10.34740/KAGGLE/DSV/12479689',
    datasets: ['microsoft-guide', 'container-security', 'edge-iiot'],
    color: '#A855F7',
    description: 'Cloud-native, container, and industrial edge datasets with security telemetry, API events, and protocol-level features.',
  },
}

const CATEGORY_COLORS: Record<string, string> = {
  ddos: '#EF4444', recon: '#F59E0B', bruteforce: '#A855F7', spoofing: '#06B6D4',
  web: '#22C55E', malware: '#EC4899', dos: '#F97316', injection: '#8B5CF6',
  botnet: '#14B8A6', exploit: '#FB923C', anomaly: '#64748B', other: '#94A3B8',
}

/* ═══════════════════════ Component ════════════════════════════════════════ */

export default function Datasets() {
  const [expanded, setExpanded] = useState<string | null>(null)
  const [view, setView] = useState<'cards' | 'table'>('cards')

  const toggle = (id: string) => setExpanded(expanded === id ? null : id)

  const totalRecords = DATASETS.reduce((s, d) => s + d.recordsRaw, 0)
  const totalAttacks = new Set(DATASETS.flatMap((d) => d.attackClasses.map((a) => a.name))).size

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl md:text-2xl font-display font-bold">Benchmark Datasets</h1>
          <p className="text-xs md:text-sm text-text-secondary mt-1">
            6 datasets &middot; {(totalRecords / 1_000_000).toFixed(1)}M total records &middot; {totalAttacks} unique attack classes
          </p>
        </div>
        <div className="flex gap-1 bg-bg-secondary rounded-lg p-1 border border-bg-card">
          <button
            onClick={() => setView('cards')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${view === 'cards' ? 'bg-accent-blue/15 text-accent-blue' : 'text-text-secondary hover:text-text-primary'}`}
          >
            Cards
          </button>
          <button
            onClick={() => setView('table')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${view === 'table' ? 'bg-accent-blue/15 text-accent-blue' : 'text-text-secondary hover:text-text-primary'}`}
          >
            Table
          </button>
        </div>
      </div>

      <PageGuide
        title="How to use Datasets"
        steps={[
          { title: 'Browse available datasets', desc: 'View the 6 benchmark datasets (CIC-IoT-2023, CSE-CIC-IDS2018, UNSW-NB15, NSL-KDD, etc.) with their specifications, class distributions, and feature counts.' },
          { title: 'View dataset statistics', desc: 'Click any dataset card to see detailed statistics: number of flows, attack class distribution, feature dimensions, and recommended preprocessing.' },
          { title: 'Download sample data', desc: 'Download sample CSV files for testing with the Upload & Analyse, Adversarial Eval, or RL Response Agent pages.' },
          { title: 'Compare datasets', desc: 'Compare attack distributions and feature characteristics across datasets to understand their strengths for different evaluation scenarios.' },
        ]}
        tip="Tip: CIC-IoT-2023 has the widest attack variety (34 classes). Use it for comprehensive model evaluation."
      />

      {/* Collection DOI links */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {(Object.entries(COLLECTION_INFO) as [string, typeof COLLECTION_INFO.network][]).map(([key, col]) => (
          <a
            key={key}
            href={col.doi}
            target="_blank"
            rel="noopener noreferrer"
            className="bg-bg-secondary rounded-xl p-4 border border-bg-card hover:border-accent-blue/40 transition-colors group"
          >
            <div className="flex items-center gap-3 mb-2">
              <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${col.color}20` }}>
                <Database className="w-4 h-4" style={{ color: col.color }} />
              </div>
              <div>
                <h3 className="text-sm font-medium group-hover:text-accent-blue transition-colors">{col.label}</h3>
                <p className="text-xs text-text-secondary">{col.datasets.length} datasets combined</p>
              </div>
              <ExternalLink className="w-3.5 h-3.5 text-text-secondary ml-auto group-hover:text-accent-blue transition-colors" />
            </div>
            <p className="text-xs text-text-secondary">{col.description}</p>
            <p className="text-xs font-mono text-accent-blue/70 mt-2 truncate">{col.doi}</p>
          </a>
        ))}
      </div>

      {/* Table View */}
      {view === 'table' && (
        <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
          <h3 className="text-sm font-medium text-text-secondary mb-4">Dataset Summary</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-text-secondary text-xs">
                  <th className="px-3 py-2 text-left">Dataset</th>
                  <th className="px-3 py-2 text-right">Records</th>
                  <th className="px-3 py-2 text-center">Attack Types</th>
                  <th className="px-3 py-2 text-center">Features</th>
                  <th className="px-3 py-2 text-left">Domain</th>
                  <th className="px-3 py-2 text-left">Label Column</th>
                  <th className="px-3 py-2 text-left">Format</th>
                  <th className="px-3 py-2 text-center">Year</th>
                </tr>
              </thead>
              <tbody>
                {DATASETS.map((d) => (
                  <tr key={d.id} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                    <td className="px-3 py-2.5 font-medium" style={{ color: d.domainColor }}>{d.name}</td>
                    <td className="px-3 py-2.5 text-right font-mono text-xs">{d.records}</td>
                    <td className="px-3 py-2.5 text-center font-mono text-xs">{d.attackTypes}</td>
                    <td className="px-3 py-2.5 text-center font-mono text-xs">{d.features}</td>
                    <td className="px-3 py-2.5 text-xs">{d.domain}</td>
                    <td className="px-3 py-2.5 font-mono text-xs text-text-secondary">{d.labelColumn}</td>
                    <td className="px-3 py-2.5 text-xs text-text-secondary">{d.fileFormat}</td>
                    <td className="px-3 py-2.5 text-center text-xs">{d.year}</td>
                  </tr>
                ))}
                <tr className="border-t-2 border-bg-card font-bold">
                  <td className="px-3 py-2.5">Total</td>
                  <td className="px-3 py-2.5 text-right font-mono text-xs">84.2M</td>
                  <td className="px-3 py-2.5 text-center font-mono text-xs">84</td>
                  <td className="px-3 py-2.5 text-center font-mono text-xs">—</td>
                  <td colSpan={4} className="px-3 py-2.5 text-xs text-text-secondary">6 domains covered</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Cards View */}
      {view === 'cards' && (
        <div className="space-y-4">
          {DATASETS.map((d) => {
            const isOpen = expanded === d.id
            const Icon = d.domainIcon
            const attackCategories = [...new Set(d.attackClasses.map((a) => a.category))]

            return (
              <div key={d.id} className="bg-bg-secondary rounded-xl border border-bg-card overflow-hidden">
                {/* Card header — always visible */}
                <button
                  onClick={() => toggle(d.id)}
                  className="w-full flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 p-4 md:p-5 text-left hover:bg-bg-card/20 transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-10 h-10 md:w-12 md:h-12 rounded-xl flex items-center justify-center shrink-0" style={{ background: `${d.domainColor}15` }}>
                      <Icon className="w-5 h-5 md:w-6 md:h-6" style={{ color: d.domainColor }} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <h3 className="font-semibold text-sm md:text-base" style={{ color: d.domainColor }}>{d.name}</h3>
                        <span className="text-xs px-2 py-0.5 rounded-full bg-bg-card text-text-secondary">{d.domain}</span>
                        <span className="text-xs px-2 py-0.5 rounded-full bg-bg-card text-text-secondary">{d.year}</span>
                      </div>
                      <p className="text-xs text-text-secondary line-clamp-2 sm:line-clamp-1">{d.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 sm:gap-6 shrink-0 pl-13 sm:pl-0">
                    <div className="text-center">
                      <div className="text-base md:text-lg font-bold font-mono">{d.records}</div>
                      <div className="text-xs text-text-secondary">Records</div>
                    </div>
                    <div className="text-center">
                      <div className="text-base md:text-lg font-bold font-mono">{d.attackTypes}</div>
                      <div className="text-xs text-text-secondary">Attacks</div>
                    </div>
                    <div className="text-center">
                      <div className="text-base md:text-lg font-bold font-mono">{d.features}</div>
                      <div className="text-xs text-text-secondary">Features</div>
                    </div>
                    {isOpen ? <ChevronUp className="w-5 h-5 text-text-secondary" /> : <ChevronDown className="w-5 h-5 text-text-secondary" />}
                  </div>
                </button>

                {/* Expanded details */}
                {isOpen && (
                  <div className="border-t border-bg-card px-3 md:px-5 pb-4 md:pb-5 space-y-5">
                    {/* Row 1: Attack classes + Feature groups */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                      {/* Attack Classes */}
                      <div>
                        <div className="flex items-center gap-2 mb-3">
                          <Shield className="w-4 h-4 text-text-secondary" />
                          <h4 className="text-sm font-medium">Attack Classes ({d.attackClasses.length})</h4>
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {d.attackClasses.map((a) => (
                            <span
                              key={a.name}
                              className="text-xs px-2 py-1 rounded-md border"
                              style={{
                                borderColor: `${CATEGORY_COLORS[a.category]}40`,
                                background: `${CATEGORY_COLORS[a.category]}10`,
                                color: CATEGORY_COLORS[a.category],
                              }}
                            >
                              {a.name}
                            </span>
                          ))}
                        </div>
                        <div className="flex flex-wrap gap-2 mt-3">
                          {attackCategories.map((cat) => (
                            <span key={cat} className="flex items-center gap-1 text-xs text-text-secondary">
                              <span className="w-2 h-2 rounded-full" style={{ background: CATEGORY_COLORS[cat] }} />
                              {cat}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Feature Groups */}
                      <div>
                        <div className="flex items-center gap-2 mb-3">
                          <Layers className="w-4 h-4 text-text-secondary" />
                          <h4 className="text-sm font-medium">Feature Groups ({d.features} total)</h4>
                        </div>
                        <div className="space-y-2">
                          {d.featureGroups.map((fg) => (
                            <div key={fg.name} className="bg-bg-card/30 rounded-lg p-2.5">
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-xs font-medium">{fg.name}</span>
                                <span className="text-xs font-mono text-text-secondary">{fg.count} features</span>
                              </div>
                              <p className="text-xs text-text-secondary font-mono">
                                {fg.examples.join(', ')}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Row 2: Preprocessing pipeline */}
                    <div>
                      <div className="flex items-center gap-2 mb-3">
                        <BarChart3 className="w-4 h-4 text-text-secondary" />
                        <h4 className="text-sm font-medium">Preprocessing Pipeline</h4>
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
                        {d.preprocessing.map((ps) => (
                          <div key={ps.step} className="flex flex-col items-center text-center">
                            <div
                              className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                              style={{ background: `${d.domainColor}20`, color: d.domainColor }}
                            >
                              {ps.step}
                            </div>
                            <div className="mt-2 px-1">
                              <div className="text-xs font-medium">{ps.name}</div>
                              <p className="text-xs text-text-secondary mt-0.5 leading-relaxed">{ps.description}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Row 3: Metadata grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <div className="bg-bg-card/30 rounded-lg p-3">
                        <div className="flex items-center gap-1.5 mb-1">
                          <Tag className="w-3 h-3 text-text-secondary" />
                          <span className="text-xs text-text-secondary">Label Column</span>
                        </div>
                        <p className="text-xs font-mono font-medium">{d.labelColumn}</p>
                        <p className="text-xs text-text-secondary mt-0.5">{d.labelType}</p>
                      </div>
                      <div className="bg-bg-card/30 rounded-lg p-3">
                        <div className="flex items-center gap-1.5 mb-1">
                          <FileText className="w-3 h-3 text-text-secondary" />
                          <span className="text-xs text-text-secondary">File Format</span>
                        </div>
                        <p className="text-xs font-medium">{d.fileFormat}</p>
                        <p className="text-xs text-text-secondary mt-0.5">Sample: {d.sampleSize}</p>
                      </div>
                      <div className="bg-bg-card/30 rounded-lg p-3">
                        <div className="flex items-center gap-1.5 mb-1">
                          <Database className="w-3 h-3 text-text-secondary" />
                          <span className="text-xs text-text-secondary">Source</span>
                        </div>
                        <p className="text-xs font-medium">{d.source}</p>
                      </div>
                      <div className="bg-bg-card/30 rounded-lg p-3">
                        <div className="flex items-center gap-1.5 mb-1">
                          <Shield className="w-3 h-3 text-text-secondary" />
                          <span className="text-xs text-text-secondary">Compatible Models</span>
                        </div>
                        <p className="text-xs font-medium">{d.compatibleModels.length} / 5 models</p>
                        <p className="text-xs text-text-secondary mt-0.5">All models supported</p>
                      </div>
                    </div>

                    {/* Notes */}
                    {d.notes && (
                      <div className="bg-accent-blue/5 border border-accent-blue/20 rounded-lg p-3">
                        <p className="text-xs text-text-secondary"><span className="font-medium text-accent-blue">Note:</span> {d.notes}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Bottom: Cross-dataset feature compatibility matrix */}
      <div className="bg-bg-secondary rounded-xl p-5 border border-bg-card">
        <h3 className="text-sm font-medium text-text-secondary mb-4">Feature Dimension & Preprocessing Summary</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-text-secondary">
                <th className="px-3 py-2 text-left">Dataset</th>
                <th className="px-3 py-2 text-center">Raw Features</th>
                <th className="px-3 py-2 text-center">Model Input Dim</th>
                <th className="px-3 py-2 text-center">Alignment</th>
                <th className="px-3 py-2 text-center">Scaler</th>
                <th className="px-3 py-2 text-center">Label Encoding</th>
                <th className="px-3 py-2 text-center">Missing Data</th>
              </tr>
            </thead>
            <tbody>
              {DATASETS.map((d) => {
                const needsAlignment = d.features !== 46
                const alignment = d.features < 46 ? 'Zero-pad' : d.features > 46 ? 'Feature selection' : 'Native fit'
                return (
                  <tr key={d.id} className="border-t border-bg-card/50 hover:bg-bg-card/20">
                    <td className="px-3 py-2 font-medium" style={{ color: d.domainColor }}>{d.name}</td>
                    <td className="px-3 py-2 text-center font-mono">{d.features}</td>
                    <td className="px-3 py-2 text-center font-mono">46</td>
                    <td className={`px-3 py-2 text-center ${needsAlignment ? 'text-accent-amber' : 'text-accent-green'}`}>
                      {alignment}
                    </td>
                    <td className="px-3 py-2 text-center">
                      {d.id === 'container-security' ? 'RobustScaler' : 'StandardScaler'}
                    </td>
                    <td className="px-3 py-2 text-center font-mono">{d.labelColumn}</td>
                    <td className="px-3 py-2 text-center">
                      {d.id === 'microsoft-guide' || d.id === 'container-security' ? (
                        <span className="text-accent-amber">Sparse</span>
                      ) : (
                        <span className="text-accent-green">&lt; 0.3%</span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-text-secondary mt-3">
          All models use 46-dimensional input. Datasets with more features use mutual-information feature selection.
          Datasets with fewer features are zero-padded. The auto-scaler regenerates per dataset.
        </p>
      </div>
    </div>
  )
}
