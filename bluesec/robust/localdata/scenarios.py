"""Practice tasks built from public attack telemetry:
- Windows: OTRF Security-Datasets (https://github.com/OTRF/Security-Datasets, MIT)
- Linux: Splunk attack_data, Sysmon for Linux (https://github.com/splunk/attack_data,
  Apache-2.0)

Each scenario names a public dataset, the alert a detection would raise on it,
and the ground truth an investigation should reach. Ground truth is written
as selectors over the graph (not hard-coded ids), so it is rebuilt from the
raw telemetry every time.

Malicious scenarios come from recorded technique simulations: the operator's
shell session in each recording is the root of the activity.
Benign scenarios are real background events from the same recordings that a
naive detection rule would flag (a common source of SOC false positives).

Ground truth per malicious task:
- core: what a complete response must name (the activity, its persistence or
  output, the host, the account).
- acceptable: everything the operator session touched; naming these is not
  penalised, naming anything else is.
"""

from __future__ import annotations

import ntpath
from dataclasses import dataclass, field
from typing import Any

from .graph import Graph

OTRF_BASE = (
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"
)
SPLUNK_BASE = (
    "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/"
)
SOURCE_LABEL = {"otrf": "OTRF Security-Datasets", "splunk": "Splunk attack_data"}


@dataclass(frozen=True)
class Scenario:
    id: str
    dataset: str  # OTRF: path under datasets/atomic/windows/ without .zip; Splunk: technique dir
    otrf_id: str  # the source's dataset id
    attack: str  # ATT&CK technique OTRF maps the recording to
    verdict: str  # "malicious" | "benign"
    title: str
    summary: str
    severity: str
    trigger: dict[str, Any]
    root: Any = "parent"  # malicious: "parent" | "self" | selector
    core: tuple = ()  # extra core selectors (malicious) or evidence anchors (benign)
    optimal_calls: int = 4
    extra_trigger: tuple = field(default=())
    source: str = "otrf"  # "otrf" | "splunk"

    @property
    def platform(self) -> str:
        return "linux" if self.source == "splunk" else "windows"


def _sel(**kw: Any) -> dict[str, Any]:
    return kw


SCENARIOS: list[Scenario] = [
    Scenario(
        id="lsass-dump-comsvcs",
        dataset="credential_access/host/psh_lsass_memory_dump_comsvcs",
        otrf_id="SDWIN-201018195009",
        attack="T1003.001",
        verdict="malicious",
        title="Process opened LSASS with full access",
        summary="rundll32.exe opened lsass.exe with access mask 0x1FFFFF on workstation5.",
        severity="high",
        trigger=_sel(type="windows_process", image="rundll32.exe", cmd="minidump"),
        core=(_sel(type="windows_file", path_contains="lsass-comsvcs.dmp"),),
        optimal_calls=4,
    ),
    Scenario(
        id="logon-script-persistence",
        dataset="persistence/host/cmd_userinitmprlogonscript_batch",
        otrf_id="SDWIN-201019224718",
        attack="T1037.001",
        verdict="malicious",
        title="User environment registry value written by reg.exe",
        summary="reg.exe wrote a value under HKCU\\Environment on workstation5.",
        severity="medium",
        trigger=_sel(type="windows_process", image="reg.exe", cmd="userinitmprlogonscript"),
        core=(
            _sel(type="registry_key", path_endswith="environment\\userinitmprlogonscript"),
            _sel(type="windows_file", path_contains="art.bat"),
        ),
        optimal_calls=4,
    ),
    Scenario(
        id="service-binpath-hijack",
        dataset="privilege_escalation/host/cmd_service_mod_fax",
        otrf_id="SDWIN-201021204544",
        attack="T1543.003",
        verdict="malicious",
        title="Service configuration changed with sc.exe",
        summary="sc.exe changed the configuration of the Fax service on workstation5.",
        severity="high",
        trigger=_sel(type="windows_process", image="sc.exe", cmd="powershell"),
        core=(
            _sel(type="windows_process", image="powershell.exe", cmd="t1543.003"),
            _sel(type="windows_process", image="sc.exe", cmd="start fax"),
        ),
        optimal_calls=5,
    ),
    Scenario(
        id="hta-startup-folder",
        dataset="defense_evasion/host/psh_mshta_html_application_execution",
        otrf_id="SDWIN-201022035214",
        attack="T1218.005",
        verdict="malicious",
        title="mshta.exe executed an HTA file",
        summary="mshta.exe started with an .hta file argument on workstation5.",
        severity="high",
        trigger=_sel(type="windows_process", image="mshta.exe"),
        core=(
            _sel(type="windows_file", path_contains="startup\\t1218.005.hta"),
            _sel(type="windows_process", image="cmd.exe", cmd="calc.exe"),
        ),
        optimal_calls=5,
    ),
    Scenario(
        id="firewall-rule-added",
        dataset="defense_evasion/host/cmd_netsh_fw_mod_open_ports",
        otrf_id="SDWIN-201021001911",
        attack="T1562.004",
        verdict="malicious",
        title="Inbound firewall rule added from the command line",
        summary="netsh.exe added an inbound allow rule on workstation5.",
        severity="medium",
        trigger=_sel(type="windows_process", image="netsh.exe", cmd="add rule"),
        optimal_calls=3,
    ),
    Scenario(
        id="python-http-server",
        dataset="execution/host/psh_python_webserver",
        otrf_id="SDWIN-201029001615",
        attack="T1059",
        verdict="malicious",
        title="Interpreter from a user profile started a network service",
        summary="python.exe from a user AppData folder started listening on a TCP port on "
        "workstation5.",
        severity="medium",
        trigger=_sel(type="windows_process", image="python.exe", cmd="http.server"),
        core=(_sel(type="windows_process", image="netsh.exe", cmd="python.exe"),),
        optimal_calls=4,
    ),
    Scenario(
        id="bits-download",
        dataset="defense_evasion/host/cmd_bitsadmin_download_psh_script",
        otrf_id="SDWIN-201023023651",
        attack="T1197",
        verdict="malicious",
        title="BITS transfer job started from the command line",
        summary="bitsadmin.exe created a foreground transfer job on workstation5.",
        severity="medium",
        trigger=_sel(type="windows_process", image="bitsadmin.exe"),
        optimal_calls=3,
    ),
    Scenario(
        id="run-key-and-beacon",
        dataset="persistence/host/empire_persistence_registry_modification_run_keys_elevated_user",
        otrf_id="SDWIN-200722001847",
        attack="T1547.001",
        verdict="malicious",
        title="Autostart Run key value set by PowerShell",
        summary="powershell.exe set a value under HKLM\\...\\CurrentVersion\\Run on "
        "workstation5.mordor.local.",
        severity="high",
        trigger=_sel(
            type="windows_process", image="powershell.exe", writes_key="currentversion\\run\\"
        ),
        root="self",
        core=(
            _sel(type="registry_key", path_contains="currentversion\\run\\updater"),
            _sel(type="network_connection", destination_ip="10.10.10.5"),
        ),
        optimal_calls=4,
    ),
    # ---------------------------------------------------------------- benign
    Scenario(
        id="lsass-query-by-svchost",
        dataset="defense_evasion/host/cmd_bitsadmin_download_psh_script",
        otrf_id="SDWIN-201023023651",
        attack="-",
        verdict="benign",
        title="Process opened a handle to LSASS",
        summary="svchost.exe opened lsass.exe on workstation5.",
        severity="medium",
        trigger=_sel(rel="accessed_process", source_image="svchost.exe", target_image="lsass.exe"),
        core=("trigger_relation", "trigger_source"),
        optimal_calls=2,
    ),
    Scenario(
        id="w32time-runtime-key",
        dataset="execution/host/psh_python_webserver",
        otrf_id="SDWIN-201029001615",
        attack="-",
        verdict="benign",
        title="Registry value written under a path matching '\\Run'",
        summary="lsass.exe wrote a registry value whose path contains '\\RunTime\\' on "
        "workstation5.",
        severity="medium",
        trigger=_sel(
            rel="set_registry_value",
            source_image="lsass.exe",
            target_path_contains="securetimelimits\\runtime\\securetimetickcount",
        ),
        core=("trigger_relation", "trigger_target", "trigger_source"),
        optimal_calls=2,
    ),
    Scenario(
        id="gpsvc-service-host",
        dataset="defense_evasion/host/cmd_netsh_fw_mod_open_ports",
        otrf_id="SDWIN-201021001911",
        attack="-",
        verdict="benign",
        title="New service host process started as SYSTEM",
        summary="svchost.exe started under NT AUTHORITY\\SYSTEM on workstation5.",
        severity="low",
        trigger=_sel(type="windows_process", image="svchost.exe", cmd="gpsvc"),
        core=("trigger", "trigger_parent"),
        optimal_calls=2,
    ),
    # ======================================================== Linux (Splunk)
    Scenario(
        id="linux-shadow-read",
        source="splunk",
        dataset="T1003.008/copy_file_stdoutpipe",
        otrf_id="T1003.008/copy_file_stdoutpipe",
        attack="T1003.008",
        verdict="malicious",
        title="Credential file read by a script run with sudo",
        summary="cat read /etc/shadow as root on the host.",
        severity="high",
        trigger=_sel(type="linux_process", image="cat", cmd="/etc/shadow"),
        root="ancestor:bash",
        core=(_sel(type="linux_process", cmd="stdout_etc.sh"),),
        optimal_calls=4,
    ),
    Scenario(
        id="linux-wiper-shred",
        source="splunk",
        dataset="T1485/rm_shred_critical_dir",
        otrf_id="T1485/rm_shred_critical_dir",
        attack="T1485",
        verdict="malicious",
        title="shred overwrote a system directory",
        summary="shred ran against /boot with overwrite and zero-fill options.",
        severity="critical",
        trigger=_sel(type="linux_process", image="shred", cmd="/boot"),
        root="ancestor:bash",
        core=(
            _sel(type="linux_process", image="rm", cmd="rm -rf /home --no-preserve-root"),
            _sel(type="linux_file", path_endswith="/soloshred.sh"),
        ),
        optimal_calls=4,
    ),
    Scenario(
        id="linux-kernel-module",
        source="splunk",
        dataset="T1547.006/loading_linux_kernel_module",
        otrf_id="T1547.006/loading_linux_kernel_module",
        attack="T1547.006",
        verdict="malicious",
        title="Kernel module loaded with insmod",
        summary="insmod loaded a kernel module as root.",
        severity="high",
        trigger=_sel(type="linux_process", cmd="insmod rootkit.ko", user="root"),
        root="ancestor:bash",
        core=(
            _sel(type="linux_file", path_contains="drivers/rootkit/rootkit.ko"),
            _sel(type="linux_process", image="cp", cmd="rootkit.ko", user="root"),
        ),
        optimal_calls=4,
    ),
    Scenario(
        id="linux-account-created",
        source="splunk",
        dataset="T1548.003/linux_adduser",
        otrf_id="T1548.003/linux_adduser",
        attack="T1136.001",
        verdict="malicious",
        title="Local account created",
        summary="useradd created a local account as root.",
        severity="medium",
        trigger=_sel(type="linux_process", image="useradd", cmd="atomic_user1", user="root"),
        root="ancestor:bash",
        core=(_sel(type="linux_process", image="useradd", cmd="atomic_user2"),),
        optimal_calls=4,
    ),
    Scenario(
        id="linux-sudoers-nopasswd",
        source="splunk",
        dataset="T1548.003/nopasswd_sudoers",
        otrf_id="T1548.003/nopasswd_sudoers",
        attack="T1548.003",
        verdict="malicious",
        title="Passwordless sudo rule written",
        summary="A NOPASSWD sudo rule was echoed as root.",
        severity="high",
        trigger=_sel(type="linux_process", image="echo", cmd="evil_user all=(all) nopasswd"),
        root="ancestor:bash",
        core=(_sel(type="linux_process", image="echo", cmd="root all=(all) nopasswd"),),
        optimal_calls=4,
    ),
    Scenario(
        id="linux-ld-preload-hijack",
        source="splunk",
        dataset="T1574.006/lib_hijack",
        otrf_id="T1574.006/lib_hijack",
        attack="T1574.006",
        verdict="malicious",
        title="Freshly compiled binary executed as root from a home directory",
        summary="A binary built minutes earlier in /home ran as root via a shell script.",
        severity="high",
        trigger=_sel(type="linux_process", image="prog", user="root"),
        root="ancestor:bash",
        core=(
            _sel(type="linux_process", image="sudo", cmd="run_hook.sh"),
            _sel(type="linux_process", cmd="dll_hook.sh", user="root"),
        ),
        optimal_calls=5,
    ),
    Scenario(
        id="linux-service-stopped",
        source="splunk",
        dataset="T1489/linux_service_stop_disable",
        otrf_id="T1489/linux_service_stop_disable",
        attack="T1489",
        verdict="malicious",
        title="Service state changed by systemctl as root",
        summary="systemctl changed the state of the apache2 service as root.",
        severity="medium",
        trigger=_sel(type="linux_process", image="systemctl", cmd="stop apache2", user="root"),
        root="ancestor:bash",
        core=(
            _sel(type="linux_process", image="systemctl", cmd="disable apache2", user="root"),
        ),
        optimal_calls=4,
    ),
    # ---------------------------------------------------------- Linux benign
    Scenario(
        id="linux-dpkg-service-start",
        source="splunk",
        dataset="T1489/linux_service_stop_disable",
        otrf_id="T1489/linux_service_stop_disable",
        attack="-",
        verdict="benign",
        title="Service state changed by systemctl as root",
        summary="systemctl changed the state of the apache2 service as root.",
        severity="medium",
        trigger=_sel(type="linux_process", image="systemctl", cmd="start apache2.service"),
        core=("trigger", "trigger_parent", "ancestor:dpkg"),
        optimal_calls=3,
    ),
    Scenario(
        id="linux-motd-discovery",
        source="splunk",
        dataset="T1485/rm_shred_critical_dir",
        otrf_id="T1485/rm_shred_critical_dir",
        attack="-",
        verdict="benign",
        title="Session discovery command run as root",
        summary="who -q ran as root on the host.",
        severity="low",
        trigger=_sel(type="linux_process", image="who", cmd="who -q"),
        core=("trigger", "trigger_parent", "ancestor:sshd"),
        optimal_calls=3,
    ),
    Scenario(
        id="linux-motd-tmp-cleanup",
        source="splunk",
        dataset="T1485/rm_shred_critical_dir",
        otrf_id="T1485/rm_shred_critical_dir",
        attack="-",
        verdict="benign",
        title="Files deleted by rm as root",
        summary="rm deleted files as root on the host.",
        severity="medium",
        trigger=_sel(type="linux_process", image="rm", cmd="/var/lib/update-notifier/tmp."),
        core=("trigger", "trigger_parent", "ancestor:sshd"),
        optimal_calls=3,
    ),
]

BY_ID = {s.id: s for s in SCENARIOS}


# ---------------------------------------------------------------- selectors
def _lc(v: Any) -> str:
    return str(v or "").lower()


def match_entity(g: Graph, sel: dict[str, Any]) -> list[str]:
    out = []
    for eid, e in g.entities.items():
        if sel.get("type") and e["type"] != sel["type"]:
            continue
        if "image" in sel and ntpath.basename(_lc(e.get("image"))) != sel["image"]:
            continue
        if "cmd" in sel and sel["cmd"] not in _lc(e.get("command_line")):
            continue
        if "user" in sel and _lc(e.get("user")) != sel["user"]:
            continue
        if "path_contains" in sel and sel["path_contains"] not in _lc(e.get("path")):
            continue
        if "path_endswith" in sel and not _lc(e.get("path")).endswith(sel["path_endswith"]):
            continue
        if "destination_ip" in sel and e.get("destination_ip") != sel["destination_ip"]:
            continue
        if "writes_key" in sel and not any(
            g.relations[r]["type"] == "set_registry_value"
            and sel["writes_key"] in _lc(g.entities[g.relations[r]["target"]].get("path"))
            for r in g.outgoing.get(eid, [])
        ):
            continue
        out.append(eid)
    return sorted(out)


def match_relation(g: Graph, sel: dict[str, Any]) -> list[str]:
    out = []
    for rid, r in g.relations.items():
        if r["type"] != sel["rel"]:
            continue
        src, tgt = g.entities[r["source"]], g.entities[r["target"]]
        if "source_image" in sel and ntpath.basename(_lc(src.get("image"))) != sel["source_image"]:
            continue
        if "target_image" in sel and ntpath.basename(_lc(tgt.get("image"))) != sel["target_image"]:
            continue
        if "target_path_contains" in sel and sel["target_path_contains"] not in _lc(
            tgt.get("path")
        ):
            continue
        out.append(rid)
    return sorted(out, key=lambda rid: g.relations[rid].get("timestamp", ""))


# ---------------------------------------------------------------- tasks
@dataclass
class Task:
    scenario: Scenario
    graph: Graph
    alert: dict[str, Any]
    core: set[str]
    acceptable: set[str]
    evidence_fields: dict[str, set[str]]  # benign: anchor id -> property fields that prove it


class ScenarioError(ValueError):
    pass


def build_task(sc: Scenario, g: Graph) -> Task:
    trigger_rel = None
    if "rel" in sc.trigger:
        rels = match_relation(g, sc.trigger)
        if not rels:
            raise ScenarioError(f"{sc.id}: trigger relation not found")
        trigger_rel = rels[0]
        trig = g.relations[trigger_rel]["source"]
    else:
        procs = match_entity(g, sc.trigger)
        if not procs:
            raise ScenarioError(f"{sc.id}: trigger not found")
        trig = procs[0]
    host = _host_of(g, trig)
    alert: dict[str, Any] = {
        "title": sc.title,
        "severity": sc.severity,
        "summary": sc.summary,
        "host": g.entities[host]["hostname"] if host else None,
        "trigger_entities": [trig] + ([g.relations[trigger_rel]["target"]] if trigger_rel else []),
        "detected_at": (
            g.relations[trigger_rel].get("timestamp")
            if trigger_rel
            else g.entities[trig].get("start_time")
        ),
        "source": f"{SOURCE_LABEL[sc.source]} {sc.otrf_id}",
    }
    if trigger_rel:
        alert["trigger_relations"] = [trigger_rel]

    if sc.verdict == "malicious":
        if sc.root == "self":
            root = trig
        elif sc.root == "parent":
            root = g.parent(trig) or trig
        elif isinstance(sc.root, str) and sc.root.startswith("ancestor:"):
            root = _ancestor(g, trig, sc.root.split(":", 1)[1])
            if root is None:
                raise ScenarioError(f"{sc.id}: no {sc.root} above the trigger")
        else:
            root = match_entity(g, sc.root)[0]
        session = _descendants(g, root)
        core = {trig, root}
        if host:
            core.add(host)
        # Accounts to act on: the session owner, and the trigger's account unless it
        # is the system account the session elevated to (sudo -> root, SYSTEM).
        for p in (root, trig):
            u = g.entities[p].get("user_entity_id")
            name = _lc(g.entities[u].get("name")) if u else ""
            if u and (p == root or name not in SYSTEM_ACCOUNTS):
                core.add(u)
        for sel in sc.core:
            hits = match_entity(g, sel)
            if not hits:
                raise ScenarioError(f"{sc.id}: core selector matched nothing: {sel}")
            core.update(hits)
        acceptable = set(core) | _touched(g, session | core)
        return Task(sc, g, alert, core, acceptable, {})

    # benign: anchors that legitimately prove the activity, with their real fields
    anchors: dict[str, set[str]] = {}
    for a in sc.core:
        if a == "trigger_relation" and trigger_rel:
            anchors[trigger_rel] = _fields(g.relations[trigger_rel])
        elif a == "trigger_source":
            src = g.relations[trigger_rel]["source"] if trigger_rel else trig
            anchors[src] = _fields(g.entities[src])
        elif a == "trigger_target" and trigger_rel:
            tgt = g.relations[trigger_rel]["target"]
            anchors[tgt] = _fields(g.entities[tgt])
        elif a == "trigger":
            anchors[trig] = _fields(g.entities[trig])
        elif a == "trigger_parent":
            par = g.parent(trig)
            if par:
                anchors[par] = _fields(g.entities[par])
        elif a.startswith("ancestor:"):
            anc = _ancestor(g, trig, a.split(":", 1)[1])
            if anc is None:
                raise ScenarioError(f"{sc.id}: no {a} above the trigger")
            anchors[anc] = _fields(g.entities[anc])
    return Task(sc, g, alert, set(anchors), set(anchors), anchors)


def _fields(obj: dict[str, Any]) -> set[str]:
    return {k for k in obj if k not in ("type", "source", "target")}


SYSTEM_ACCOUNTS = {"root", "nt authority\\system"}


def _ancestor(g: Graph, eid: str, image: str) -> str | None:
    p = g.parent(eid)
    for _ in range(12):
        if p is None:
            return None
        if ntpath.basename(_lc(g.entities[p].get("image"))) == image:
            return p
        p = g.parent(p)
    return None


def _host_of(g: Graph, eid: str) -> str | None:
    for r in g.incoming.get(eid, []):
        if g.relations[r]["type"] == "runs_process":
            return g.relations[r]["source"]
    return None


def _descendants(g: Graph, root: str) -> set[str]:
    seen, stack = set(), [root]
    while stack:
        p = stack.pop()
        if p not in seen:
            seen.add(p)
            stack.extend(g.children(p))
    return seen


TOUCH = {
    "wrote_file",
    "deleted_file",
    "set_registry_value",
    "created_registry_key",
    "deleted_registry_key",
    "connected_to",
    "accepted_connection_from",
    "resolves_to",
    "executed_file",
    "created_pipe",
    "connected_to_pipe",
    "injected_into",
    "accessed_process",
    "created_scheduled_task",
    "win_process_create",
}


def _touched(g: Graph, procs: set[str]) -> set[str]:
    out: set[str] = set()
    for p in procs:
        for r in g.outgoing.get(p, []):
            if g.relations[r]["type"] in TOUCH:
                out.add(r)
                out.add(g.relations[r]["target"])
    return out
