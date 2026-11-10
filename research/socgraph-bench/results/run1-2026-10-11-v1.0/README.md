# Study run 1 (2026-10-11), scored on SOCGraph-21 v1.0

One `--ablation-suite` over all 21 tasks: six configurations, 126 task runs.
Model claude-opus-5-5, effort high, concurrency 4, soft budget 12, hard cap 30.

| File | Content |
|---|---|
| `console.log` | the run's console output (per-task lines and the printed table) |
| `per_task.csv` | the per-task lines as a table, with platform and expected verdict from the pack manifest |

**These scores are superseded and are not the paper's results.** They were
computed with the v1.0 ground truth, which had two defects found by
inspecting this run (see `benchmark/README.md`, *Versions*):

- Benign Linux tasks scored the same partial quality under every
  configuration (0.683 on `linux-motd-discovery`, 0.683 on
  `linux-dpkg-service-start` in five of six configurations). Q = 0.683 is
  exactly two of three anchors cited plus three ids outside the anchors (the
  only decomposition of the score that gives it), and the trigger lineages
  contain processes between the anchors (three shells in the login-message
  chain; the `apache2.postinst` script between `dpkg` and `systemctl`) that
  v1.0 counted as unrelated citations.
- On Linux, `sudo` and intermediate shells in the operator session were not
  in the acceptable set, so naming them lowered precision. Windows malicious
  answers are not affected.

A third issue was in the local runtime, not the ground truth: in the
`no validation` run, a malformed argument reached the runtime and raised an
exception (`'str' object has no attribute 'get'`), aborting
`lsass-dump-comsvcs` with reward 0. A server would have rejected the call
with an error. The runtime now validates arguments against the tool schema
and rejects them as a server does (the call still counts). That task run of
the `no validation` configuration is therefore not usable.

The traces of this run (`bluesec1-agent/traces/20261011-20*-local-run`)
are rescored on v1.1 without model calls; the rescored folders go to
`../study/`.
