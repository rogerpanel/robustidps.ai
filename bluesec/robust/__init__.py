"""RobustIDPS investigation agent for the BlueSec1 runtime.

Installed into a clone of the organisers' reference agent as
`src/bluesec1_agent/robust/` (see bluesec/install.sh). It uses their runtime
client unchanged and only replaces the reasoning loop:

- the tool catalog advertised by each task is the single source of truth;
- identical calls are answered from a local cache instead of spending a call;
- arguments are validated locally against the advertised schema first;
- the final submission is checked for ids that never appeared in evidence;
- every task is written to a JSON trace next to the server's own score.

Run: uv run --with anthropic --with jsonschema --env-file .env \
         python -m bluesec1_agent.robust.cli
"""
