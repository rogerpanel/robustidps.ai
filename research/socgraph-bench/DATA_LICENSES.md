# Data licences and attribution

SOCGraph-21 (`benchmark/socgraph-21-v1.1.zip`) is derived from two public
datasets. The derived tasks keep field values from the original events
(capped at 600 characters) and restructure them into an entity-relation graph;
the original licences apply to that content.

| Source | Publisher | Licence | Used for |
|---|---|---|---|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | Open Threat Research Forge | MIT (`benchmark/LICENSES/OTRF-Security-Datasets-LICENSE.txt`) | 11 Windows tasks (Sysmon and Windows Security events) |
| [Splunk attack_data](https://github.com/splunk/attack_data) | Splunk Inc. | Apache-2.0 (`benchmark/LICENSES/Splunk-attack_data-LICENSE.txt`) | 10 Linux tasks (Sysmon for Linux events) |

Changes made to the Splunk recordings (Apache-2.0 §4b): the log forwarder's
own file-creation and file-deletion events under `/opt/splunkforwarder/`
were removed as collector self-telemetry; all other events were converted into
graph entities and relations. The exact source file of every task is listed
in the pack's `manifest.json` (`source_url`) and README.

The recordings were made by their publishers in lab environments during
technique simulations; they contain lab hostnames and accounts, not data
about real people.
