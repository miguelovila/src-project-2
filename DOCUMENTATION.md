# Running and understanding the analysis

The main entry point is [analysis.ipynb](analysis.ipynb). It loads the flow logs, measures normal network behavior, and runs six detection rules. This guide covers the setup, input format, and implementation details behind the [project overview](README.md).

## Setup

Run these commands from the repository root. Python 3.13 matches the notebook's recorded environment, which used Python 3.13.5.

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install jupyterlab nbconvert
python -m jupyterlab analysis.ipynb
```

The requirements file pins the analysis dependencies, including pandas, NumPy, fastparquet, and GeoIP2. Jupyter is installed separately because it is not included in that file.

Select the Python kernel from this environment and run the notebook from top to bottom. Paths are built from the working directory, so the kernel must run in the repository root. The datasets and both GeoLite2 databases are already included; the analysis uses local country lookups.

The first code cell selects the dataset:

```python
dataset_id = 10
```

The repository includes complete sets for IDs **2, 8, and 10**. Changing this value selects the matching baseline, test, and server-access files. Restart the kernel and run all cells after changing it so results from different datasets are not mixed. The notebook's explanatory prose and the final report describe dataset 10 and do not update automatically.

## Input files

Each dataset has three Parquet files:

| File | Purpose |
| --- | --- |
| `datasets/data<ID>.parquet` | One full day of internal-device traffic, supplied as the clean baseline. |
| `datasets/test<ID>.parquet` | Another full day of internal-device traffic that may contain anomalies. |
| `datasets/servers<ID>.parquet` | One day of external clients accessing the corporate public servers. This file may also contain anomalies. |

All three use the same seven columns:

| Column | Meaning |
| --- | --- |
| `timestamp` | Time of the flow's first packet, in hundredths of a second since midnight. Divide by 100 for seconds; this is not a Unix timestamp. |
| `src_ip` | Source IPv4 address: the internal device in `data`/`test`, or the external client in `servers`. |
| `dst_ip` | Destination IPv4 address. |
| `proto` | Transport protocol, represented as `tcp` or `udp`. |
| `port` | Destination port. |
| `up_bytes` | Bytes uploaded by the source. |
| `down_bytes` | Bytes downloaded by the source. |

The notebook opens `databases/geolite2-country.mmdb` and `databases/geolite2-asn.mmdb`. Its geographic rule uses the country database; the ASN reader is initialized but is not used by the six rules. Keep both files available because the setup cell opens both.

## What the notebook runs

The opening section identifies private `/24` networks from source addresses and treats private destinations observed in the baseline as internal servers. It then measures protocol/port frequencies, traffic volumes, per-device upload/download ratios, HTTPS/DNS flow-count ratios, and destination countries.

Rules 1–5 compare the internal test traffic with measurements from the clean baseline. Rule 6 analyzes the external server-access file separately. The following thresholds describe the executable code, including its inclusive and strict comparisons. Here, `q5` and `q95` mean the fifth and ninety-fifth percentiles of the relevant baseline metric.

| Rule | Metric and trigger |
| --- | --- |
| **1. Internal botnet activity** | Counts flows per internal source/destination pair. Counts at least **5×**, **10×**, or **25×** the mean baseline pair count receive moderate, high, or critical severity. Any internal destination absent from the baseline server set is labeled critical lateral movement, regardless of volume. |
| **2. HTTPS exfiltration** | For port 443, sums upload and download bytes per source and calculates `upload / (download + 1e-6)`. Baseline ratios above 100 are excluded. Ratios inside `[q5 − 0.005, q95 + 0.005]` are skipped; among the remaining values, ratios at least **10× q95** are critical, at least **5× q95** are high, and values above **q95 + 0.005** are moderate. Low ratios are not flagged. |
| **3. DNS tunneling or suppression** | Divides each source's port-443 flow count by its port-53 flow count. Only devices with both types of traffic enter the baseline or detection. Ratios below **0.3× q5** are critical tunneling candidates; below **0.7× q5** are high. Ratios above **2× q95** are critical DNS suppression candidates; above **1.5× q95** are high. |
| **4. DNS command and control** | Counts port-53 flows per source. Counts at least **2× the largest baseline count** are critical; otherwise, counts at least **baseline maximum + standard deviation** are high. The additional `q95 + 2× standard deviation` threshold is calculated and printed, but is not used for detection. |
| **5. External destinations** | Finds newly contacted countries and countries whose total flow count increased by **at least 100%**. Associates those country-level changes with the internal sources that contacted them. A new `Unknown` country entry is excluded from source attribution. |
| **6. External access timing** | Analyzes sources with at least **10 flows** and a positive mean interval. Computes `CV = 100 × std(intervals) / mean(intervals)`. CV below **0.5× q5** is critical bot-like timing; below **0.8× q5** is high. Otherwise, a mean interval above **3× the average per-client mean interval** is high slow-access behavior. |

The external-access rule calculates its reference distribution from the same server-access file it checks. It is a comparison between clients in that capture, not validation against a separate clean day. The detector reads `pattern_data` from the supplied baseline dictionary, so passing a different `servers_df` alongside an old baseline does not recompute those client measurements.

## Inspect and export results

Detection functions print the baseline measurements and reasons for each finding. They also retain structured results in the notebook:

| Variable | Contents |
| --- | --- |
| `detections` | Internal source/destination pairs, flow counts, severity, and detection reason. |
| `https_detections` | Sources with unusual HTTPS upload/download ratios. |
| `dns_detections` | Sources with unusual HTTPS/DNS flow-count ratios. |
| `dns_cc_detections` | Sources with unusually large DNS flow counts. |
| `destinations_detections` | Dictionary of new countries, country-level increases, and associated sources. |
| `external_detections` | External sources with unusual timing, their classifications, and target servers. |

A full dataset-10 run completed all 11 code cells with Python 3.13.16 and the pinned analysis dependencies. It produced **18 internal pairs, 8 HTTPS sources, 6 HTTPS/DNS-ratio sources, 4 DNS-volume sources, 56 sources associated with country changes, and 3 external timing findings**. Sources overlap between rules; these counts cannot be added to obtain a device total.

After running the notebook on dataset 10, add a cell to inspect or save the findings:

```python
https_detections.head()
dns_detections.head()
sorted(destinations_detections["anomalous_ips"])

# The setup cell creates output/, but exports are explicit.
https_detections.to_csv("output/https-detections.csv", index=False)
external_detections.to_csv("output/external-detections.csv", index=False)
```

Some result variables are assigned only when their baseline calculation succeeds. When adapting the notebook to other data, account for missing traffic categories and empty DataFrames before selecting result columns.

To execute a copy without opening Jupyter, run this from the repository root with the environment active:

```bash
mkdir -p output
python -m jupyter nbconvert --to notebook --execute analysis.ipynb \
  --output analysis.executed --output-dir output \
  --ExecutePreprocessor.timeout=600
python -m jupyter nbconvert --to html output/analysis.executed.ipynb \
  --output analysis --output-dir output
```

This produces `output/analysis.executed.ipynb` and `output/analysis.html`, preserving the original notebook.

## The earlier rule module

[siemrules.py](siemrules.py) contains the earlier implementation. The notebook does not import it. Its functions check protocol/port changes, bandwidth changes, countries, ASNs, internal-server behavior, per-client deviations, and external flow timing using a different set of thresholds.

The protocol/port check accepts grouped pandas Series, so it can be called directly after loading the notebook's input tables:

```python
import siemrules

siemrules.check_protocol_port_anomalies(
    normal_data.groupby(["proto", "port"]).size(),
    anomalous_data.groupby(["proto", "port"]).size(),
)
```

Other checks require preparation beyond the raw Parquet schema. Country checks need `dst_cc`; ASN checks also need `dst_asn` and `dst_asn_org`. Server checks take a mapping of server IPs to `(expected_flow_count, "protocol:port")`. The client check additionally requires a baseline DataFrame with `src_ip`, `protocol_ports`, `contacted_countries`, `contacted_asns`, `contacted_private_ip`, `tot_flows`, `tot_up_traffic`, `tot_down_traffic`, and `avg_flows_per_minute`.

Most functions print their alerts. `check_client_behavior_anomalies(...)` returns a `CompromisedClientsReport`, which supports filtering with methods such as `report.filterBy("protocol_violations").show()` and `report.summary()`. That report is separate from the notebook's results. The module's external DDoS check uses an **unscaled** coefficient of variation; do not compare its numeric CV thresholds directly with the notebook's percentage-scaled values.

## Reading the findings

These rules use flow metadata. Port 53 and port 443 identify the traffic being measured; there is no packet-payload inspection, DNS-query decoding, or TLS decryption. A DNS flow count is not a decoded query count, despite some labels in the output.

The analysis assumes stable device IPs and comparable full-day captures. A single clean day establishes what was observed on that day; it does not cover every legitimate workload. Likewise, discovering a new private destination is a reason to investigate, not proof of lateral movement. Country changes provide context, and the hardcoded country highlights in the output are not threat intelligence.

Printed labels such as “compromised,” “malicious,” or “statistically impossible” reflect the original reporting language. Treat them as rule findings requiring investigation. Rule 1's combined IP list includes destinations as well as sources, so a listed server may be the target of unusual traffic.

The written reports also differ from the code in a few places. Rule 5 executes at **≥100%** growth, while the final report describes **>700%**. The current run flags eight HTTPS sources; the report lists six. The aggregate threat scores and the report's 22-device summary are written analysis; the notebook does not generate an equivalent combined report. Use the rule-level results when reproducing the implementation.

## Original project material

This project was developed by **Miguel Vila** and **Gonçalo Cunha** for **Segurança em Redes de Comunicações / Security in Communications Networks**, taught by **Paulo Salvador** at the University of Aveiro.

- [Project proposal](project-proposal.pdf): the assignment, corporate-network scenario, dataset definitions, and required analyses.
- [Final project report](project_report.pdf): the dataset-10 investigation, thresholds, findings, and combined assessment.
- [Enhancement report](enhancement_report.pdf): the move from the earlier static checks to six specialized rules built around measured traffic behavior.
