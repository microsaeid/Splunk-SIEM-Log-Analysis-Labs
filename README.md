# Splunk SIEM Log Analysis Labs

A hands-on collection of security log analysis labs using Splunk Enterprise, designed to develop practical SOC investigation and SPL skills through real-world network datasets.

## About This Project

This repository documents my hands-on practice analyzing different security log sources in Splunk.

Rather than focusing only on SPL syntax, each lab is structured around an investigation process:

**Observe → Identify → Investigate → Validate → Document**

The goal is to understand what the logs reveal, identify behavior that deserves further investigation, and use SPL to support evidence-based analysis.

The labs progressively increase in complexity as the series develops.

## Lab Series

| Lab | Log Source | Investigation Focus                                                | Status      |
| --- | ---------- | ------------------------------------------------------------------ | ----------- |
| 01  | DNS        | DNS activity, source behavior, domain diversity, traffic anomalies | In Progress |
| 02  | FTP        | Authentication and file-transfer activity                          | Planned     |
| 03  | HTTP       | Web requests, response codes, URI and client behavior              | Planned     |
| 04  | SSH        | Authentication failures, password attacks, remote access           | Planned     |
| 05  | Tunnel     | Tunnel protocols, endpoint behavior, anomaly analysis              | Planned     |
| 06  | SMTP       | Email traffic and sender behavior                                  | Planned     |
| 07  | DHCP       | Device identification, IP attribution, and asset correlation       | Planned     |

Each lab will be completed and updated with tested SPL queries, screenshots, observations, and findings from the actual dataset.

## Investigation Approach

The labs are designed to move beyond simple log searching.

Each investigation asks questions such as:

* What behavior is normal in this dataset?
* Which systems or users stand out?
* Is high activity actually suspicious?
* What additional evidence is needed?
* Can multiple events be connected into a meaningful sequence?
* What would justify deeper investigation or escalation?

An anomaly is treated as an investigative lead, not automatically as evidence of malicious activity.

## SPL Skills

The series progressively applies SPL techniques including:

### Core Search & Analysis

* `search`
* `fields`
* `table`
* `sort`
* `head`
* `stats`
* `count`
* `dc()`
* `values()`
* `where`
* `dedup`
* `rename`
* `eval`

### Investigation & Behavioral Analysis

* `rex`
* `timechart`
* `chart`
* `bin`
* `eventstats`
* `streamstats`
* `transaction`
* `lookup`
* `fillnull`
* `case()`
* `if()`

Commands are introduced when they provide useful investigative value rather than simply to demonstrate syntax.

## SOC Skills Practiced

The labs are intended to strengthen practical skills in:

* Security log analysis
* Alert investigation
* Authentication analysis
* Network traffic analysis
* Behavioral analysis
* Timeline reconstruction
* Baseline and anomaly analysis
* Investigation pivoting
* Context enrichment
* Detection development
* Evidence-based decision making

## Data Sources

The labs use publicly available security datasets, primarily from the MACCDC dataset available through Security Repo.

Dataset-specific sources are documented inside each individual lab.

## Lab Structure

Each completed lab may include:

```text
Lab XX – Log Source/
│
├── README.md
├── queries.spl
└── screenshots/
```

The lab README documents the investigation process, while SPL searches and screenshots provide supporting evidence from the hands-on analysis.

## Current Lab

### Lab 01 – DNS Log Analysis with Splunk SIEM

The first lab investigates DNS activity by examining:

* Active DNS sources
* Frequently queried domains
* Query volume
* Domain diversity
* Time-based activity
* Potential behavioral anomalies

The investigation emphasizes an important SOC principle:

> High activity is not automatically malicious. An analyst must determine whether the behavior is unusual, explainable, and supported by additional evidence.

## Development Status

This repository is an ongoing hands-on project.

Labs are added progressively after the searches are tested against the actual datasets and the investigation results are reviewed.

The goal is to document not only the final SPL searches, but also the reasoning used to move from raw logs to an investigative conclusion.

---

**Focus:** Splunk | SIEM | SOC Analysis | SPL | Network Security | Log Analysis | Threat Detection
