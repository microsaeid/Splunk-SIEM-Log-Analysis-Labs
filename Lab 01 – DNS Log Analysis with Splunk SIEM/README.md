# Lab 01 – DNS Log Analysis with Splunk SIEM

## Overview

This lab focuses on analyzing DNS traffic in Splunk from a SOC analyst perspective.

The objective is not only to search DNS logs, but to identify unusual behavior, investigate high-volume DNS activity, analyze domain usage patterns, and determine whether specific endpoints require further investigation.

This lab uses sample DNS log data and progressively applies SPL commands to move from basic visibility to security-focused analysis.

---

## Objectives

By completing this lab, I aimed to:

* Ingest DNS log data into Splunk
* Identify the most active DNS clients
* Identify frequently queried domains
* Analyze DNS activity over time
* Detect unusual spikes in DNS queries
* Compare total DNS activity with unique domain activity
* Develop an analyst mindset rather than relying only on simple event counts

---

## Lab Environment

* Splunk Enterprise
* Sample DNS log dataset
* Local lab environment
* SPL Search & Reporting

---

## Dataset

Sample DNS log data can be obtained from:

`https://www.secrepo.com/maccdc2012/dns.log.gz`

The dataset contains DNS-related activity that can be used to simulate investigation of network behavior.

Depending on how the logs are parsed, field names may differ.

Common DNS fields include:

* `src_ip`
* `dest_ip`
* `fqdn`
* `query`
* `query_type`
* `rcode`
* `_time`

Before beginning the investigation, I verified which fields were available in the dataset.

---

# Investigation

## Step 1 – Verify DNS Events

The first step was to confirm that DNS events had been successfully indexed.

```spl
index=<dns_index> sourcetype=dns_sample
| head 20
```

### Analyst Question

Are the events being parsed correctly, and are useful DNS fields available?

At this stage, I reviewed the raw events and available fields before attempting more advanced searches.

---

## Step 2 – Identify the Most Active DNS Sources

To determine which endpoints generated the largest number of DNS requests:

```spl
index=<dns_index> sourcetype=dns_sample
| stats count as dns_queries by src_ip
| sort - dns_queries
```

### Analyst Interpretation

A system generating significantly more DNS traffic than other endpoints deserves additional investigation.

However, high DNS volume alone does not indicate malicious activity.

Possible legitimate explanations include:

* DNS servers
* Browsers
* Software update services
* Cloud applications
* Automated services

The next step is therefore to examine the behavior of these hosts in more detail.

---

## Step 3 – Identify the Most Frequently Queried Domains

```spl
index=<dns_index> sourcetype=dns_sample
| stats count as query_count by fqdn
| sort - query_count
| head 20
```

### Analyst Question

Which domains receive the highest number of DNS queries?

Frequently queried domains may represent legitimate services, but unusual or unknown domains could justify additional investigation.

---

## Step 4 – Analyze DNS Activity Over Time

To determine whether DNS activity is consistent or occurs in sudden bursts:

```spl
index=<dns_index> sourcetype=dns_sample
| timechart span=5m count
```

### Analyst Interpretation

A sudden increase in DNS traffic may indicate:

* Automated processes
* Malware beaconing
* Scanning activity
* Misconfigured applications
* DNS-based command-and-control behavior

A spike is an indicator for investigation, not proof of malicious activity.

---

## Step 5 – Analyze DNS Activity by Source

To determine whether a specific endpoint is responsible for unusual DNS activity:

```spl
index=<dns_index> sourcetype=dns_sample
| timechart span=5m count by src_ip
```

### Analyst Question

Is one endpoint responsible for a disproportionate increase in DNS traffic?

If so, that endpoint should become the focus of the investigation.

---

## Step 6 – Compare DNS Volume with Unique Domains

A useful distinction is the difference between:

* Total number of DNS queries
* Number of unique domains contacted

```spl
index=<dns_index> sourcetype=dns_sample
| stats count as total_queries dc(fqdn) as unique_domains by src_ip
| sort - total_queries
```

### Analyst Interpretation

Different patterns can mean different things.

An endpoint with:

* High total queries but few unique domains may repeatedly contact the same services
* High total queries and many unique domains may indicate browsing, automated discovery, malware, or domain-generation behavior

Additional evidence is required before making a security determination.

---

## Step 7 – Identify Endpoints with High Domain Diversity

```spl
index=<dns_index> sourcetype=dns_sample
| stats dc(fqdn) as unique_domains count as total_queries by src_ip
| sort - unique_domains
```

### Analyst Question

Which endpoint communicates with the largest number of unique domains?

A high number of unique domain requests may be worth investigating, particularly when the behavior is inconsistent with the endpoint's expected role.

---

## Step 8 – Investigate a Specific Endpoint

After identifying an interesting source IP, I isolated its DNS activity.

```spl
index=<dns_index> sourcetype=dns_sample src_ip="<suspicious_ip>"
| stats count by fqdn
| sort - count
```

This allows the analyst to understand which domains the endpoint is attempting to resolve.

---

## Step 9 – Review the Endpoint Timeline

```spl
index=<dns_index> sourcetype=dns_sample src_ip="<suspicious_ip>"
| table _time src_ip fqdn query_type
| sort _time
```

### Analyst Interpretation

Reviewing the timeline can help identify:

* Repeated queries at regular intervals
* Bursts of activity
* Unexpected domains
* Repetitive communication patterns

Regular intervals may be particularly interesting because some malware families use periodic DNS requests for command-and-control communication.

---

# Findings

The most important lesson from this lab is that DNS volume alone should not be treated as evidence of compromise.

A SOC analyst should combine multiple observations, including:

* Query volume
* Unique domain count
* Time-based patterns
* Endpoint behavior
* Domain reputation
* Expected role of the system

The goal is to identify behavior that is unusual enough to justify deeper investigation.

---

# Detection Opportunities

Based on this analysis, several possible detection strategies could be developed:

* Endpoint generating unusually high DNS query volume
* Endpoint contacting unusually large numbers of unique domains
* Sudden DNS activity spikes
* Repeated DNS queries at fixed intervals
* Large numbers of failed DNS resolutions
* Queries to suspicious or newly observed domains

These detections would require baselining to reduce false positives.

---

# Analyst Takeaway

This lab demonstrates the difference between simply searching DNS logs and performing an investigation.

Commands such as `stats`, `sort`, `head`, `timechart`, and `dc()` provide visibility, but the important part is determining what the results mean.

A high event count is not automatically malicious.

The analyst must ask:

**Is this behavior unusual for this endpoint, and what additional evidence would confirm or reject the hypothesis?**

---

# Skills Practiced

* Splunk SPL
* DNS log analysis
* `stats`
* `sort`
* `head`
* `timechart`
* `dc()`
* Field analysis
* Timeline investigation
* Anomaly identification
* SOC investigation methodology

---

## Screenshots

Recommended screenshots to include:

1. Raw DNS events in Splunk
2. Top DNS source IPs
3. Top queried domains
4. DNS activity `timechart`
5. Unique domains by source IP
6. Investigation of one selected endpoint

---

## Conclusion

DNS logs provide valuable visibility into endpoint and network behavior.

Instead of treating high query counts as inherently malicious, this investigation uses multiple indicators to identify abnormal activity and determine which endpoints deserve deeper analysis.

This approach reflects the investigative process used in security operations, where anomalies generate hypotheses that must be validated using additional evidence.
