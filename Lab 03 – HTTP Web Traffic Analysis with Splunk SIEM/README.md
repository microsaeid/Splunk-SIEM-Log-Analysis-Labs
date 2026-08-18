# Lab 03 – HTTP Web Traffic Analysis with Splunk SIEM

## Overview

This lab focuses on analyzing HTTP web traffic in Splunk from a SOC analyst perspective.

The investigation moves beyond basic request counting and examines HTTP methods, requested resources, response codes, source behavior, user agents, and changes in activity over time.

The objective is to identify unusual web activity and determine which sources or requests deserve deeper investigation.

---

## Objectives

By completing this lab, I aimed to:

* Ingest and validate HTTP logs in Splunk
* Analyze HTTP request methods
* Identify frequently accessed resources
* Investigate HTTP error responses
* Identify highly active source IPs
* Compare normal and unusual client behavior
* Analyze web traffic over time
* Investigate suspicious HTTP activity
* Build an investigation timeline for a selected source

---

## Lab Environment

* Splunk Enterprise
* Sample HTTP log dataset
* Local lab environment
* SPL Search & Reporting

---

## Dataset

Sample HTTP log data:

`https://www.secrepo.com/maccdc2012/http.log.gz`

Potentially useful fields include:

* `_time`
* `src_ip`
* `dest_ip`
* `method`
* `uri`
* `status`
* `user_agent`
* `bytes`
* `host`

Actual field names depend on how the dataset is parsed in Splunk.

Before beginning the investigation, I reviewed the raw events and verified which fields were available.

---

# Investigation

## Step 1 – Verify HTTP Events

```spl
index=<http_index> sourcetype=http_sample
| head 20
```

I first reviewed the raw HTTP events and available fields.

### Analyst Question

Do the events contain enough information to identify:

* Who made the request?
* What resource was requested?
* Which HTTP method was used?
* What response did the server return?

---

## Step 2 – Analyze HTTP Request Methods

```spl
index=<http_index> sourcetype=http_sample
| stats count as request_count by method
| sort - request_count
```

Typical methods may include:

* `GET`
* `POST`
* `HEAD`
* `PUT`
* `DELETE`

### Analyst Interpretation

`GET` and `POST` commonly dominate normal web traffic.

Less common methods are not automatically malicious, but unexpected methods such as `PUT` or `DELETE` may deserve investigation depending on the application.

---

## Step 3 – Identify Frequently Accessed Resources

```spl
index=<http_index> sourcetype=http_sample
| stats count as request_count by uri
| sort - request_count
| head 20
```

### Analyst Question

Which resources receive the most requests?

High request volume may be legitimate, but unusual concentration on authentication pages, administrative interfaces, scripts, or unexpected resources may provide useful investigative leads.

---

## Step 4 – Analyze HTTP Response Codes

```spl
index=<http_index> sourcetype=http_sample
| stats count as response_count by status
| sort status
```

Common response categories include:

* `2xx` – Successful requests
* `3xx` – Redirection
* `4xx` – Client errors
* `5xx` – Server errors

### Analyst Interpretation

Response codes provide context about whether requests succeeded.

A large number of `404`, `401`, or `403` responses from one source may indicate:

* Broken applications
* Automated scanners
* Enumeration
* Unauthorized access attempts
* Web reconnaissance

The response code alone is not enough to classify the activity.

---

## Step 5 – Identify Sources Generating HTTP Errors

```spl
index=<http_index> sourcetype=http_sample
| where status>=400
| stats count as error_count values(status) as response_codes by src_ip
| sort - error_count
```

This search introduces an important distinction.

Instead of asking:

**How many HTTP errors exist?**

the investigation asks:

**Which source generated them, and what kinds of errors did it receive?**

### Analyst Question

Does one source IP generate significantly more HTTP errors than the others?

---

## Step 6 – Measure Resource Diversity by Source

A client requesting many different resources may deserve further investigation.

```spl
index=<http_index> sourcetype=http_sample
| stats count as total_requests dc(uri) as unique_uris by src_ip
| sort - unique_uris
```

### Analyst Interpretation

This allows comparison between total request volume and the number of unique resources accessed.

For example:

* High request count + low URI diversity may represent repeated access to a small number of resources
* High request count + high URI diversity may represent normal browsing, crawling, automated scanning, or enumeration

Context is required to distinguish between them.

---

## Step 7 – Examine Which Resources Each Source Accessed

```spl
index=<http_index> sourcetype=http_sample
| stats count as total_requests dc(uri) as unique_uris values(uri) as requested_resources by src_ip
| sort - unique_uris
```

### Analyst Question

Is an unusual source systematically accessing many different resources?

The `values()` function provides additional context by preserving the set of resources observed for each source.

This can help distinguish repetitive traffic from broader exploration of the web application.

---

## Step 8 – Analyze Web Traffic Over Time

```spl
index=<http_index> sourcetype=http_sample
| timechart span=5m count as requests
```

### Analyst Interpretation

A time-based view helps identify:

* Sudden traffic spikes
* Short bursts of automated activity
* Periods of unusually low activity
* Changes from normal traffic patterns

A spike becomes more useful when correlated with source IPs, URIs, methods, and response codes.

---

## Step 9 – Analyze Activity by Source IP

```spl
index=<http_index> sourcetype=http_sample
| timechart span=5m count by src_ip
```

### Analyst Question

Is a specific source responsible for an unusual traffic spike?

If so, that source becomes a candidate for deeper investigation.

---

## Step 10 – Identify Unusual User Agents

```spl
index=<http_index> sourcetype=http_sample
| stats count as requests by user_agent
| sort - requests
```

User agents can provide clues about the software generating HTTP requests.

Potentially interesting observations include:

* Rare user agents
* Missing user agents
* Command-line clients
* Automated tools
* Unexpected software

A user agent should be treated as supporting evidence because it can be modified or spoofed.

---

## Step 11 – Correlate Sources with User Agents

```spl
index=<http_index> sourcetype=http_sample
| stats count as requests dc(uri) as unique_uris values(user_agent) as user_agents by src_ip
| sort - unique_uris
```

### Analyst Interpretation

Combining multiple fields provides stronger context than analyzing each field independently.

A source IP showing:

* High request volume
* High URI diversity
* Unusual user agent

would be more interesting than a source matching only one of these conditions.

---

## Step 12 – Investigate a Selected Source

After identifying an interesting source IP:

```spl
index=<http_index> sourcetype=http_sample src_ip="<investigated_ip>"
| table _time src_ip method uri status user_agent
| sort _time
```

This provides a chronological view of the source's behavior.

### Analyst Questions

* Which resource did the source access first?
* Did it request many different resources?
* Were requests successful?
* Did the source receive many `404`, `401`, or `403` responses?
* Did its behavior change during the session?

---

# Investigation Scenario

Consider a source that produces:

* A high number of requests
* Requests to many unique URIs
* Numerous `404` responses
* Requests occurring within a short period
* An unusual user agent

Individually, these observations may have legitimate explanations.

Together, however, they could support the hypothesis that the source is performing automated web reconnaissance or enumeration.

The hypothesis would still require additional evidence before classifying the activity as malicious.

---

# Detection Opportunities

Potential HTTP detection ideas include:

* Source generating excessive `404` responses
* Repeated `401` or `403` responses
* High URI diversity from a single source
* Sudden request spikes
* Unusual HTTP methods
* Rare or unexpected user agents
* Rapid requests to many different application paths
* Access to administrative or sensitive resources

Detection thresholds should be based on normal environment behavior to reduce false positives.

---

# Findings

HTTP logs provide much more than simple web traffic counts.

By combining:

* Source IP
* HTTP method
* URI
* Response status
* User agent
* Time

an analyst can begin reconstructing the behavior of a web client.

The strongest investigative leads usually come from combinations of unusual behaviors rather than a single indicator.

---

# Analyst Takeaway

The central question in this lab is not:

**Which IP generated the most traffic?**

It is:

**What was this source trying to do?**

A useful investigation progresses from:

**Volume → Source → Resources → Responses → Client characteristics → Timeline**

This provides the context needed to distinguish ordinary web traffic from behavior that deserves escalation.

---

# Skills Practiced

### Essential SPL

* `search`
* `table`
* `sort`
* `head`
* `stats`
* `count`
* `dc()`
* `values()`
* `where`

### Intermediate SPL

* `timechart`

### SOC Analysis

* HTTP log analysis
* Web traffic analysis
* Response-code analysis
* Source behavior analysis
* URI diversity analysis
* User-agent analysis
* Timeline reconstruction
* Hypothesis-driven investigation

---

## Screenshots

Recommended screenshots:

1. Raw HTTP events
2. HTTP method distribution
3. Most frequently accessed URIs
4. HTTP response-code distribution
5. Sources generating the most HTTP errors
6. Unique URIs by source
7. HTTP traffic timechart
8. Selected source investigation timeline

---

## Conclusion

HTTP logs provide detailed evidence about interactions between clients and web applications.

Rather than relying on a single metric, this investigation combines request volume, URI diversity, response codes, user agents, source IPs, and time-based behavior.

This approach allows a SOC analyst to move from basic log searching toward forming and testing hypotheses about potentially suspicious web activity.
