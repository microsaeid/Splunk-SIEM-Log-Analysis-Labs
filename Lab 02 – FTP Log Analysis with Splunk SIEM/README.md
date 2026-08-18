# Lab 02 – FTP Log Analysis with Splunk SIEM

## Overview

This lab focuses on analyzing FTP activity in Splunk from a SOC analyst perspective.

The goal is to identify authentication activity, file transfer behavior, suspicious FTP commands, unusual source IPs, and potential indicators of unauthorized access or data movement.

Instead of treating FTP logs as simple file-transfer records, this lab approaches them as evidence that can be used during a security investigation.

---

## Objectives

By completing this lab, I aimed to:

* Ingest FTP logs into Splunk
* Identify active FTP clients and users
* Analyze authentication activity
* Identify frequently used FTP commands
* Investigate file transfer behavior
* Detect unusual or suspicious access patterns
* Build an investigation based on multiple pieces of evidence

---

## Lab Environment

* Splunk Enterprise
* Sample FTP log dataset
* Local lab environment
* SPL Search & Reporting

---

## Dataset

Sample FTP log data:

`https://www.secrepo.com/maccdc2012/ftp.log.gz`

Depending on the dataset and parsing configuration, available field names may differ.

Potentially useful FTP fields include:

* `_time`
* `src_ip`
* `dest_ip`
* `user`
* `command`
* `filename`
* `status`
* `response`

Before beginning the analysis, I first reviewed the raw events and verified which fields were actually available.

---

# Investigation

## Step 1 – Verify FTP Events

```spl
index=<ftp_index> sourcetype=ftp_sample
| head 20
```

### Analyst Question

Are FTP events being indexed and parsed correctly?

Before performing analysis, I reviewed the raw logs to understand the event structure and identify useful fields.

---

## Step 2 – Identify the Most Active Source IPs

```spl
index=<ftp_index> sourcetype=ftp_sample
| stats count as ftp_events by src_ip
| sort - ftp_events
```

### Analyst Interpretation

A source IP generating significantly more FTP activity than other hosts may deserve additional investigation.

However, high activity alone does not prove malicious behavior.

The host may legitimately perform automated backups, software transfers, or administrative tasks.

---

## Step 3 – Identify the Most Active FTP Users

```spl
index=<ftp_index> sourcetype=ftp_sample
| stats count as activity_count by user
| sort - activity_count
```

### Analyst Question

Which user accounts generate the most FTP activity?

An unusually active account may be legitimate, but it can also indicate:

* Compromised credentials
* Automated access
* Misuse of a service account
* Unexpected file transfer activity

---

## Step 4 – Analyze FTP Commands

FTP commands provide useful context about what a user or host is attempting to do.

```spl
index=<ftp_index> sourcetype=ftp_sample
| stats count by command
| sort - count
```

Common commands may include:

* `USER`
* `PASS`
* `LIST`
* `RETR`
* `STOR`
* `CWD`
* `DELE`

### Analyst Interpretation

Commands such as `RETR` and `STOR` are especially important because they indicate file download and upload activity.

Repeated use of sensitive commands may require further investigation depending on the role of the user and system.

---

## Step 5 – Identify File Upload Activity

```spl
index=<ftp_index> sourcetype=ftp_sample command=STOR
| stats count as upload_count by src_ip user
| sort - upload_count
```

### Analyst Question

Which users and systems are uploading files to the FTP server?

Unexpected upload activity may indicate:

* Unauthorized file placement
* Malware staging
* Data transfer
* Abuse of compromised credentials

---

## Step 6 – Identify File Download Activity

```spl
index=<ftp_index> sourcetype=ftp_sample command=RETR
| stats count as download_count by src_ip user
| sort - download_count
```

### Analyst Interpretation

A large number of downloads may represent legitimate activity, but unusually high transfer volume or access by unexpected users may require investigation.

---

## Step 7 – Review Transferred Files

If filename information is available:

```spl
index=<ftp_index> sourcetype=ftp_sample
(command=STOR OR command=RETR)
| stats count by command filename user src_ip
| sort - count
```

### Analyst Question

What types of files are being transferred?

Potentially interesting file types include:

* `.exe`
* `.dll`
* `.ps1`
* `.bat`
* `.zip`
* `.rar`
* `.7z`

These file extensions are not inherently malicious, but they can be relevant during a security investigation.

---

## Step 8 – Investigate Authentication Activity

If login status information is available:

```spl
index=<ftp_index> sourcetype=ftp_sample
| stats count by user status
| sort - count
```

### Analyst Question

Are certain accounts experiencing an unusual number of failed login attempts?

Multiple failures followed by a successful login may be particularly interesting.

---

## Step 9 – Identify Potential Authentication Failures

The exact search depends on the fields available in the dataset.

For example:

```spl
index=<ftp_index> sourcetype=ftp_sample status="failed"
| stats count as failed_attempts by src_ip user
| sort - failed_attempts
```

### Analyst Interpretation

Repeated failed authentication attempts may indicate:

* User error
* Misconfigured applications
* Password changes
* Credential guessing
* Brute-force attempts

Additional context is required before classifying the activity as malicious.

---

## Step 10 – Analyze FTP Activity Over Time

```spl
index=<ftp_index> sourcetype=ftp_sample
| timechart span=5m count
```

This helps identify periods of unusually high FTP activity.

---

## Step 11 – Track Activity by Source IP

```spl
index=<ftp_index> sourcetype=ftp_sample
| timechart span=5m count by src_ip
```

### Analyst Question

Is one host responsible for a sudden spike in FTP activity?

If so, that host should become a priority for further analysis.

---

## Step 12 – Investigate a Specific Source

After identifying an unusual source IP:

```spl
index=<ftp_index> sourcetype=ftp_sample src_ip="<investigated_ip>"
| table _time src_ip user command filename status
| sort _time
```

### Analyst Interpretation

Reviewing the full timeline allows the analyst to reconstruct what the source did.

For example:

1. Authentication attempts
2. Directory navigation
3. File listing
4. File upload or download
5. Session termination

This sequence provides much more context than looking at isolated events.

---

# Investigation Example

An interesting pattern could be:

* Multiple failed login attempts
* Followed by a successful login
* Followed by `LIST`
* Followed by several `RETR` or `STOR` commands

This sequence would be more significant than any individual event alone.

The next step would be to determine whether the user and source IP were authorized to perform this activity.

---

# Findings

FTP logs provide visibility into both authentication and file movement.

During an investigation, individual indicators such as:

* High event volume
* Failed authentication
* File uploads
* File downloads

should not automatically be classified as malicious.

The analyst should instead combine them to understand the complete activity sequence.

---

# Detection Opportunities

Potential FTP detection ideas include:

* Multiple failed FTP authentication attempts
* Failed logins followed by successful authentication
* Unusual `STOR` activity
* Large numbers of file downloads
* Executable or script uploads
* FTP access from unusual source IPs
* Sudden spikes in FTP activity
* File transfer activity from accounts that do not normally use FTP

---

# Analyst Takeaway

The main lesson from this lab is that FTP analysis should focus on behavior sequences rather than isolated events.

For example:

**Failed login → Successful login → File access → File transfer**

provides much stronger investigative context than simply counting FTP events.

A SOC analyst should continuously ask:

**Who accessed the server, what did they do, what files were involved, and was that behavior expected?**

---

# Skills Practiced

* Splunk SPL
* FTP log analysis
* `stats`
* `sort`
* `head`
* `timechart`
* `table`
* Filtering
* Authentication analysis
* File-transfer investigation
* Timeline reconstruction
* SOC investigation methodology

---

## Screenshots

Recommended screenshots:

1. Raw FTP events
2. Most active source IPs
3. Most active FTP users
4. FTP command distribution
5. `STOR` activity
6. `RETR` activity
7. FTP activity timechart
8. Investigation timeline for one selected source

---

## Conclusion

FTP logs provide useful evidence about authentication, user behavior, and file movement.

By combining source IPs, users, commands, filenames, authentication results, and timestamps, a SOC analyst can reconstruct FTP activity and identify behavior that requires deeper investigation.

The goal is not to label individual events as malicious, but to build enough context to determine whether the overall activity is expected or suspicious.
