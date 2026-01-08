# comp3010-botsv3-analysis
Incident analysis report for BOTSv3 using Splunk – COMP3010 Security Operations &amp; Incident Management (70% Coursework).



1. Introduction

This report documents a professional Security Operations Centre (SOC)–style investigation conducted using the Boss of the SOC v3 (BOTSv3) dataset within Splunk Enterprise. BOTSv3 simulates a realistic multi-stage security incident affecting Frothly, a fictional cloud-enabled organisation operating AWS infrastructure and Windows endpoints.

The objective of this investigation is to demonstrate practical SOC workflows by identifying cloud misconfigurations, insecure access patterns, and endpoint anomalies through structured log analysis. The work aligns with COMP3010 learning outcomes by evidencing SOC roles, incident handling methodologies, and applied intrusion analysis using Splunk’s Search Processing Language (SPL).

The scope of this investigation focuses on:

AWS CloudTrail and S3 access logs

Windows endpoint monitoring telemetry

Detection of misconfiguration, insecure authentication, and system outliers

All findings are supported by reproducible SPL queries and screenshots.
