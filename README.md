# comp3010-botsv3-analysis
Incident analysis report for BOTSv3 using Splunk – COMP3010 Security Operations &amp; Incident Management (70% Coursework).



1. Introduction

This report presents a professional security investigation using the Boss of the SOC v3 (BOTSv3) dataset, a realistic, multi-source security telemetry environment designed by Splunk to emulate the operations of an enterprise-level Security Operations Centre (SOC). The scenario centres on Frothly, a fictional cloud-enabled organisation whose infrastructure includes AWS cloud services, Windows endpoints, and external-facing applications. The dataset contains thousands of logs across CloudTrail, S3 access logs, endpoint monitoring, and system activity—providing a representative environment for analysing adversary behaviours using Splunk’s Search Processing Language (SPL).

The objective of this investigation is to replicate SOC-level workflows by identifying suspicious AWS activity, misconfigurations, and endpoint anomalies through structured log analysis. This aligns directly with the module aims of COMP3010 by demonstrating:

How a SOC monitors cloud and endpoint telemetry

How analysts detect, triage, and investigate security alerts

How incident handling methodologies guide evidence-based security decisions

The scope of this report is limited to the AWS-focused 200-level question set from BOTSv3, reflecting real analyst tasks such as identifying IAM misuse, detecting S3 bucket misconfigurations, analysing CloudTrail logs for privilege escalation, and correlating cloud events with endpoint host anomalies. Supporting evidence is provided through SPL queries, result snapshots, and contextual analysis explaining the impact of each finding on incident handling.

This investigation assumes a functional Splunk deployment with the BOTSv3 dataset ingested and indexed. All work reflects practical SOC analysis and adheres to professional forensic reporting standards.


3. Methodology and SPL Investigation Approach

The investigation followed a structured, hypothesis-driven SOC analysis workflow. Rather than relying on single queries, each finding was validated through iterative SPL refinement and cross-source correlation.

For AWS-related analysis, CloudTrail logs (aws:cloudtrail) were used as the primary source to identify IAM activity, API calls without MFA, and S3 access control changes. SPL searches were constructed to filter by eventName, userIdentity fields, and error codes to distinguish successful versus unsuccessful actions. Where necessary, console login events were excluded to reduce noise and focus on programmatic access risks.

S3 access logs (aws:s3:accesslogs) were then correlated with CloudTrail findings to confirm whether misconfigurations led to real data exposure, such as successful object uploads during periods of public access. HTTP status codes and request types were used to validate outcomes.

Endpoint analysis leveraged winhostmon and hardware-related source types to identify host-level anomalies. Aggregation functions and comparative statistics were applied to detect deviations in operating system editions across endpoints, allowing identification of an outlier host by FQDN.

This approach reflects professional SOC investigation practice, where alerts are treated as starting points and conclusions are only drawn after corroborating evidence across multiple telemetry sources.
2. SOC Roles & Incident Handling Reflection

Security Operations Centres (SOCs) operate through a tiered model that enables efficient detection, investigation and escalation of security events. In a real environment—mirrored by the BOTSv3 scenario—each SOC tier contributes differently to preventing, detecting, responding to, and recovering from incidents.

Tier 1 – Alert Monitoring
Tier 1 analysts perform initial triage by monitoring dashboards and automated alerts. In the context of BOTSv3, they would identify unusual AWS CloudTrail events such as unauthorised IAM access, API calls without MFA, or sudden S3 bucket ACL changes. Their responsibility is to classify severity, escalate suspicious activity, and ensure continuous situational awareness.

Tier 2 – Incident Investigation
Tier 2 analysts conduct deeper forensic investigation using Splunk SPL queries. They correlate logs across AWS CloudTrail, S3 access logs, and Windows endpoint telemetry. In this coursework, the AWS 200-level questions reflect Tier 2 duties: identifying the IAM user responsible, determining which S3 bucket became public, analysing uploaded object metadata, and linking cloud events with endpoint host anomalies.

Tier 3 – Threat Hunting & Advanced Response
Tier 3 analysts validate whether the activity is part of a broader attack lifecycle, map findings to the MITRE ATT&CK framework, and recommend long-term mitigation. For BOTSv3, this includes evaluating whether public S3 buckets introduce exfiltration paths, detecting potential credential compromise, and determining whether unusual Windows OS variations indicate persistence techniques.

Incident Handling Methodology (NIST 800-61)
This investigation follows the NIST incident response lifecycle:

Preparation: Splunk installation, dataset ingestion, account configuration

Detection & Analysis: Identifying anomalies in CloudTrail and endpoint logs

Containment: Addressing misconfigured buckets, revoking IAM keys

Eradication & Recovery: Enforcing MFA, IAM least privilege, secure ACLs

Post-Incident Activity: Documentation, lessons learned, SOC workflow improvements

This structured methodology shows how SOC teams transform raw logs into actionable intelligence—exactly what BOTSv3 is designed to teach.




