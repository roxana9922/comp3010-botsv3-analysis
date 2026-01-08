 
# comp3010-botsv3-analysis
Incident analysis report for BOTSv3 using Splunk – COMP3010 Security Operations &amp; Incident Management (70% Coursework).



## 1. Introduction

This report presents a Security Operations Centre (SOC)–style incident investigation using the Boss of the SOC v3 (BOTSv3) dataset within Splunk Enterprise. BOTSv3 simulates a realistic, multi-stage cyber incident affecting Frothly, a fictional cloud-enabled organisation operating AWS services and Windows endpoints.

The objective of this investigation is to demonstrate practical SOC workflows, including detection, investigation, and response to cloud misconfigurations, insecure authentication practices, and endpoint anomalies. The investigation assumes a centralised SOC environment with access to cloud, endpoint, and infrastructure logs.

This work aligns with the COMP3010 learning outcomes by evidencing SOC roles, incident handling methodologies, and applied intrusion analysis using Splunk’s Search Processing Language (SPL).

## 2. SOC Context and Incident Handling Reflection
Tier 1 SOC Analyst
Responsible for monitoring alerts and initial triage. In this scenario, Tier 1 would detect AWS API activity without MFA and identify unusual S3 bucket permission changes.

Tier 2 SOC Analyst
Responsible for in-depth investigation. Tier 2 would analyse AWS CloudTrail and S3 access logs to confirm public access misconfiguration, identify the affected S3 bucket, and assess data exposure risk.

Tier 3 / Incident Responder
Responsible for containment and remediation. This role would remove public S3 permissions, enforce MFA policies, and coordinate longer-term IAM and cloud security improvements.

          Incident Handling Lifecycle
The investigation follows a standard incident handling lifecycle:
Detection: Identification of AWS API calls without MFA and public S3 bucket access
Analysis: Correlation of CloudTrail, S3 access logs, and endpoint telemetry
Containment: Removal of public bucket permissions and access review
Eradication: Enforcement of MFA and correction of IAM policies
Recovery: Validation of secure cloud configuration
Lessons Learned: Review of cloud governance and monitoring gaps



## 3. Installation and Data Preparation

Splunk Enterprise was installed on an Ubuntu virtual machine following standard deployment procedures. The BOTSv3 dataset was downloaded from the official Splunk repository and ingested into Splunk using the provided configuration scripts.

Data ingestion was validated by confirming event counts across key source types, including aws:cloudtrail, aws:s3:accesslogs, and winhostmon. Time range consistency and field extraction were verified to ensure accurate querying.

This setup reflects a realistic SOC infrastructure where cloud and endpoint logs are centrally collected for investigation and correlation.

## 4. Methodology

A structured, question-driven methodology was applied to ensure the investigation was systematic, repeatable, and aligned with SOC best practices.
For each investigation task:
Relevant data sources were identified based on the question context
Focused SPL queries were constructed to extract meaningful security-relevant fields
Findings were validated using raw event inspection
Screenshots were captured to provide evidential support
Where applicable, results were correlated across multiple log sources
This methodology mirrors how SOC analysts investigate alerts, validate findings, and document incidents in operational environments.

## 5. Guided Investigation and Results

Objective: Identify AWS API activity occurring without MFA.
Data Source: aws:cloudtrail
Approach: Queried CloudTrail events excluding console logins and inspected MFA-related fields.
Finding: API calls were observed where MFA was not present, indicating a security weakness.
SOC Relevance: API activity without MFA increases the risk of credential abuse and requires immediate policy enforcement.
Evidence: See screenshots/Screenshot 2026-01-07 225610.png

## 6. Conclusion and Recommendations
This investigation demonstrates how a SOC can use Splunk to detect, analyse, and respond to cloud and endpoint security issues. By correlating AWS CloudTrail logs, S3 access logs, and Windows host telemetry, multiple security weaknesses were identified, including insecure authentication practices, public cloud storage exposure, and endpoint configuration inconsistencies.

Recommendations:

Enforce MFA for all AWS IAM users
Implement automated alerts for public S3 bucket access
Standardise endpoint configurations to reduce monitoring gaps
Conduct regular cloud security posture reviews
These improvements would strengthen detection capabilities and reduce the likelihood of future incidents.


## 7. References
[1] Splunk Inc., “Boss of the SOC v3 (BOTS v3),” GitHub repository.
[2] Amazon Web Services, “AWS CloudTrail log file examples,” AWS Documentation.
[3] Amazon Web Services, “PutBucketAcl – Amazon S3 API Reference,” AWS Documentation.
[4] Amazon Web Services, “PutObject – Amazon S3 API Reference,” AWS Documentation.
[5] Amazon Web Services, “How to enable and monitor MFA for AWS API activity,” AWS Documentation / Knowledge Center.



