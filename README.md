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
2 Purpose
This section explains how a real Security Operations Centre (SOC) would handle the BOTSv3 incident. The goal is to demonstrate that you understand roles, responsibilities, and incident workflows, not just Splunk queries.
SOC roles involved in this investigation

In a real-world SOC, this incident would involve multiple roles working together:

Tier 1 SOC Analyst
Responsible for initial alert monitoring and triage. A Tier 1 analyst would identify suspicious AWS activity, such as API calls without MFA or public S3 bucket exposure.

Tier 2 SOC Analyst
Responsible for deeper investigation. This role would analyse CloudTrail and S3 access logs to confirm misconfigurations, identify affected assets, and assess potential impact.

Tier 3 / Incident Responder
Responsible for containment and remediation. This role would revoke public access to the S3 bucket, enforce MFA policies, and coordinate long-term corrective actions.
Incident handling lifecycle
The investigation aligns with standard incident handling phases:
Detection – Identification of AWS API activity without MFA and public S3 bucket exposure
Analysis – Correlation of CloudTrail, S3 access logs, and endpoint telemetry
Containment – Remov
al of public bucket permissions and access review
Eradication – Enforcement of MFA and correction of IAM policies
Recovery – Validation of secure configuration
Lessons learned – Review of cloud governance and monitoring gaps
This demonstrates applied understanding of SOC operations rather than theoretical knowledge.



3. Methodology
 The methodology section explains how the investigation was performed and why the chosen tools and data sources were appropriate. This section is critical for 60%+ marks, as it proves your work is systematic and reproducible.

Tools used
The following tools and platforms were used:
Splunk Enterprise – Used for log ingestion, searching, correlation, and analysis
BOTSv3 dataset – Provided realistic, multi-source security telemetry
AWS CloudTrail logs – Used to analyse AWS API activity and authentication behaviour
AWS S3 access logs – Used to identify object-level access and file uploads
Windows host monitoring (winhostmon) – Used to identify endpoint configuration differences

Analytical approach

A structured, question-driven approach was used throughout the investigation:
Identify relevant data sources based on the question context
Construct focused SPL queries to extract meaningful fields
Validate findings using raw event data
Capture screenshots as evidence
Correlate findings across multiple log sources where applicable

This approach mirrors how SOC analysts conduct real incident investigations.

4. Guided Investigation
This section documents the technical investigation results and directly supports ALO 3 (intrusion and anomaly analysis). Each question demonstrates a different aspect of SOC analysis.

5. Conclusion
This investigation demonstrated how a Security Operations Centre can use Splunk to detect, analyse, and respond to cloud and endpoint security issues. By analysing AWS CloudTrail, S3 access logs, and Windows host telemetry, multiple security weaknesses were identified, including insecure authentication practices, public cloud storage exposure, and endpoint configuration inconsistencies.

The investigation highlights the importance of correlating multiple data sources to gain full situational awareness during incident response.




Lessons learned and recommendations

Key lessons from this investigation include:
MFA enforcement is essential for all AWS IAM users to reduce the risk of credential compromise
Public S3 bucket access should be continuously monitored using automated alerts
Endpoint standardisation simplifies monitoring and reduces security blind spots
Cloud misconfigurations can lead to immediate exploitation, not just theoretical risk
In a production environment, these findings would justify stronger governance controls, automated detection rules, and regular security posture reviews.

All evidence included in this repository was generated directly from Splunk Enterprise
during hands-on analysis of the BOTSv3 dataset. Screenshots correspond directly to
the answers submitted in the COMP3010 coursework quiz.



References
[1] Splunk Inc., “Boss of the SOC v3 (BOTS v3),” GitHub repository.
[2] Amazon Web Services, “AWS CloudTrail log file examples,” AWS Documentation.
[3] Amazon Web Services, “PutBucketAcl – Amazon S3 API Reference,” AWS Documentation.
[4] Amazon Web Services, “PutObject – Amazon S3 API Reference,” AWS Documentation.
[5] Amazon Web Services, “How to enable and monitor MFA for AWS API activity,” AWS Documentation / Knowledge Center.
