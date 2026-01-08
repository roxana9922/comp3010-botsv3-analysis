 
# comp3010-botsv3-analysis
Incident analysis report for BOTSv3 using Splunk – COMP3010 Security Operations &amp; Incident Management (70% Coursework).



## 1. Introduction

This report presents a Security Operations Centre (SOC)–style incident investigation using the Boss of the SOC v3 (BOTSv3) dataset within Splunk Enterprise. BOTSv3 simulates a realistic, multi-stage cyber security incident affecting Frothly, a fictional cloud-enabled organisation operating Amazon Web Services (AWS) infrastructure and Windows-based endpoints.

The objective of this investigation is to demonstrate practical SOC workflows, including detection, investigation, and response to cloud misconfigurations, insecure authentication practices, and endpoint anomalies. The investigation assumes a centralised SOC environment with visibility across cloud, endpoint, and infrastructure telemetry.

This work aligns with the COMP3010 learning outcomes by evidencing SOC roles, incident handling methodologies, and applied intrusion analysis using Splunk’s Search Processing Language (SPL).

## 2. SOC Context and Incident Handling Reflection
SOC Roles Involved

In a real-world SOC environment, this incident would involve multiple analyst tiers working collaboratively:

Tier 1 SOC Analyst
Responsible for continuous monitoring and initial triage. In this scenario, Tier 1 analysts would identify suspicious AWS API activity, such as requests executed without multi-factor authentication (MFA) or unexpected S3 bucket permission changes.

Tier 2 SOC Analyst
Responsible for deeper technical investigation. Tier 2 analysts would analyse AWS CloudTrail and S3 access logs to confirm misconfigurations, identify affected assets, and assess the potential impact of exposure.

Tier 3 Analyst / Incident Responder
Responsible for containment, eradication, and remediation. This role would revoke public S3 access, enforce MFA policies, review IAM permissions, and coordinate longer-term corrective actions.

Incident Handling Lifecycle

The investigation follows a standard incident handling lifecycle:

Detection: Identification of AWS API activity without MFA and public S3 bucket exposure

Analysis: Correlation of CloudTrail events, S3 access logs, and endpoint telemetry

Containment: Removal of public bucket permissions and immediate access review

Eradication: Enforcement of MFA and correction of IAM and access control policies

Recovery: Validation of secure configuration and monitoring effectiveness

Lessons Learned: Review of cloud governance, monitoring gaps, and policy weaknesses

This demonstrates applied understanding of SOC operations rather than purely theoretical knowledge.



## 3. Installation and Data Preparation

Splunk Enterprise was installed on an Ubuntu virtual machine following standard deployment procedures. The BOTSv3 dataset was retrieved from the official Splunk repository and ingested using the provided configuration scripts.

Successful ingestion was validated by confirming event counts and field extraction across key source types, including:

aws:cloudtrail

aws:s3:accesslogs

winhostmon

Time range consistency and field normalisation were verified to ensure accurate querying and correlation. This setup reflects a realistic SOC architecture where cloud and endpoint telemetry is centrally collected for investigation.
## 4. Methodology

A structured, question-driven methodology was applied to ensure the investigation was systematic, repeatable, and aligned with SOC best practices.

For each investigation task:

Relevant data sources were identified based on the question context

Focused SPL queries were constructed to extract security-relevant fields

Findings were validated using raw event inspection

Screenshots were captured to provide evidential support

Where applicable, results were correlated across multiple log sources

This methodology mirrors how SOC analysts investigate alerts, validate findings, and document incidents in operational environments.


## 5. Guided Investigation and Results

This section presents the technical findings derived from the BOTSv3 guided questions. Each question addresses a specific aspect of cloud or endpoint security and demonstrates applied intrusion and anomaly analysis.

Question 2 – AWS API Activity Without MFA

Objective: Identify AWS API activity occurring without multi-factor authentication.
Data Source: aws:cloudtrail

Approach:
CloudTrail events were queried while excluding interactive console logins. MFA-related fields within the authentication context were inspected to identify API requests executed without MFA.

Finding:
Multiple AWS API calls were observed where MFA was not present, indicating a weakness in authentication enforcement.

SOC Relevance:
API activity without MFA significantly increases the risk of credential compromise and unauthorised access. In a production SOC, this would trigger high-priority alerts and immediate policy review.

Evidence:
screenshots/Screenshot 2026-01-07 225610.png

Question 3 – Processor Used on Web Servers

Objective: Identify the processor model used on the web servers.
Data Source: hardware

Finding and SOC Relevance:
Hardware inventory data allows SOC teams to understand endpoint baselines and detect abnormal configurations that may indicate unauthorised changes or unsupported systems.

Evidence:
screenshots/Screenshot 2026-01-07 230237.png

Questions 4–6 – S3 Bucket Public Access Misconfiguration

Objective: Identify the API call, user, and bucket involved in public S3 access.
Data Source: aws:cloudtrail

Finding and SOC Relevance:
A PutBucketAcl API call made by a specific IAM user resulted in public access being enabled on an S3 bucket. Public cloud storage exposure represents a critical misconfiguration that can lead to data leakage.

Evidence:
screenshots/Screenshot 2026-01-07 230906.png

Question 7 – File Uploaded While Bucket Was Public

Objective: Identify files uploaded while the S3 bucket was publicly accessible.
Data Source: aws:s3:accesslogs

Finding and SOC Relevance:
A text file was successfully uploaded during the window of public access, demonstrating real exposure risk rather than a theoretical misconfiguration.

Evidence:
screenshots/Screenshot 2026-01-07 231643.png

Question 8 – Endpoint Running a Different Windows Version

Objective: Identify the endpoint running a different Windows OS edition.
Data Source: winhostmon

Finding and SOC Relevance:
One endpoint was identified running a different Windows edition compared to other hosts. Endpoint inconsistency increases monitoring complexity and may indicate unmanaged or misconfigured systems.

Evidence:
screenshots/Screenshot 2026-01-07 233105.png





## 6. Conclusion and Recommendations
This investigation demonstrates how a SOC can use Splunk to detect, analyse, and respond to cloud and endpoint security issues. By correlating AWS CloudTrail logs, S3 access logs, and Windows host telemetry, multiple security weaknesses were identified, including insecure authentication practices, public cloud storage exposure, and endpoint configuration inconsistencies.

Recommendations

Enforce MFA for all AWS IAM users

Implement automated alerts for public S3 bucket access

Standardise endpoint configurations to reduce monitoring gaps

Conduct regular cloud security posture reviews

These controls would significantly strengthen detection capabilities and reduce the likelihood of future incidents.


## 7. References
[1] Splunk Inc., “Boss of the SOC v3 (BOTS v3),” GitHub repository.
[2] Amazon Web Services, “AWS CloudTrail log file examples,” AWS Documentation.
[3] Amazon Web Services, “PutBucketAcl – Amazon S3 API Reference,” AWS Documentation.
[4] Amazon Web Services, “PutObject – Amazon S3 API Reference,” AWS Documentation.
[5] Amazon Web Services, “How to enable and monitor MFA for AWS API activity,” AWS Documentation / Knowledge Center.



