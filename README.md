 
# comp3010-botsv3-analysis
Incident analysis report for BOTSv3 using Splunk – COMP3010 Security Operations &amp; Incident Management (70% Coursework).



## 1. Introduction

A Security Operations Centre (SOC) is responsible for the continuous monitoring, detection, analysis, and response to cybersecurity threats within an organisation [1]. The core objective of a SOC is to safeguard critical systems, data, and infrastructure by identifying malicious or abnormal activity at an early stage and coordinating an effective incident response. To support this function, SOC teams rely on Security Information and Event Management (SIEM) platforms, such as Splunk, which collect, normalise, and correlate large volumes of security telemetry from multiple sources in near real time. This centralised visibility improves situational awareness and enables analysts to detect anomalies, investigate incidents, and make evidence-based response decisions.

The Boss of the SOC version 3 (BOTSv3) dataset is a pre-generated security dataset designed to support Capture the Flag (CTF)–style cybersecurity training [2]. It simulates a realistic security incident affecting a fictional brewing organisation, Frothly, and contains log data from diverse sources including Amazon Web Services (AWS), endpoint systems, network infrastructure, and supporting services. The dataset requires analysts to reconstruct an attack timeline by analysing log evidence and applying established incident response practices, closely reflecting real-world SOC investigations.

The aim of this investigation is to analyse the BOTSv3 dataset using Splunk in order to answer the AWS- and endpoint-focused 200-level questions, reconstruct the sequence of security events, and produce a structured incident report that identifies weaknesses and proposes mitigation measures. The investigation is conducted using Splunk’s Search Processing Language (SPL) and focuses exclusively on cloud and endpoint telemetry. This constrained scope reflects standard SOC operating conditions, where analysts prioritise the most relevant data sources to improve detection efficiency and response times. Advanced activities such as malware reverse engineering are excluded, as they fall outside the responsibilities of SOC analysts during initial incident handling.

This investigation is based on several assumptions. It is assumed that the BOTSv3 log data is accurate, complete, and trustworthy; that timestamps are correctly recorded and synchronised; and that the dataset contains sufficient evidence to identify malicious or high-risk activity. These assumptions are consistent with the controlled nature of the BOTSv3 environment and allow the analysis to focus on operational decision-making and investigative methodology.


## 2.SOC Roles and Incident Handling
A Security Operations Centre (SOC) operates as a layered function designed to manage large volumes of security alerts while enabling effective investigation and response. Tiered SOC structures allow analysts to focus on tasks appropriate to their expertise, improving detection accuracy and reducing analyst fatigue. As noted by the SANS Institute (2024), tiering helps organisations balance alert volume with investigative depth, ensuring incidents are escalated efficiently and handled at the correct level.

Despite these benefits, tiered SOC models introduce operational challenges. High alert volumes can lead to alert fatigue, particularly at Tier 1, where analysts may deprioritise low-fidelity alerts and risk missing early indicators of compromise. Escalation gaps may occur if suspicious activity is not recognised or escalated promptly, delaying containment and increasing potential impact. In addition, resource constraints often limit full visibility across all telemetry sources, requiring risk-based prioritisation of alerts and data sources.

Tier 1: Monitoring, Triage, and Escalation

Tier 1 analysts are responsible for continuous monitoring of SIEM dashboards and alert queues. Their primary role is rapid triage rather than deep investigation. Analysts validate alerts, review basic contextual information such as user identity, source IPs, and affected resources, and determine whether events warrant escalation.

Within the BOTSv3 investigation, Tier 1 responsibilities are reflected in the identification of:

AWS API calls executed without multi-factor authentication (Question 2), indicating increased credential risk

PutBucketAcl events suggesting potential S3 bucket misconfiguration (Questions 4–6)

Endpoint anomalies, such as a host running an unexpected Windows edition (Question 8)

Effective Tier 1 escalation is critical to SOC maturity. Failure at this stage prevents Tier 2 analysts from performing timely root cause analysis, reducing the organisation’s ability to contain incidents quickly.

Tier 2: Investigation, Correlation, and Response

Tier 2 analysts conduct in-depth investigations of incidents escalated from Tier 1. Their work focuses on correlating multiple data sources, analysing root cause, assessing scope and impact, and recommending or executing response actions. As described by Palo Alto Networks (2024), Tier 2 analysts perform deeper analysis using contextual data and threat intelligence to validate and understand incidents.

In the BOTSv3 scenario, Tier 2 responsibilities include:

Enumerating IAM user activity to establish identity baselines (Question 1)

Identifying gaps in MFA enforcement

Tracing the full lifecycle of the S3 public access incident, from misconfiguration to data exposure

At this stage, analysts would typically implement containment actions such as revoking IAM credentials, correcting S3 access control lists, enforcing MFA policies, or isolating non-compliant endpoints.

Tier 3: Threat Hunting and Strategic Improvement

Tier 3 analysts focus on proactive security improvement rather than reactive investigation. Their responsibilities include threat hunting, SIEM detection engineering, and long-term security posture optimisation. By analysing incident trends, Tier 3 transforms operational findings into durable security controls and automated detections.

As highlighted by CrowdStrike (2024), Tier 3 analysts proactively search for advanced threats and assess weaknesses in existing controls. In the context of BOTSv3, this would include improving alerting for risky AWS API actions, strengthening cloud governance, and refining endpoint baselines to prevent similar incidents in the future.

Alignment with Incident Handling Frameworks

The BOTSv3 investigation aligns closely with the NIST SP 800-61 incident handling lifecycle:

Preparation: Installing Splunk, ingesting the BOTSv3 dataset, and validating relevant sourcetypes

Detection and Analysis: IAM enumeration, MFA validation, cloud misconfiguration analysis, and endpoint deviation detection

Containment and Recovery: Removing public S3 access, enforcing MFA, and correcting endpoint inconsistencies

Post-Incident Activity: Improving detection logic, strengthening governance, and refining security baselines

This alignment demonstrates how SOC analysts must pivot across identity logs, configuration changes, cloud storage access patterns, and endpoint telemetry to construct a coherent incident narrative. The investigation highlights the importance of SPL proficiency, awareness of cloud misconfiguration risks, and understanding of attacker behaviour—core competencies required in a modern, cloud-centric SOC.



## 3. Installation and Data Preparation

3.1 Splunk Setup

All analysis was conducted in a controlled virtual environment to safely investigate the BOTSv3 dataset. Splunk Enterprise was installed on an Ubuntu 24.04 virtual machine using the official installation package, reflecting a typical SOC analysis environment [3][4]. After installation, the Splunk service was started and access to the web interface was confirmed through the Search and Reporting application.

This setup provides isolation from production systems and mirrors real-world SOC practice, where analysts investigate security incidents within secured environments.

3.2 BOTSv3 Dataset Ingestion

The BOTSv3 dataset was downloaded from the official Splunk GitHub repository and deployed as a pre-indexed Splunk application. As a result, no manual parsing, field extraction, or index configuration was required. After restarting Splunk, the botsv3 index and its associated sourcetypes were immediately available.

This reflects standard enterprise SOC workflows, where log data is typically onboarded using vendor-supported applications, allowing analysts to focus on investigation rather than data engineering.

3.3 Data Validation

To verify successful ingestion, the following search was executed:

index=botsv3 earliest=0

<img width="1303" height="936" alt="Screenshot 2026-01-07 222615" src="https://github.com/user-attachments/assets/0f01f0d2-6351-41ef-95bd-f78798a1c898" />

The search returned over 100,000 events, confirming that the dataset was correctly indexed. Several events were reviewed in raw format to ensure key fields such as host, index, and sourcetype were properly parsed. The presence of expected sourcetypes confirmed that AWS and endpoint telemetry was available for investigation.

This validation step aligns with the preparation phase of incident handling, ensuring data integrity before analysis begins.

3.4 Justification of Setup

Using a virtualised Splunk environment provides full administrative control, isolates investigative activity from live systems, and supports realistic SIEM-based workflows. Logs are centralised and normalised, allowing analysts to focus on detection, correlation, and incident analysis rather than system configuration.
## 4. Methodology

A structured, question-driven methodology was applied to ensure the investigation was systematic, repeatable, and aligned with SOC best practices.

For each investigation task:

Relevant data sources were identified based on the question context

Focused SPL queries were constructed to extract security-relevant fields

Findings were validated using raw event inspection

Screenshots were captured to provide evidential support

Where applicable, results were correlated across multiple log sources

This methodology mirrors how SOC analysts investigate alerts, validate findings, and document incidents in operational environments.


## Guided Questions
4.1 Question 1 – IAM Users Accessing AWS Services

o identify which IAM users interacted with AWS services, AWS CloudTrail logs were analysed within Splunk to extract all unique IAM usernames associated with API activity. Both successful and unsuccessful API calls were included to ensure a comprehensive view of identity usage across the environment.

The analysis was performed by filtering CloudTrail events for userIdentity.type=IAMUser and aggregating the userIdentity.userName field. This produced a consolidated list of IAM identities that generated AWS API activity, including human users, privileged accounts, and service accounts. The results confirm that the IAM users bstoll, btun, splunk_access, and web_admin accessed AWS services during the investigation period.

Identifying active IAM users is a foundational step in cloud incident investigations, as it establishes an identity baseline and enables analysts to detect anomalous access patterns, misuse of privileged accounts, or potential credential compromise. This approach reflects standard Tier 1 and Tier 2 SOC practices, where identity-based analysis is often the starting point for cloud security investigations.
<img width="523" height="419" alt="Screenshot 2026-01-08 124303" src="https://github.com/user-attachments/assets/8600a65d-daa1-4b39-8bb4-31bd88415ed1" />



    Question 2 – AWS API Activity Without MFA

To determine how multi-factor authentication (MFA) usage is represented within the BOTSv3 dataset, AWS CloudTrail identity context fields were examined in Splunk. By reviewing the available fields associated with userIdentity, the field userIdentity.sessionContext.attributes.mfaAuthenticated was identified. This boolean field indicates whether MFA was used during an AWS API call.

The investigation confirmed that this field can be reliably used to detect and alert on AWS API activity performed without MFA. Filtering or alerting on events where mfaAuthenticated=false enables SOC analysts to identify potentially risky authentication behaviour, as API calls executed without MFA significantly increase the likelihood of credential misuse or compromise.

Monitoring MFA enforcement is a critical cloud security control and a common SOC detection use case. Since AWS access keys can be stolen, reused, or leaked, MFA provides an essential additional layer of protection. API activity occurring without MFA therefore represents a high-risk condition that should trigger immediate investigation or escalation within a SOC environment.

Answer: userIdentity.sessionContext.attributes.mfaAuthenticated

<img width="1118" height="852" alt="Screenshot 2026-01-07 225610" src="https://github.com/user-attachments/assets/bc88b041-1ad9-4ef2-a7e0-24d8817ee53c" />

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



