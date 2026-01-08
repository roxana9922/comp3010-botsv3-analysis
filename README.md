 
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


## 4 Guided Questions
4.1 Question 1 – IAM Users Accessing AWS Services

o identify which IAM users interacted with AWS services, AWS CloudTrail logs were analysed within Splunk to extract all unique IAM usernames associated with API activity. Both successful and unsuccessful API calls were included to ensure a comprehensive view of identity usage across the environment.

The analysis was performed by filtering CloudTrail events for userIdentity.type=IAMUser and aggregating the userIdentity.userName field. This produced a consolidated list of IAM identities that generated AWS API activity, including human users, privileged accounts, and service accounts. The results confirm that the IAM users bstoll, btun, splunk_access, and web_admin accessed AWS services during the investigation period.

Identifying active IAM users is a foundational step in cloud incident investigations, as it establishes an identity baseline and enables analysts to detect anomalous access patterns, misuse of privileged accounts, or potential credential compromise. This approach reflects standard Tier 1 and Tier 2 SOC practices, where identity-based analysis is often the starting point for cloud security investigations.
<img width="523" height="419" alt="Screenshot 2026-01-08 124303" src="https://github.com/user-attachments/assets/8600a65d-daa1-4b39-8bb4-31bd88415ed1" />



  4.2.  Question 2 – AWS API Activity Without MFA

To determine how multi-factor authentication (MFA) usage is represented within the BOTSv3 dataset, AWS CloudTrail identity context fields were examined in Splunk. By reviewing the available fields associated with userIdentity, the field userIdentity.sessionContext.attributes.mfaAuthenticated was identified. This boolean field indicates whether MFA was used during an AWS API call.

The investigation confirmed that this field can be reliably used to detect and alert on AWS API activity performed without MFA. Filtering or alerting on events where mfaAuthenticated=false enables SOC analysts to identify potentially risky authentication behaviour, as API calls executed without MFA significantly increase the likelihood of credential misuse or compromise.

Monitoring MFA enforcement is a critical cloud security control and a common SOC detection use case. Since AWS access keys can be stolen, reused, or leaked, MFA provides an essential additional layer of protection. API activity occurring without MFA therefore represents a high-risk condition that should trigger immediate investigation or escalation within a SOC environment.

Answer: userIdentity.sessionContext.attributes.mfaAuthenticated

<img width="1118" height="852" alt="Screenshot 2026-01-07 225610" src="https://github.com/user-attachments/assets/bc88b041-1ad9-4ef2-a7e0-24d8817ee53c" />

4.3. Question 3 – Processor Model Identification

To identify the processor model used on the web servers, the BOTSv3 dataset was queried for hardware-related telemetry. Events with the hardware sourcetype were analysed, returning system specification records for the relevant hosts. Examination of the CPU fields within these events allowed the processor model to be identified.

Query:
index=botsv3 sourcetype="hardware"

The analysis showed that the web servers were consistently configured with the Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40 GHz, confirmed by hardware logs recorded on 20/08/2018 at 14:26:25.

SOC Relevance:
Hardware baselining supports effective asset management and incident scoping within a SOC. Consistent processor configurations reduce uncertainty during investigations, while deviations may indicate misconfiguration, unmanaged systems, or potential compromise. Incorporating hardware telemetry into SOC analysis strengthens visibility across the infrastructure and supports informed response decisions.

Evidence:
Processor identification evidence is provided in /evidence/Q3/Processor.png.

<img width="1276" height="898" alt="Screenshot 2026-01-07 230237" src="https://github.com/user-attachments/assets/63ce1917-6947-49f3-9690-aceab0d190f5" />

4.4. Questions 4–6 – S3 Bucket Public Access Misconfiguration

To determine how an Amazon S3 bucket became publicly accessible, AWS CloudTrail events were analysed to identify configuration changes affecting S3 access control. Events were ordered chronologically to isolate the initial misconfiguration responsible for exposing the bucket.

The investigation focused on the PutBucketAcl API call, which modifies S3 access control lists. Examination of the raw CloudTrail JSON revealed three critical attributes required to answer Questions 4–6:

Event ID, obtained from the eventID field

IAM user, extracted from userIdentity.userName

S3 bucket name, identified within requestParameters.bucketName

This approach reflects standard SOC practice when investigating cloud misconfigurations, where analysts rely on CloudTrail logs to attribute configuration changes and assess exposure risk.

SOC Relevance:
Misconfigured S3 access control lists are a common cause of cloud data exposure incidents. CloudTrail provides authoritative evidence of:

Who performed the configuration change

What resource was affected

When the change occurred

How access permissions were altered

Monitoring high-risk API actions such as PutBucketAcl enables early detection of accidental or malicious misconfigurations and reduces the window of exposure.

Question 4

What is the event ID of the API call that enabled public access?

Query:
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl"

Answer:
ab45689d-69cd-41e7-8705-5350402cf7ac

Timestamp:
20/08/2018 13:01:46

Evidence:
/evidence/Q4/eventid.png

Question 5

What is Bud’s username?

The IAM username associated with the PutBucketAcl event was extracted from the userIdentity.userName field.

Answer:
bstoll

Evidence:
/evidence/Q5/BudsUsername.png

Question 6

What is the name of the S3 bucket that was made publicly accessible?

The affected bucket name was identified from the requestParameters.bucketName field within the same CloudTrail event.

Answer:
frothlywebcode

Evidence:
/evidence/Q6/BucketName.png
<img width="1277" height="971" alt="Screenshot 2026-01-07 230906" src="https://github.com/user-attachments/assets/4ac38d07-9720-4489-8aa8-b235d396d256" />



4.5. Question 7 – File Uploaded While the S3 Bucket Was Publicly Accessible

To assess the impact of the S3 bucket misconfiguration, Amazon S3 access logs were analysed to identify activity occurring during the period when the bucket was publicly accessible. An initial broad search of the access logs returned a large volume of events, so the analysis was refined to focus specifically on object upload operations involving text files.

Filtering the logs for PUT requests and .txt file extensions significantly reduced the dataset, allowing the relevant upload event to be isolated. Inspection of the request path confirmed that a text file was successfully uploaded to the bucket while public access was enabled.

SOC Relevance:
This approach reflects standard SOC impact assessment procedures following cloud storage exposure. After identifying a misconfiguration, analysts must determine whether:

Files were uploaded or modified

Data was exfiltrated

The exposed resource was actively probed or abused

Targeted filtering of access logs enables analysts to quickly establish whether the incident represents a theoretical risk or a confirmed security impact.

Question 7

What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible?

Query:
index=botsv3 sourcetype="aws:s3accesslogs" frothlywebcode PUT txt

Timestamp:
20/08/2018 13:02:44

Answer:
OPEN_BUCKET_PLEASE_FIX.txt

Evidence:
/evidence/Q7/txtFile.png
<img width="1280" height="845" alt="Screenshot 2026-01-07 231643" src="https://github.com/user-attachments/assets/da3e0983-1828-49f6-bf08-57057591bdce" />

 4.6. Question 8 – Endpoint Running a Different Windows Operating System Edition

Endpoint telemetry from the winhostmon sourcetype was analysed to establish a baseline of operating system versions across Frothly’s Windows hosts. A deduplicated view of operating system editions per host was generated to identify inconsistencies within the environment.

This analysis revealed that one endpoint was running a different Windows edition compared to the rest of the infrastructure. While most hosts were operating on Microsoft Windows 10 Pro, the endpoint associated with user bstoll was running Microsoft Windows 10 Enterprise, indicating a deviation from the expected baseline.

To confirm the identity of the anomalous system, a secondary query was performed against Windows Security Event Logs for the identified host. This allowed the fully qualified domain name (FQDN) of the endpoint to be accurately determined.

Question 8

What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?

Queries:

index=botsv3 sourcetype="winhostmon" OS="*"

index=botsv3 host="bstoll-l" sourcetype="WinEventLog:Security"

Answer:
BSTOLL-L.froth.ly

Evidence:

/evidence/Q8/InitialSearch.png

/evidence/Q8/DifferentOS.png

/evidence/Q8/FQDN.png

SOC Analysis

Operating system inconsistencies represent a significant security concern within enterprise environments. Deviations from standardised endpoint builds may indicate unmanaged devices, configuration drift, or systems that have bypassed hardening and patching controls. In more advanced attack scenarios, threat actors may deliberately introduce or modify endpoint configurations to maintain persistence or evade detection.

The fact that the anomalous endpoint is associated with the same user responsible for the S3 bucket misconfiguration strengthens the overall incident narrative. From a SOC perspective, this correlation would warrant further investigation to determine whether poor security practices, privilege misuse, or compromise contributed to multiple control failures across cloud and endpoint domains.

Baseline monitoring of endpoint operating systems is therefore a critical control for maintaining visibility, enforcing compliance, and detecting early indicators of compromise.


<img width="1277" height="807" alt="Screenshot 2026-01-07 233105" src="https://github.com/user-attachments/assets/767f5ab0-e097-44aa-bde6-be6cbd823f6f" />



## 6. Conclusion

This investigation demonstrated a comprehensive Security Operations Centre (SOC)–level analysis using the BOTSv3 dataset within Splunk, covering AWS identity activity, cloud misconfigurations, S3 access patterns, and endpoint telemetry. By correlating multiple log sources, the analysis reconstructed a realistic incident scenario and highlighted how seemingly minor configuration errors can significantly increase organisational risk.

The investigation identified a critical cloud misconfiguration in which an Amazon S3 bucket was made publicly accessible by a legitimate IAM user. During the exposure window, a text file was successfully uploaded to the bucket, and AWS GuardDuty subsequently detected a known malicious external IP probing an exposed EC2 instance. Although no evidence of deeper compromise was identified within the defined scope, these findings clearly demonstrate how misconfigurations can attract malicious attention and escalate the likelihood of attack.

Key lessons learned from this investigation include:

AWS CloudTrail is a primary forensic data source for analysing identity-centric cloud security incidents.

Multi-factor authentication (MFA) enforcement for API activity is critical in mitigating credential misuse and unauthorised access.

Public S3 bucket misconfigurations remain one of the most common and impactful cloud security failures.

Cross-dataset correlation between CloudTrail, S3 access logs, GuardDuty alerts, and endpoint telemetry is essential for understanding attack scope and impact.

Endpoint baseline deviations, such as inconsistent operating system versions, may indicate unmanaged systems, configuration drift, or potential compromise.

The incident also highlighted weaknesses in Frothly’s preventative controls. The absence of enforced MFA, insufficient IAM governance, and inconsistent endpoint configurations increased the likelihood of accidental exposure caused by human error. From a SOC perspective, these gaps represent control failures rather than isolated technical mistakes.

Based on SOC incident handling methodologies aligned with Prevention, Detection, Response, and Recovery, the following recommendations are proposed:

Implement automated Splunk alerts for high-risk AWS API activity, including PutBucketAcl events and API calls executed without MFA.

Enforce MFA for all IAM users and API-level access without exception.

Apply AWS “Block Public Access” controls to all S3 buckets by default.

Standardise endpoint operating system builds and implement alerts for baseline deviations.

Conduct regular IAM privilege audits to enforce least-privilege access and reduce misuse risk.

Following incident containment, further actions should include reviewing the contents of affected cloud storage, scanning systems for malicious artefacts, and validating system integrity before restoring normal operations. Long-term prevention should focus on improving security awareness, reinforcing cloud security policies, and ensuring staff are trained to recognise and respond to incidents effectively.

Overall, this investigation demonstrates how SOC analysts transform raw telemetry into actionable security intelligence. By combining technical analysis with operational context and structured incident handling, the report reflects the analytical depth, methodological rigor, and professional reasoning expected in real-world SOC environments.
## 7. References
[1] IBM, “What is a Security Operations Center (SOC)?,” IBM Security, 2024. [Online]. Available: https://www.ibm.com/think/topics/security-operations-center
. Accessed: Jan. 6, 2026.
[2] Splunk Inc., “Boss of the SOC v3 (BOTSv3) Dataset,” Splunk GitHub, 2024. [Online]. Available: https://github.com/splunk/botsv3
. Accessed: Jan. 6, 2026.

[3] Splunk Inc., “Splunk Enterprise Documentation,” Splunk Docs, 2025. [Online]. Available: https://docs.splunk.com
. Accessed: Jan. 6, 2026.

[4] Canonical Ltd., “Ubuntu Desktop,” Ubuntu Documentation, 2019. [Online]. Available: https://ubuntu.com/download/desktop
. Accessed: Jan. 6, 2026.

[5] Amazon Web Services, “AWS CloudTrail Documentation,” AWS Documentation, 2025. [Online]. Available: https://docs.aws.amazon.com/cloudtrail
. Accessed: Jan. 6, 2026.

[6] Amazon Web Services, “Amazon GuardDuty Documentation,” AWS Documentation, 2025. [Online]. Available: https://docs.aws.amazon.com/guardduty
. Accessed: Jan. 6, 2026.

[7] Amazon Web Services, “AWS Identity and Access Management Best Practices,” AWS Documentation, 2025. [Online]. Available: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
. Accessed: Jan. 6, 2026.

[8] Amazon Web Services, “How to prevent Amazon S3 buckets from being publicly accessible,” AWS Knowledge Center, 2025. [Online]. Available: https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-public-access/
. Accessed: Jan. 6, 2026.

[9] NIST, Computer Security Incident Handling Guide (SP 800-61 Rev. 2), National Institute of Standards and Technology, 2012. [Online]. Available: https://nvlpubs.nist.gov
. Accessed: Jan. 6, 2026.

[10] CREST, “Cyber Security Incident Response Guide,” CREST, 2024. [Online]. Available: https://www.crest-approved.org
. Accessed: Jan. 6, 2026.

[11] SANS Institute, “SOC Tiering and Analyst Roles,” SANS White Papers, 2024. [Online]. Available: https://www.sans.org/white-papers/402/
. Accessed: Jan. 6, 2026.

[12] CrowdStrike, “Cloud Misconfigurations and Data Exposure,” CrowdStrike Blog, 2024. [Online]. Available: https://www.crowdstrike.com/blog/cloud-security-101-misconfigurations/
. Accessed: Jan. 6, 2026.

[13] Verizon, 2024 Data Breach Investigations Report, Verizon Enterprise, 2024. [Online]. Available: https://www.verizon.com/business/resources/reports/2024-dbir-data-breach-investigations-report.pdf
. Accessed: Jan. 6, 2026.
