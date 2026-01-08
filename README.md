 
# comp3010-botsv3-analysis
Incident analysis report for BOTSv3 using Splunk – COMP3010 Security Operations &amp; Incident Management (70% Coursework).



## 1. Introduction

The Security Operations Centre (SOC) monitors information systems and identifies any security threats that impact an organisation, providing coordinated responses to digital threats. With security monitoring technologies, trained analysts, and standardised incident management processes, SOCs enable organisations to maintain situational awareness across their cloud, network, and endpoint environments.

This report presents an incident investigation using the Boss of the SOC v3 (BOTSv3) dataset, a realistic security simulation developed by Splunk. The dataset represents a fictional organisation named Frothly and includes a wide range of security telemetry such as AWS CloudTrail logs, S3 access logs, Windows endpoint data, and network activity. Together, these data sources simulate a complex security incident involving cloud misconfiguration and suspicious access behaviour.

The objective of this investigation is to replicate SOC-level workflows by analysing BOTSv3 data within Splunk using Search Processing Language (SPL). The analysis focuses on identifying unauthorised AWS activity, detecting misconfigured cloud resources, and examining endpoint-related anomalies. Each finding is supported by Splunk queries, outputs, and screenshots to demonstrate practical application of incident analysis techniques.

This report also reflects on SOC roles and incident handling methodologies, linking technical findings to detection, response, and recovery phases. The scope is limited to one set of BOTSv3 200-level guided questions. The report is structured to first outline SOC context, followed by Splunk setup and data preparation, detailed analysis with evidence, and a concluding reflection on lessons learned and improvements to SOC operations.


## 2. SOC Roles and Incident Handling

A Security Operations Centre (SOC) operates through clearly defined analyst tiers and structured incident handling processes to ensure timely detection, investigation, and response to cybersecurity incidents. Each tier supports a specific stage of the incident lifecycle, enabling efficient escalation, accurate analysis, and informed decision-making within a high-volume security monitoring environment.

### SOC Analyst Tiers and BOTSv3 Mapping

| SOC Tier | Primary Responsibilities | BOTSv3 Application |
|---------|--------------------------|--------------------|
| **Tier 1 – Monitoring & Triage** | Continuous monitoring of SIEM dashboards, alert validation, false positive reduction, and escalation of suspicious activity | Identification of anomalous AWS API activity, unusual S3 access events, and endpoint alerts using Splunk searches |
| **Tier 2 – Investigation & Analysis** | In-depth investigation, multi-source correlation, root cause analysis, and impact assessment | Correlation of AWS CloudTrail logs, S3 access logs, and endpoint telemetry to reconstruct the attack timeline and assess exposure |
| **Tier 3 – Response & Improvement** | Advanced analysis, containment planning, remediation strategy, and detection optimisation | Interpretation of investigation findings to propose IAM hardening, cloud misconfiguration alerts, and SOC detection improvements |


### Incident Handling Lifecycle Alignment

| Incident Phase | BOTSv3 Evidence |
|----------------|----------------|
| **Detection** | Identification of AWS API activity without MFA and S3 ACL changes using Splunk searches |
| **Analysis** | Correlation of CloudTrail, S3 access logs, and endpoint data to determine scope and impact |
| **Containment (Conceptual)** | Identification of required actions such as removing public S3 access and enforcing MFA |
| **Post-Incident Review** | Recommendations for improved detection logic, IAM governance, and cloud security posture |

Overall, this investigation shows how structured SOC roles and disciplined incident handling methodologies translate into effective operational workflows. By leveraging centralised visibility and query-driven analysis, SOC teams can transform raw telemetry into actionable intelligence and continuously improve detection and response capabilities.




## 3. Installation and Data Preparation

### 3.1 Splunk Setup

To conduct the BOTSv3 investigation, Splunk Enterprise was deployed on an Ubuntu virtual machine to simulate a SOC analysis environment. Splunk was installed using the official Splunk Enterprise installer and configured to run locally on port 8000. Following installation, the Splunk service was started successfully, and the web interface was accessed via a browser to confirm operational status.

During the initial setup, the Splunk license agreement was accepted, and default administrative credentials were configured. The Splunk instance was verified by confirming access to the Search & Reporting application and ensuring that search functionality was operational. This setup provided a stable foundation for ingesting and analysing large-scale security telemetry, consistent with SOC operational practices.<img width="1129" height="892" alt="Screenshot 2026-01-07 215557" src="https://github.com/user-attachments/assets/2862c3f2-19d7-4670-b43c-13f26cd9287e" />



### 3.2 BOTSv3 Dataset Ingestion

The Boss of the SOC v3 (BOTSv3) dataset was ingested into Splunk following the official dataset documentation. The dataset was extracted locally and indexed into Splunk using the predefined botsv3 index to ensure consistent querying and analysis.

Once ingestion was completed, validation searches were performed to confirm that data had been indexed correctly and that expected source types were available. A broad search across the botsv3 index confirmed the presence of millions of events, indicating successful ingestion. Additional validation queries were used to identify available sourcetypes, including AWS CloudTrail logs, S3 access logs, endpoint monitoring data, DNS logs, and host-based telemetry.

These validation steps are critical in a SOC environment, as incomplete or misconfigured data ingestion can lead to missed detections or inaccurate analysis. By verifying data availability and coverage before proceeding, confidence was established that subsequent investigative queries were based on reliable telemetry.<img width="1261" height="905" alt="Screenshot 2026-01-07 224817" src="https://github.com/user-attachments/assets/182f9017-5685-4a47-a79a-89cda377e588" />

<img width="1223" height="965" alt="Screenshot 2026-01-07 224915" src="https://github.com/user-attachments/assets/437c80a5-8a6c-4a80-97e5-5196431c3a1d" />


### 3.3 Data Validation

To ensure readiness for investigation, multiple exploratory searches were conducted across different data sources. These searches confirmed that key datasets required for answering the BOTSv3 guided questions were present and queryable. Endpoint-related data, AWS audit logs, and access records were all accessible within Splunk, allowing correlation across cloud and host-level activity.

This validation phase reflects standard SOC operational practice, where analysts confirm data completeness and visibility before engaging in detailed incident analysis. With ingestion and validation completed, the environment was deemed suitable for answering the BOTSv3 200-level questions and supporting evidence-based incident investigation.

<img width="1303" height="936" alt="Screenshot 2026-01-07 222615" src="https://github.com/user-attachments/assets/0f01f0d2-6351-41ef-95bd-f78798a1c898" />


### 3.4 Justification of Setup

The chosen setup was designed to reflect realistic SOC operational workflows while supporting accurate and efficient incident analysis. Deploying Splunk within a virtualised Ubuntu environment provides full administrative control, isolates investigative activity from production systems, and ensures a reproducible analysis environment.

Using Splunk Enterprise as the SIEM platform enables centralised log collection, normalisation, and correlation across multiple data sources, including cloud and endpoint telemetry. The creation of a dedicated botsv3 index improves search performance and prevents cross-contamination with other datasets, reflecting best practice in enterprise SOC environments.

Additionally, the use of structured validation queries and documented evidence screenshots supports traceability and reproducibility of findings. This approach aligns with professional SOC reporting standards, where analysts are expected to justify conclusions using verifiable evidence. Overall, the selected configuration supports the learning objectives of COMP3010 by enabling methodical, evidence-driven security analysis consistent with real-world incident response practices.

## 4 Guided Questions
4.1 Question 1 – IAM Users Accessing AWS Services

**Purpose** 
The objective of this analysis was to identify all IAM users that interacted with AWS services within the Frothly environment. Both successful and unsuccessful API calls were included to establish a complete identity baseline.

**Method**
AWS CloudTrail logs were analysed in Splunk by filtering events where userIdentity.type=IAMUser. The userIdentity.userName field was aggregated to extract a unique list of IAM identities responsible for AWS API activity across the environment.

<img width="523" height="419" alt="Screenshot 2026-01-08 124303" src="https://github.com/user-attachments/assets/8600a65d-daa1-4b39-8bb4-31bd88415ed1" />

**Result** 
The following IAM users were observed accessing AWS services during the investigation period:

**Answer:** bstoll, btun, splunk_access, web_admin

**SOC Relevance**
Identity-based analysis is a foundational SOC activity in cloud investigations. Establishing which IAM users are active enables analysts to detect anomalous access patterns, misuse of privileged accounts, and potential credential compromise. This activity typically forms part of Tier 1 alert triage and Tier 2 investigation workflows within a SOC.



  4.2.  Question 2 – AWS API Activity Without MFA

**Purpose**
The objective of this analysis was to identify the CloudTrail field that indicates whether multi-factor authentication (MFA) was used during AWS API activity, enabling detection of API calls performed without MFA.

**Method**  
AWS CloudTrail identity context fields were examined in Splunk by reviewing attributes associated with the userIdentity object. Particular attention was given to session context metadata that records authentication characteristics for API requests. This analysis identified the userIdentity.sessionContext.attributes.mfaAuthenticated field as the indicator of MFA usage.

<img width="1118" height="852" alt="Screenshot 2026-01-07 225610" src="https://github.com/user-attachments/assets/bc88b041-1ad9-4ef2-a7e0-24d8817ee53c" />

**Result** 
The field used to determine whether MFA was applied during an AWS API call is:

**Answer:** userIdentity.sessionContext.attributes.mfaAuthenticated

**SOC Relevance**  
Monitoring AWS API activity without MFA is a critical SOC detection use case. API calls executed without MFA significantly increase the risk of credential misuse, particularly if access keys are compromised or leaked. In operational SOC environments, events where mfaAuthenticated=false would typically trigger alerting, escalation, or further investigation, especially for privileged IAM users or sensitive services. Continuous monitoring of this field supports enforcement of strong identity controls and reduces the likelihood of cloud account compromise. 




4.3. Question 3 – Processor Model Identification

**Purpose**
The objective of this analysis was to identify the processor model used by Frothly’s web servers in order to establish a baseline of underlying hardware characteristics within the environment.

**Method**  
Hardware telemetry within the BOTSv3 dataset was analysed by querying events with the hardware sourcetype. These events contain system specification data, including CPU details, for hosts within the infrastructure. Relevant CPU fields were examined to determine the processor model used by the web servers.

Query

index=botsv3 sourcetype="hardware"

<img width="1276" height="898" alt="Screenshot 2026-01-07 230237" src="https://github.com/user-attachments/assets/63ce1917-6947-49f3-9690-aceab0d190f5" />

**Result** 
The analysis showed that the web servers were consistently configured with the following processor:

**Answer:** Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40 GHz
Observed timestamp: 20/08/2018 14:26:25

**SOC Relevance**  
Hardware baselining is an important component of SOC asset management and incident scoping. Consistent processor configurations across servers indicate standardised builds and reduce uncertainty during investigations. Conversely, unexpected hardware deviations may suggest misconfiguration, unmanaged assets, or potential compromise. Incorporating hardware telemetry into SOC analysis enhances infrastructure visibility and supports informed response and remediation decisions.


4.4. Questions 4–6 – S3 Bucket Public Access Misconfiguration

**Purpose**  
The objective of this analysis was to determine how an Amazon S3 bucket became publicly accessible, identify the IAM user responsible for the change, and establish which resource was affected.

**Method** 
AWS CloudTrail logs were analysed in Splunk to identify configuration changes related to S3 access control. Events were reviewed chronologically to isolate the initial action that enabled public access. The investigation focused on the PutBucketAcl API call, which modifies S3 bucket access control lists (ACLs).

Inspection of the raw CloudTrail JSON revealed three key fields required to answer Questions 4–6:

Event ID (eventID) to uniquely identify the configuration change

IAM username (userIdentity.userName) to attribute responsibility

S3 bucket name (requestParameters.bucketName) to identify the affected resource

This approach reflects standard SOC investigative practice when analysing cloud misconfigurations, where attribution and impact assessment are derived from authoritative audit logs.

Query

index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl"

<img width="1277" height="971" alt="Screenshot 2026-01-07 230906" src="https://github.com/user-attachments/assets/4ac38d07-9720-4489-8aa8-b235d396d256" />



Question 4 – Event ID of the API Call
Answer: ab45689d-69cd-41e7-8705-5350402cf7ac
Timestamp: 20/08/2018 13:01:46
Evidence: /evidence/Q4/eventid.png

Question 5 – IAM Username
The IAM username associated with the PutBucketAcl event was extracted from the userIdentity.userName field.
Answer: bstoll
Evidence: /evidence/Q5/BudsUsername.png

Question 6 – S3 Bucket Name
The affected S3 bucket name was identified from the requestParameters.bucketName field within the same CloudTrail event.
**Answer:**  frothlywebcode
Evidence: /evidence/Q6/BucketName.png

**SOC Relevance** 
Misconfigured S3 access controls are a common cause of cloud data exposure incidents. CloudTrail provides authoritative evidence that allows SOC analysts to determine who made a configuration change, what resource was affected, when the change occurred, and how permissions were modified. Monitoring high-risk API actions such as PutBucketAcl enables early detection of accidental or malicious misconfigurations, reducing exposure time and potential impact.


4.5. Question 7 – File Uploaded While the S3 Bucket Was Publicly Accessible
**Purpose**  
The objective of this analysis was to determine whether the publicly accessible S3 bucket was actively used during the exposure window, thereby establishing whether the misconfiguration resulted in a confirmed security impact.

**Method**  
Amazon S3 access logs were analysed in Splunk to identify activity occurring while public access was enabled. An initial broad search of the access logs returned a high volume of events, so the analysis was refined to focus on object upload operations. Filtering was applied for PUT requests and .txt file extensions to isolate successful upload events.

Query

index=botsv3 sourcetype="aws:s3accesslogs" frothlywebcode PUT txt

<img width="1280" height="845" alt="Screenshot 2026-01-07 231643" src="https://github.com/user-attachments/assets/da3e0983-1828-49f6-bf08-57057591bdce" />

**Result**
The analysis confirmed that a text file was successfully uploaded to the S3 bucket while public access was enabled.

**Answer:** OPEN_BUCKET_PLEASE_FIX.txt
Timestamp: 20/08/2018 13:02:44

**SOC Relevance** 
This analysis reflects standard SOC impact assessment procedures following cloud storage exposure. After identifying a misconfiguration, analysts must determine whether the issue represents a theoretical risk or a confirmed security incident. Analysing access logs allows SOC teams to establish whether files were uploaded or modified, whether exposed resources were actively abused, and whether further containment or remediation actions are required.





 4.6 Question 8 – Endpoint Running a Different Windows Operating System Edition

**Purpose** 
The objective of this analysis was to identify any Windows endpoint operating with a different OS edition than the established baseline, and to determine the fully qualified domain name (FQDN) of the anomalous system.

**Method** 
Endpoint telemetry from the winhostmon sourcetype was analysed to establish a baseline of Windows operating system editions across Frothly’s hosts. A deduplicated comparison of OS editions per host was performed to identify inconsistencies.
Once an anomalous host was identified, a secondary query against Windows Security Event Logs was used to confirm host identity and determine the FQDN.

Queries

index=botsv3 sourcetype="winhostmon" OS="*"
index=botsv3 host="bstoll-l" sourcetype="WinEventLog:Security"


<img width="1277" height="807" alt="Screenshot 2026-01-07 233105" src="https://github.com/user-attachments/assets/767f5ab0-e097-44aa-bde6-be6cbd823f6f" />

**Result**  
The analysis revealed a single endpoint operating with a different Windows edition than the rest of the environment. While the majority of hosts were running Microsoft Windows 10 Pro, the endpoint associated with user bstoll was running Microsoft Windows 10 Enterprise.

**Answer:**  BSTOLL-L.froth.ly

**SOC Relevance**  
Operating system inconsistencies represent a significant security concern in enterprise environments. Deviations from standardised endpoint builds may indicate unmanaged devices, configuration drift, or systems that have bypassed hardening and patching controls. In more advanced attack scenarios, threat actors may intentionally alter endpoint configurations to maintain persistence or evade detection.

Notably, the anomalous endpoint is associated with the same user responsible for the S3 bucket access control misconfiguration identified earlier in the investigation. From a SOC perspective, this correlation strengthens the overall incident narrative and would warrant escalation for deeper investigation into potential privilege misuse, poor security practices, or account compromise across both cloud and endpoint domains.

Baseline monitoring of endpoint operating systems is therefore a critical SOC control for maintaining asset visibility, enforcing configuration compliance, and detecting early indicators of compromise.

### 4.7 Investigation Summary (Cross-source Correlation)

Across CloudTrail, S3 access logs, and endpoint telemetry, the investigation identifies a high-risk cloud misconfiguration (`PutBucketAcl`) that exposed the `frothlywebcode` bucket. S3 access logs confirm real-world impact via a successful upload during the exposure window (`OPEN_BUCKET_PLEASE_FIX.txt`). Endpoint baselining further highlights OS edition deviation on `BSTOLL-L`, associated with the same user implicated in the S3 ACL change, warranting escalation for deeper identity and endpoint review.


### 4.8 SOC Escalation and Response Implications

| SOC Stage                             | Evidence Observed (BOTSv3)                                                                                    | SOC Decision & Action                                                                                           |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Tier 1 – Detection & Triage**       | CloudTrail logs showing AWS API activity without MFA and S3 permission changes (`PutBucketAcl`)               | Alert validated as suspicious cloud activity and escalated due to increased credential and data exposure risk   |
| **Tier 2 – Investigation & Analysis** | Correlation of CloudTrail, S3 access logs, and endpoint telemetry confirming public S3 access and file upload | Incident confirmed; scope, attribution, and impact assessed across cloud and endpoint domains                   |
| **Confirmed Impact**                  | S3 access logs showing successful upload of `OPEN_BUCKET_PLEASE_FIX.txt` during exposure window               | Incident classified as a verified security breach rather than a theoretical misconfiguration                    |
| **Containment (Conceptual)**          | Evidence of misconfiguration and identity misuse                                                              | Recommended actions: remove public S3 ACLs, enforce MFA, rotate affected credentials, review IAM permissions    |
| **Tier 3 – Response & Improvement**   | Findings from cloud and endpoint correlation                                                                  | Detection improvements proposed: MFA enforcement alerts, S3 ACL monitoring, endpoint baseline compliance checks |


## 5. Video Presentation (10 minutes)

**YouTube:** 
In the presentation, I demonstrate:
- Splunk environment setup confirmation and data validation
- Key SPL queries used to answer the 200-level questions
- Evidence review for the S3 misconfiguration and confirmed upload
- SOC reflection: triage → investigation → containment recommendations


## 6. Conclusion

This investigation demonstrated how a Security Operations Centre (SOC) can effectively detect, analyse, and contextualise security incidents by correlating cloud and endpoint telemetry using Splunk. Through structured analysis of the BOTSv3 dataset, multiple security weaknesses were identified, including unsafe IAM practices, AWS API activity without multi-factor authentication, a critical S3 bucket access misconfiguration, and endpoint configuration inconsistencies.

The investigation established a clear incident narrative beginning with identity-based analysis of AWS API usage, followed by the identification of a publicly accessible S3 bucket caused by an improper access control change. Subsequent analysis confirmed that the misconfiguration resulted in confirmed impact, evidenced by the successful upload of a file during the exposure window. Endpoint analysis further revealed configuration drift on a system associated with the same user responsible for the cloud misconfiguration, strengthening the case for escalation within a real SOC environment.

From an operational perspective, this exercise highlights the importance of centralised logging, continuous monitoring, and effective correlation across cloud and endpoint domains. CloudTrail logs provided authoritative attribution of configuration changes, while S3 access logs and endpoint telemetry enabled impact assessment and environment-wide baselining. Together, these data sources illustrate how SOC teams can transition from alert detection to evidence-based decision-making.

The findings reinforce several key SOC lessons: the necessity of enforcing MFA for all AWS API access, the need for continuous monitoring of high-risk cloud configuration changes, and the value of maintaining standardised endpoint builds. Implementing preventative controls such as automated alerts for PutBucketAcl events, stricter IAM privilege management, and baseline compliance monitoring would significantly reduce the likelihood and impact of similar incidents.

Overall, the BOTSv3 investigation provided practical insight into real-world SOC workflows, demonstrating how disciplined incident handling, clear role separation, and data-driven analysis support effective security operations. The skills applied throughout this investigation reflect industry-standard practices and directly align with the learning objectives of COMP3010.
## 🤖 AI Usage Declaration

AI was used only for writing support (grammar and clarity).  
All technical analysis and investigation were completed independently.
<img width="883" height="729" alt="Screenshot 2026-01-08 211035" src="https://github.com/user-attachments/assets/1f9ad69f-5685-420d-981d-e64306e1113a" />



## 7. References
[1] IBM, “What is a Security Operations Center (SOC)?,” IBM Security, 2024. [Online]. Available: https://www.ibm.com/think/topics/security-operations-center
. Accessed: Jan. 7, 2026.
[2] Splunk Inc., “Boss of the SOC v3 (BOTSv3) Dataset,” Splunk GitHub, 2024. [Online]. Available: https://github.com/splunk/botsv3
. Accessed: Jan. 7, 2026.

[3] Splunk Inc., “Splunk Enterprise Documentation,” Splunk Docs, 2025. [Online]. Available: https://docs.splunk.com
. Accessed: Jan. 7, 2026.

[4] Canonical Ltd., “Ubuntu Desktop,” Ubuntu Documentation, 2019. [Online]. Available: https://ubuntu.com/download/desktop
. Accessed: Jan. 7, 2026.

[5] Amazon Web Services, “AWS CloudTrail Documentation,” AWS Documentation, 2025. [Online]. Available: https://docs.aws.amazon.com/cloudtrail
. Accessed: Jan. 7, 2026.

[6] Amazon Web Services, “Amazon GuardDuty Documentation,” AWS Documentation, 2025. [Online]. Available: https://docs.aws.amazon.com/guardduty
. Accessed: Jan. 6, 2026.

[7] Amazon Web Services, “AWS Identity and Access Management Best Practices,” AWS Documentation, 2025. [Online]. Available: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
. Accessed: Jan. 7, 2026.

[8] Amazon Web Services, “How to prevent Amazon S3 buckets from being publicly accessible,” AWS Knowledge Center, 2025. [Online]. Available: https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-public-access/
. Accessed: Jan. 6, 2026.

[9] NIST, Computer Security Incident Handling Guide (SP 800-61 Rev. 2), National Institute of Standards and Technology, 2012. [Online]. Available: https://nvlpubs.nist.gov
. Accessed: Jan. 7, 2026.

[10] CREST, “Cyber Security Incident Response Guide,” CREST, 2024. [Online]. Available: https://www.crest-approved.org
. Accessed: Jan. 7, 2026.

[11] SANS Institute, “SOC Tiering and Analyst Roles,” SANS White Papers, 2024. [Online]. Available: https://www.sans.org/white-papers/402/
. Accessed: Jan. 6, 2026.

[12] Verizon, 2024 Data Breach Investigations Report, Verizon Enterprise, 2024. [Online]. Available: https://www.verizon.com/business/resources/reports/2024-dbir-data-breach-investigations-report.pdf
. Accessed: Jan. 7, 2026.
