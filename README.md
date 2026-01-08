 
# comp3010-botsv3-analysis
Incident analysis report for BOTSv3 using Splunk – COMP3010 Security Operations &amp; Incident Management (70% Coursework).



## 1. Introduction

Security Operations Centres (SOCs) are responsible for continuously monitoring organisational systems, detecting security incidents, and coordinating effective responses to cyber threats. By combining skilled analysts, structured incident handling processes, and security monitoring technologies, SOCs provide organisations with situational awareness across cloud, network, and endpoint environments.

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

In the BOTSv3 investigation, Tier 1 and Tier 2 activities are most prominently represented. Initial detection and triage are achieved through Splunk-based monitoring of AWS and endpoint telemetry, while deeper analysis is performed through correlation of multiple log sources to establish a coherent incident narrative. Although active containment and eradication actions are outside the scope of the simulated environment, Tier 3 responsibilities are reflected through analytical interpretation and the formulation of security improvement recommendations.

### Incident Handling Lifecycle Alignment

| Incident Phase | BOTSv3 Evidence |
|----------------|----------------|
| **Detection** | Identification of AWS API activity without MFA and S3 ACL changes using Splunk searches |
| **Analysis** | Correlation of CloudTrail, S3 access logs, and endpoint data to determine scope and impact |
| **Containment (Conceptual)** | Identification of required actions such as removing public S3 access and enforcing MFA |
| **Post-Incident Review** | Recommendations for improved detection logic, IAM governance, and cloud security posture |

Overall, this investigation demonstrates how structured SOC roles and disciplined incident handling methodologies translate into effective operational workflows. By leveraging centralised visibility and query-driven analysis, SOC teams can transform raw telemetry into actionable intelligence and continuously improve detection and response capabilities.




## 3. Installation and Data Preparation

3.1 Splunk Setup

To conduct the BOTSv3 investigation, Splunk Enterprise was deployed on an Ubuntu virtual machine to simulate a SOC analysis environment. Splunk was installed using the official Splunk Enterprise installer and configured to run locally on port 8000. Following installation, the Splunk service was started successfully, and the web interface was accessed via a browser to confirm operational status.

During the initial setup, the Splunk license agreement was accepted, and default administrative credentials were configured. The Splunk instance was verified by confirming access to the Search & Reporting application and ensuring that search functionality was operational. This setup provided a stable foundation for ingesting and analysing large-scale security telemetry, consistent with SOC operational practices.<img width="1129" height="892" alt="Screenshot 2026-01-07 215557" src="https://github.com/user-attachments/assets/2862c3f2-19d7-4670-b43c-13f26cd9287e" />



3.2 BOTSv3 Dataset Ingestion

The Boss of the SOC v3 (BOTSv3) dataset was ingested into Splunk following the official dataset documentation. The dataset was extracted locally and indexed into Splunk using the predefined botsv3 index to ensure consistent querying and analysis.

Once ingestion was completed, validation searches were performed to confirm that data had been indexed correctly and that expected source types were available. A broad search across the botsv3 index confirmed the presence of millions of events, indicating successful ingestion. Additional validation queries were used to identify available sourcetypes, including AWS CloudTrail logs, S3 access logs, endpoint monitoring data, DNS logs, and host-based telemetry.

These validation steps are critical in a SOC environment, as incomplete or misconfigured data ingestion can lead to missed detections or inaccurate analysis. By verifying data availability and coverage before proceeding, confidence was established that subsequent investigative queries were based on reliable telemetry.<img width="1261" height="905" alt="Screenshot 2026-01-07 224817" src="https://github.com/user-attachments/assets/182f9017-5685-4a47-a79a-89cda377e588" />

<img width="1223" height="965" alt="Screenshot 2026-01-07 224915" src="https://github.com/user-attachments/assets/437c80a5-8a6c-4a80-97e5-5196431c3a1d" />


3.3 Data Validation

To ensure readiness for investigation, multiple exploratory searches were conducted across different data sources. These searches confirmed that key datasets required for answering the BOTSv3 guided questions were present and queryable. Endpoint-related data, AWS audit logs, and access records were all accessible within Splunk, allowing correlation across cloud and host-level activity.

This validation phase reflects standard SOC operational practice, where analysts confirm data completeness and visibility before engaging in detailed incident analysis. With ingestion and validation completed, the environment was deemed suitable for answering the BOTSv3 200-level questions and supporting evidence-based incident investigation.

<img width="1303" height="936" alt="Screenshot 2026-01-07 222615" src="https://github.com/user-attachments/assets/0f01f0d2-6351-41ef-95bd-f78798a1c898" />


3.4 Justification of Setup

The chosen setup was designed to reflect realistic SOC operational workflows while supporting accurate and efficient incident analysis. Deploying Splunk within a virtualised Ubuntu environment provides full administrative control, isolates investigative activity from production systems, and ensures a reproducible analysis environment.

Using Splunk Enterprise as the SIEM platform enables centralised log collection, normalisation, and correlation across multiple data sources, including cloud and endpoint telemetry. The creation of a dedicated botsv3 index improves search performance and prevents cross-contamination with other datasets, reflecting best practice in enterprise SOC environments.

Additionally, the use of structured validation queries and documented evidence screenshots supports traceability and reproducibility of findings. This approach aligns with professional SOC reporting standards, where analysts are expected to justify conclusions using verifiable evidence. Overall, the selected configuration supports the learning objectives of COMP3010 by enabling methodical, evidence-driven security analysis consistent with real-world incident response practices.

## 4 Guided Questions
4.1 Question 1 – IAM Users Accessing AWS Services

Purpose
The objective of this analysis was to identify all IAM users that interacted with AWS services within the Frothly environment. Both successful and unsuccessful API calls were included to establish a complete identity baseline.

Method
AWS CloudTrail logs were analysed in Splunk by filtering events where userIdentity.type=IAMUser. The userIdentity.userName field was aggregated to extract a unique list of IAM identities responsible for AWS API activity across the environment.

<img width="523" height="419" alt="Screenshot 2026-01-08 124303" src="https://github.com/user-attachments/assets/8600a65d-daa1-4b39-8bb4-31bd88415ed1" />

Result
The following IAM users were observed accessing AWS services during the investigation period:

Answer: bstoll, btun, splunk_access, web_admin

SOC Relevance
Identity-based analysis is a foundational SOC activity in cloud investigations. Establishing which IAM users are active enables analysts to detect anomalous access patterns, misuse of privileged accounts, and potential credential compromise. This activity typically forms part of Tier 1 alert triage and Tier 2 investigation workflows within a SOC.



  4.2.  Question 2 – AWS API Activity Without MFA

Purpose
The objective of this analysis was to identify the CloudTrail field that indicates whether multi-factor authentication (MFA) was used during AWS API activity, enabling detection of API calls performed without MFA.

Method
AWS CloudTrail identity context fields were examined in Splunk by reviewing attributes associated with the userIdentity object. Particular attention was given to session context metadata that records authentication characteristics for API requests. This analysis identified the userIdentity.sessionContext.attributes.mfaAuthenticated field as the indicator of MFA usage.

<img width="1118" height="852" alt="Screenshot 2026-01-07 225610" src="https://github.com/user-attachments/assets/bc88b041-1ad9-4ef2-a7e0-24d8817ee53c" />

Result
The field used to determine whether MFA was applied during an AWS API call is:

Answer: userIdentity.sessionContext.attributes.mfaAuthenticated

SOC Relevance
Monitoring AWS API activity without MFA is a critical SOC detection use case. API calls executed without MFA significantly increase the risk of credential misuse, particularly if access keys are compromised or leaked. In operational SOC environments, events where mfaAuthenticated=false would typically trigger alerting, escalation, or further investigation, especially for privileged IAM users or sensitive services. Continuous monitoring of this field supports enforcement of strong identity controls and reduces the likelihood of cloud account compromise. 




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

[12] Verizon, 2024 Data Breach Investigations Report, Verizon Enterprise, 2024. [Online]. Available: https://www.verizon.com/business/resources/reports/2024-dbir-data-breach-investigations-report.pdf
. Accessed: Jan. 6, 2026.
