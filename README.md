# SOC-Home-Lab

## Objective


Developed an end-to-end SOC lab to master threat detection engineering. I integrated Wazuh and Suricata to monitor an Ubuntu endpoint, authoring custom detection rules to identify specific adversarial patterns. By simulating network attacks from Kali Linux, I validated the full detection lifecycle—from initial reconnaissance to centralized alerting—demonstrating my ability to deploy SIEM/IDS solutions and engineer actionable security telemetry.

### Skills Learned


- Rule Tuning: Authored custom XML-based rules to prioritize high-fidelity alerts.
- Log Ingestion: Configured the Wazuh manager to ingest and parse Suricata JSON telemetry.
- Incident Simulation: Validated detection capabilities by emulating adversary reconnaissance techniques.
- Detection Engineering: Bridged the "visibility gap" by layering network-based (Suricata) and host-based (Wazuh) sensors to capture the full scope of a threat actor's movements.
- Adversarial Mindset: Adopted an offensive perspective to analyze the "digital footprint" of network attacks, mapping the transition from stealthy reconnaissance to active exploitation.

### Tools Used


- Wazuh (SIEM): Centralized security monitoring platform used for log aggregation, analysis, and alerting.
- Suricata (IDS): Network Intrusion Detection System used to monitor and identify malicious network traffic via signature-based detection.
- Kali (Attacking VM): The offensive security platform used to perform adversary emulation and network reconnaissance.
- Ubuntu (Victim VM): The primary endpoint host acting as the monitoring target, running the Wazuh Agent and Suricata sensor.
- Nmap: Used for network discovery and security auditing to simulate port scanning and service enumeration attacks.
- Virtual Box: The hypervisor used to host and manage the virtual network and machines.

## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

*Ref 1: SOC Lab

<img width="1184" height="864" alt="SOC Home LAB Topology" src="https://github.com/user-attachments/assets/d9eb58d3-07fb-4c29-ae7e-cfb85334dabf" />


Prior to project implementation, I designed a network topology to architect the data flow and system segmentation. This blueprint served as a critical reference point during the deployment phase, ensuring accurate connectivity between the attack, victim, and SOC networks.

*Ref 2: SOC Lab
<img width="797" height="601" alt="Screenshot 2025-12-29 224557" src="https://github.com/user-attachments/assets/bdd7a7d3-6130-4c97-a14d-087505c5064f" />

Upon the initial deployment of the Wazuh OVA within VirtualBox, I performed network discovery on the appliance to identify its assigned IP address. This step was essential for establishing a connection to the web-based Wazuh Dashboard and beginning the administrative configuration.

*Ref 3: SOC Lab

<img width="647" height="200" alt="Screenshot 2025-12-29 225626" src="https://github.com/user-attachments/assets/f37d69d9-a0c8-4977-80e0-3a053ffdeebc" />


The purpose of downloading and executing this script is to provision and enroll the Ubuntu "Victim" VM as a monitored asset within my SOC environment. By running this command, I am installing the Wazuh Agent, which serves as the bridge for host-based security telemetry.

*Ref 4: SOC Lab
<img width="1174" height="541" alt="Screenshot 2025-12-29 234859" src="https://github.com/user-attachments/assets/12da9ebc-67ee-4d98-ae45-370ce96686b2" />

Successfully enrolled the Ubuntu endpoint into the SOC environment by installing the Wazuh Agent. I performed connectivity checks to confirm that the node appeared as 'Active' on the Wazuh dashboard, enabling real-time monitoring.

*Ref 5: SOC Lab

<img width="1125" height="630" alt="Screenshot 2025-12-29 234932" src="https://github.com/user-attachments/assets/ddb344da-e708-4690-9d97-7005e76dc6e4" />

After running the wazuh agent in the ubuntu, I have went into my wazuh dashboard under the agent management to confirm it was successfully connected to the wazuh siem.

*Ref 6: SOC Lab

<img width="647" height="444" alt="Screenshot 2025-12-30 133207" src="https://github.com/user-attachments/assets/18790db9-68c4-4b1f-a392-d8084dfdf64b" />

In this phase, I verified the active status of the Suricata service and confirmed its ability to generate network telemetry. After successfully starting the service via systemctl, I utilized a test command to trigger a simulated NIDS event. By inspecting the eve.json log file, I confirmed that Suricata was accurately capturing and logging network events in JSON format. This step was crucial to ensure that the network sensor was operational and ready to forward high-fidelity alerts to the Wazuh Manager for centralized analysis.

*Ref 7: SOC Lab

<img width="1123" height="531" alt="Screenshot 2025-12-30 133300" src="https://github.com/user-attachments/assets/083fc4ff-8388-4da8-971e-6dcd7f4e7d00" />

In the final phase, I performed end-to-end validation of the detection pipeline. By triggering a simulated attack, I verified that Suricata captured the network event and that the Wazuh Agent successfully forwarded the telemetry to the Manager. The presence of correlated alerts on the Wazuh Dashboard confirmed that the SIEM was accurately ingesting both network-based and host-based security events.

*Ref 8: SOC Lab

<img width="462" height="509" alt="Screenshot 2025-12-30 135635" src="https://github.com/user-attachments/assets/2faafe4c-e9df-494a-94b8-e0a4692057d7" />


To facilitate the testing phase, I manually configured a dedicated network interface on the Kali Linux attacking node. By assigning a static IP address within the lab’s internal subnet, I established the necessary routing for the subsequent Nmap reconnaissance and threat simulation. This ensured that the 'Ubuntu Victim' could be reached across the virtualized network, allowing for the end-to-end validation of the Suricata and Wazuh detection pipeline.

*Ref 9: SOC Lab

<img width="846" height="421" alt="Screenshot 2025-12-30 135717" src="https://github.com/user-attachments/assets/c4ca0c4c-7183-441e-bcfd-2fbe8aee4737" />

This stage of the project involved Adversary Emulation Network Configuration, where the communication path between the attacker and victim nodes was established. By manually configuring network interfaces on both the Kali Linux and Ubuntu VMs, a controlled environment was created to simulate and detect cyber attacks.


*Ref 10: SOC Lab

<img width="648" height="187" alt="Screenshot 2025-12-30 140149" src="https://github.com/user-attachments/assets/7f93e01a-a360-4f4f-968c-5dfa4e634c53" />

Following the successful network interface configuration and connectivity verification, I performed a strategic restart of the Suricata service. This step was essential to ensure that the IDS engine fully initialized with the updated network parameters and loaded the latest signature sets. By refreshing the service, I validated that the software solution was synchronized with the host’s new IP configuration, ensuring that the network sensor was primed for accurate, real-time traffic inspection.

*Ref 11: SOC Lab

<img width="544" height="440" alt="Screenshot 2025-12-30 140708" src="https://github.com/user-attachments/assets/c4992209-06b7-4ddc-bdf5-b5eb9eabae49" />

With the network architecture established, I initiated the Adversary Emulation phase by conducting an aggressive reconnaissance scan from the Kali Linux node. Using Nmap, I targeted the Ubuntu victim's internal IP to simulate a real-world probing attempt. This step was designed to test the responsiveness of the Suricata IDS and verify that the resulting network traffic would be identified as a potential threat, successfully triggering the end-to-end telemetry pipeline from the endpoint to the Wazuh SIEM.

*Ref 12: SOC Lab

<img width="1135" height="668" alt="Screenshot 2025-12-30 140946" src="https://github.com/user-attachments/assets/414d1e4e-1d27-4854-b8e6-fba14dc1af9f" />

The final Wazuh Dashboard provides a comprehensive visualization of the attack-to-detection pipeline. By correlating host-based telemetry with Suricata's network IDS alerts, the SIEM effectively identifies critical threats, as evidenced by the spike in Level 12 alerts during the adversary emulation phase. The integration of the MITRE ATT&CK framework further enhances the investigative process by mapping raw events to known adversarial tactics, validating the lab's effectiveness as a real-world security monitoring solution.


*Ref 13: SOC Lab

<img width="1137" height="685" alt="Screenshot 2025-12-30 141015" src="https://github.com/user-attachments/assets/a9290d5e-3843-4079-b53c-e5c50b5b5295" />

The Wazuh Threat Hunting Dashboard provides a centralized view of all ingested telemetry, enabling rapid incident correlation and triage. By mapping incoming alerts to the MITRE ATT&CK framework, the SIEM successfully identified and categorized the adversarial behavior initiated during the Nmap testing phase. The high-severity alerts (Level 12+) and the corresponding spike in the event timeline provide empirical evidence that the integrated Suricata IDS and Wazuh Agent pipeline can accurately detect and prioritize real-world reconnaissance tactics.

*Ref 14: SOC Lab

<img width="1191" height="349" alt="Screenshot 2025-12-30 141922" src="https://github.com/user-attachments/assets/0cb79fff-60e4-4d8f-8475-14e24ba51963" />

To demonstrate advanced defensive capabilities, I developed and implemented a custom IDS signature or rule within Suricata to detect targeted ICMP traffic from a specific adversary node. After configuring the internal network routing between the Kali Linux attacker and Ubuntu victim, I validated the signature by performing an aggressive Nmap scan. The successful ingestion and visualization of these alerts on the Wazuh Dashboard proved the effectiveness of the telemetry pipeline and my ability to engineer specific detection controls for unique threat patterns.

*Ref 15: SOC Lab

<img width="1174" height="541" alt="Screenshot 2025-12-29 234859" src="https://github.com/user-attachments/assets/1b5085d8-de23-47e5-9632-ae436b909fea" />

To enable granular detection of targeted threats, I performed advanced IDS tuning by modifying the suricata.yaml configuration file. I successfully integrated a dedicated path for local rules, allowing the engine to ingest and process custom-engineered signatures alongside standard detection sets. This configuration step was vital for validating my custom ICMP detection rule, ensuring that the Suricata sensor was properly equipped to identify and log the specific adversarial patterns simulated during the testing phase."

*Ref 16: SOC Lab

<img width="656" height="440" alt="Screenshot 2025-12-30 143743" src="https://github.com/user-attachments/assets/e3ffe7a9-d2ae-4249-909e-34166cf6e85d" />

Following the configuration of the suricata.yaml file, I performed a rigorous validation and deployment workflow. I utilized Suricata's test mode to verify the syntax of the updated configuration and confirmed the successful ingestion of custom-engineered signatures. Once validated, I restarted the Suricata service to transition the system into an active monitoring state. This process demonstrated a disciplined approach to change management, ensuring that new security policies were error-free before being deployed into the live production environment.

*Ref 17: SOC Lab

<img width="548" height="448" alt="Screenshot 2025-12-30 151258" src="https://github.com/user-attachments/assets/e86e05a5-bbbb-4a9c-8a9c-0e37f0a0afb9" />


In the final verification phase, I conducted an Active Attack Simulation to validate the end-to-end detection pipeline. By launching an aggressive Nmap scan from the Kali Linux attacker node, I triggered both the standard Suricata signatures and my custom ICMP detection rule. The immediate appearance of these alerts on the Wazuh Threat Hunting Dashboard confirmed that the telemetry pipeline stretching from the network sensor to the centralized SIEM—was fully operational and capable of providing real-time visibility into adversarial reconnaissance.

*Ref 18: SOC Lab

<img width="1136" height="679" alt="Screenshot 2025-12-30 144001" src="https://github.com/user-attachments/assets/e10d8ec3-b2e5-41ce-b81c-2789a723c69d" />


To conclude the project, I performed a live validation of my custom-engineered IDS signatures. After writing a specific rule to detect ICMP probing from the adversary node, I monitored the Wazuh SIEM to confirm successful ingestion. The dashboard accurately captured the 'KALI PINGing Ubuntu' alert at the exact moment of the simulation. This end-to-end verification demonstrates my proficiency in signature development, service configuration, and SIEM log correlation, proving the system's ability to detect granular, user-defined threat patterns.

