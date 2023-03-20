# Threat_Hunting

INTRODUCTION 
Threat hunt is a combative procedure in uncovering hidden adversaries with the presumption that the attacker may be present inside an organization’s network for days, weeks, and even months, preparing and executing attacks such as Zero Day, Advanced Persistent Threats, and unknown threats. Threat hunt combines a proactive methodology, innovative technology, highly skilled people, and in-depth threat intelligence to find and stop malicious activity. These attacks are hard-to-detect and executed by stealth attackers. Existing preventive tools often miss these attacks before they can execute their objectives.

Threat Hunting Pyramid of Pain 
This describe the various artifacts that can be used during a threat hunt, ranging from hash values, IP addresses and domains which are very easy to hunt for, but very easy for the attackers to modify also.
The harder ones are host artifacts, network, tools TTP, these are harder to hunt for, and will give better results as it is harder for attackers to change.

Threat Hunting Metrics


Case | Discription |
--- | --- | 
Number of incidents by severity	|You will never be able to know for certain how many incidents are lurking in your network until you find them, but ultimately keeping track of the rate at which you find incidents is a worthy metric to maintain context.Number of compromised hosts by severity	Measuring the trend of how many hosts are discovered as compromised over time can help orient analysts to the state of endpoint security on their network. This can include hosts that have had misconfigured security settings on them Dwell time of any incidents discovered	Whenever possible, try to determine how long discovered threats have been active on your network.This can help you determine if there are steps of the kill chain (or other attack model) you may be focusing on too much. Dwell time has 3 metrics: time from infectionuntil detection, time from detection to investigation, and time from investigation to remediationNumber of detection gaps filled	One high-level goal of hunting is to create new automated detections -- identifying and filling detection gaps should be part of the team’s mission.
Number of compromised hosts by severity	| Measuring the trend of how many hosts are discovered as compromised over time can help orient analysts to the state of endpoint security on their network. This can include hosts that have had misconfigured security settings on them
Dwell time of any incidents discovered	| Whenever possible, try to determine how long discovered threats have been active on your network. This can help you determine if there are steps of the kill chain (or other attack model) you may be focusing on too much. Dwell time has 3 metrics: time from infection until detection, time from detection to investigation, and time from investigation to remediation
Number of detection gaps filled	| One high-level goal of hunting is to create new automated detections -- identifying and filling detection gaps should be part of the team’s mission.
Logging gaps identified and corrected	| Gaps in logging or data collection can make it difficult for a SOC to maintain awareness and context, so trying to identify and improve any existing gaps should be an important actionable metric for a hunt team.
Insecure practices identified and corrected	| Insecure practices can lead to unauthorized access and unauthorized access can lead to incidents -- identifying insecure practices can prevent future incidents
Number of hunts transitioned to new analytics	| Since you want to create new automated detections, your team should try to transition each hunt into automated detection. Ideally you would want the ratio here to be 1:1. For every successful hunt you carry out you should be attempted to create a new analytic, update a rule, or at least log a new IoC
Number of hunts transitioned to new analytics	| Since you want to create new automated detections, your team should try to transition each hunt into automated detection. Ideally you would want the ratio here to be 1:1. For every successful hunt you carry out you should be attempted to create a new analytic, update a rule, or at least log a new IoC
False positive rate of transitioned hunts	| Once you discover a successful way to find something and create a rule or analytic to automate that process, it is useful to keep track of how many false positives have been created by those automated analytics, to see if they require improvements
Any new visibility gained	| In addition to discovering an incident and creating new threat intel, a hunt can inform analysts about their own networks, including misconfigurations, and identify friendly intelligence that can be highly useful in future investigations



This repository contains references to various Threat hunting best approaches\
Below are some great repositories where we can start from\
Use attack navigator to create a hypothesis, yara signatures.\
Lolbas hunt https://lolbas-project.github.io \
Atomic red team https://github.com/redcanaryco/atomic-red-team \
https://www.blusapphire.com/blog/threat-hunting-guide \
https://securityintelligence.com/posts/threat-hunting-guide \
https://logrhythm.com/webcasts/an-overview-to-threat-hunting-7-common-hunts-to-help-get-started \ 
https://www.deepwatch.com/blog/threat-hunting-in-splunk \
https://github.com/0x4D31/awesome-threat-detection \
https://github.com/OTRF/ThreatHunter-Playbook \
https://github.com/A3sal0n/CyberThreatHunting \
https://github.com/threat-hunting/awesome_Threat-Hunting \
https://github.com/topics/threat-hunting \
https://github.com/ThreatHuntingProject/hunter \
cs hunting: https://gist.github.com/ag-michael/4fc4e4ae7a8226dcb679261f18a3500d \

