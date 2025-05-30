#### WELCOME! to my Detection Engineering Project! ####

* This is based on ELK (Elastic Logstash Kibana) Stack as a SIEM and a Home Lab consisting of:

  -  Kali: Used as a threat actor machine
  -  Ubuntu 24.10: Used to ingest network logs via Zeek to ELK
  -  Windows 10: Mostly as a Victim, Sysmon logs ingested to ELK via Elastic agent

* Initial manual attacks and detections done:

  -  Nikto, NMAP, and Zaap scanning activity was performed on the victim and was detected by creating rules manually on the ELK platform
  -  Similarly, a malware dropper was sent to the victim's machine (Say, a victim of phishing). With the help of Metasploit, Data Exfil was done via FTP and was detected by manual rule writing on the ELK
  -  Atomic Red Team was then used to simulate a few attacks to write detections and check the workflow of rule enforcement

* The latter part has the automation workflows.
  
  -  THE PYTHON SCRIPTS AND TOML SCRIPTS HERE ARE USED AS PART OF THE AUTOMATION WORKFLOWS AND VALIDATING THE JSON, MITRE OBJECT FORMATS THAT ARE BEING PARSED AND CONVERTED FROM THE TOML-BASED RULES, WHICH THEN ARE PUSHED TO ELK VIA ITS API.

* THE MAIN GOAL HERE IS TO WRITE TOML RULES FOR ELASTIC AND CREATE A CI/CD PIPELINE SO THAT THE PROCESS OF CREATING AN ALERT IN ELASTIC IS AUTOMATED, INSTEAD OF CREATING EACH AND EVERY RULE MANUALLY IN ELASTIC.

* THE GITHUB ACTIONS WORKFLOW IS STILL IN CHECK AND NEEDS A SLIGHT DO OVER, HENCE NOT INCLUDED HERE. (Figuring out the API Key issue)

(THIS IS JUST MY PERSONAL PROJECT AND NOT RELATED TO ANY COURSEWORK)
