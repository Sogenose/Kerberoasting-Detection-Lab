---
tags:
  - Homelab
  - Cybersec
  - SOC
Created: 2026-7-28
Status: In-Progress
---
## Background:
---
[[HomeLab Project]]
This SOC Lab is being created to give hands on experience creating a SIEM environment. This lab utilizes Active Directory, Wazuh, OPNSense and Kali Linux within a Proxmox server. This serves as the initial page for the lab. Below are the sections with information pertaining to each component of the lab. **MORE TO BE ADDED**

### Active Directory
---

### Wazuh
---
Custom XML Rule:
	`sudo nano /var/ossec/etc/rules/local_rules.xml`
	Rule:
	`<group name="kerberoasting,local,">
		`<rule id="100010" level="0">`
		    `<if_group>windows</if_group>`
		    `<field name="win.system.eventID">^4769$%3C</field>`
		    `<description>Kerberos service ticket requested (TGS-REQ)</description>`
		    `<group>kerberos_ticket,</group>``
	    `</rule>`
	`<rule id="100011" level="12">`
	    `<if_sid>100010</if_sid>`
	    `<field name="win.eventdata.TicketEncryptionType">^0x17$</field>
	    `<description>Possible Kerberoasting: RC4 service ticket requested for $(win.eventdata.ServiceName) by $(win.eventdata.TargetUserName)</description>`
	    `<mitre>`
	      `<id>ET1558.003</id%3E`
	    `</mitre>`
	    `<group>Ekerberoasting,attack,</group>`
	  `</rule>`
	`</group>`

### OPNsense
----

### Kali Linux
---






### TimeLine Table
---

| Stage                           | Timestamp  | Source                               |
| ------------------------------- | ---------- | ------------------------------------ |
| SPN Enumeration (recon)         | HH:MM:SS   | Kali terminal / impacket output      |
| TGS ticket request              | HH:MM:SS   | kali terminal / impacket output      |
| Event ID 4769 generated         | HH:MM:SS   | DC01 Security Event Log              |
| Wazuh Alert (rule 100011) fired | HH:MM:SS   | Wazuh Discover / alerts.json         |
| Detection latency               | ~X seconds | Calculated (alert time - event time) |

