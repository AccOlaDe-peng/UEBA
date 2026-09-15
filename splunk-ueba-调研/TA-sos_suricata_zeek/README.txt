App Name: Technology Add-on for Security Onion (Zeek & Suricata)
App ID: TA-nsm-zeek-suricata
Version: 1.0.0
Author: Sachin Mestry
Splunk Compatibility: Splunk Enterprise 9.x and higher

Overview:
This Technology Add-on (TA) provides field extractions, event types, tags, and lookups 
to normalize Security Onion Zeek and Suricata logs into Splunk Common Information Model (CIM). 
It enables better visibility into network security events and integrates seamlessly 
with Splunk Enterprise Security.

Features:
- Field extractions for Zeek and Suricata logs
- Eventtypes and tags mapped to Splunk CIM data models
- Lookups for service identification


Installation:
1. Copy the TA-security_onion folder into $SPLUNK_HOME/etc/apps/
2. Restart Splunk
3. Verify that sourcetypes (zeek_conn, zeek_http, suricata) are being parsed correctly
4. If using Splunk ES, verify data model acceleration

Changelog:
v1.0.0 (Initial Release)
- Added field extractions in props.conf and transforms.conf
- Added CIM-compatible eventtypes and tags
- Added zeek_service_lookup.csv lookup
- Added optional dashboard (network_security.xml)

Support:
This app is community-supported. For issues or feature requests, please contact smestry@malomatia.com
