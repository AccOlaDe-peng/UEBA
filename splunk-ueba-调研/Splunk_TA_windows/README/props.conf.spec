##
## SPDX-FileCopyrightText: 2024 Splunk, Inc.
## SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

XML_INDEXED_EXTRACTIONS_PIPELINE = <structuredparsing|wineventlog|typing|exec>
* The pipeline to use for index-time field extractions from data that
  arrives in XML format.
* The following values are valid for 'XML_INDEXED_EXTRACTIONS_PIPELINE':
  * typing: This pipeline turns on field extraction from
    XML-formatted data.
  * structuredparsing: This pipeline turns on field
    extraction from XML-formatted data if you want to extract fields on
    Splunk Universal Forwarder instances.
  * exec: This pipeline turns on field extraction from Windows event logs
    that are in XML format with 'INDEXED_EXTRACTIONS=xmlkv-winevt' if
    you want to extract fields on Splunk Universal Forwarder instances.
  * wineventlog: This pipeline turns on field extraction from
    Windows event logs (.evtx files) that are in XML format with
    'INDEXED_EXTRACTIONS=xmlkv-winevt' if you want to extract fields on
    Splunk Universal Forwarder instances.
* This setting is only active if you configure 'INDEXED_EXTRACTIONS'.
* NOTE: The 'typing' value is not applicable for
  Splunk Universal Forwarder instances.
* Default: not set

extraction_cutoff = <integer>
* The number of characters into an event at which Splunk software stops
  running extractions.
* Default: 65536 (64KB)

XML_IE_EXCLUDE = <comma-separated list>
* The metadata fields that The Splunk platform must not extract for an
  event.
* Use this setting to filter index-time field extractions from data that
  arrives in XML format.
* You can use "*" as a wildcard.
* For example:
    [XmlWinEventLog]
    XML_IE_EXCLUDE = TargetProcessId
* Default: EventType

XML_IE_EXCLUDE_MV = <comma-separated list>
* The metadata fields for which the Splunk platform must not extract multiple
  values for an event.
* Use this setting to filter multivalue index-time field extractions from data
  that arrives in XML format. The Splunk platform extracts only the first value
  for each matching field.
* You can use "*" as a wildcard.
* For example:
    [XmlWinEventLog]
    XML_IE_EXCLUDE_MV = EventID
* Default: EventID

XML_IE_EXCLUDE_VALS = <comma-separated list>
* The values of metadata fields for which the Splunk platform must not extract
  for an event.
* Use this setting to skip index-time field extractions from data
  that arrives in XML format with excluded field values
  for each matching field.
* For example:
    [XmlWinEventLog]
    XML_IE_EXCLUDE_VALS = -
* Default: not set
