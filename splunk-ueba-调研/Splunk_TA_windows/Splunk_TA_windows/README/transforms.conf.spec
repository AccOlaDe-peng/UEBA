##
## SPDX-FileCopyrightText: 2024 Splunk, Inc.
## SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

CAN_OPTIMIZE_IE = <boolean>
* Whether or not Splunk software skips this extraction if field extraction
  already occurred at index time for this event.
* This setting applies to every matched event and only to search-time
  field extractions.
* A value of "true" means search-time extractions are skipped if
  index-time extraction already occurred for this event.
* A value of "false" means Splunk software performs search-time
  extractions regardless of whether index-time extractions also occur.
* Set this value to "true" only if you expect the extraction's output field to
  already be present from the index-time extraction.
* Set this value to "true" only if SOURCE_KEY maps to an extracted field other
  than _raw or an empty value.
* Optional.
* Default: false

[user_account_control_property]
python.version = {default|python|python2|python3}
* For Splunk 8.0.x and Python scripts only, selects which Python version to use.
* Either "default" or "python" select the system-wide default Python version.
* Optional.
* Default: not set; uses the system-wide Python version.
python.required = 3.9, 3.13
