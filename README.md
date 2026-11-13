# Internal Port Scan Detection with Microsoft Defender

A documented threat-hunting scenario linking unusual internal network connection attempts to PowerShell process activity and a script on an endpoint. The report and evidence remain in the original nested directory.

## Explore the project

- [Investigation walkthrough](threat-hunt-portscan-detection/threat-hunt-portscan-detection/README.md)
- [KQL queries](threat-hunt-portscan-detection/threat-hunt-portscan-detection/queries.kql)
- [Evidence screenshots](threat-hunt-portscan-detection/threat-hunt-portscan-detection/screenshots/)
- [Existing license](threat-hunt-portscan-detection/threat-hunt-portscan-detection/LICENSE)

## What the investigation covers

The walkthrough starts with failed internal connections, narrows to `angeltestvm`, then pivots into process and file events associated with `portscan.ps1`. It includes the recorded script contents, account context, response narrative, and proposed detection improvements.

## How to read the evidence

Treat this as a portfolio exercise rather than proof of production employment. The report describes isolation, scanning, and rebuilding; the screenshot inventory primarily covers investigation activity and does not independently verify all response outcomes. Its absence-of-evidence statements apply only to the examined data. Failed connections alone do not prove malicious intent: authorization and process context matter.

[Portfolio profile](https://github.com/angcra05)
