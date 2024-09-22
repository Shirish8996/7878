# Comprehensive KQL Queries for Threat Hunting

This document provides a detailed explanation of several Kusto Query Language (KQL) queries designed for threat hunting in Microsoft Defender for Endpoint and Azure Sentinel environments. These queries cover various aspects of threat detection, including cryptocurrency mining, brute force attacks, and suspicious device connections.

## Query 1: Detect Potential Coinminer Malware

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("monero", "xmrig", "cpuminer", "minerd")
    or ProcessCommandLine matches regex @"(?i)(\.exe|\.dll)\s+-o\s+pool"
    or ProcessCommandLine contains "--cpu-priority"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, FileName
| extend Alert = "Potential coinminer activity detected"
```

### Explanation:
- This query searches for process command lines that contain known coinminer-related terms or patterns.
- It looks for common names of mining software (monero, xmrig, cpuminer, minerd).
- It uses a regex to match command-line patterns often used in mining operations.
- It checks for CPU priority settings that miners often use.
- The query projects relevant fields and adds an alert message.

### Use Case:
This query helps identify machines that might be running unauthorized mining software, which could indicate a compromise or insider threat.

## Query 2: Detect High CPU Usage (Often Associated with Mining)

```kusto
DevicePerformance
| where Timestamp > ago(1h)
| where CpuUsagePercentage > 90
| summarize AvgCPU = avg(CpuUsagePercentage) by DeviceName
| where AvgCPU > 90
| project DeviceName, AvgCPU
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(1h)
    | summarize ProcessList = make_set(ProcessCommandLine) by DeviceName
) on DeviceName
| extend Alert = "High CPU usage detected, possible mining activity"
```

### Explanation:
- This query looks for devices with consistently high CPU usage (over 90%) in the past hour.
- It calculates the average CPU usage for each device.
- It then joins this information with the list of processes running on those devices.
- An alert is added to flag potential mining activity.

### Use Case:
This query helps identify mining activity that might not be detected by looking for specific process names, focusing instead on the high resource usage characteristic of mining operations.

## Query 3: Detect Brute Force Attempts on Windows

```kusto
SecurityEvent
| where EventID in (4625, 4771)
| summarize FailedAttempts = count() by TargetAccount, IpAddress, bin(TimeGenerated, 10m)
| where FailedAttempts > 10
| extend Alert = strcat("Potential brute force attack detected. ", FailedAttempts, " failed login attempts in 10 minutes")
```

### Explanation:
- This query focuses on failed login attempts (Event IDs 4625 and 4771) on Windows systems.
- It counts failed attempts from the same IP address to the same account within 10-minute windows.
- It flags potential brute force attacks if there are more than 10 failed attempts in 10 minutes.

### Use Case:
This query helps identify potential unauthorized access attempts through password guessing on Windows systems.

## Query 4: Detect Brute Force Attempts on Linux

```kusto
Syslog
| where SyslogMessage contains "Failed password"
| parse SyslogMessage with * "invalid user " User " from " IpAddress " port" *
| summarize FailedAttempts = count() by User, IpAddress, bin(TimeGenerated, 10m)
| where FailedAttempts > 10
| extend Alert = strcat("Potential Linux brute force attack detected. ", FailedAttempts, " failed login attempts in 10 minutes")
```

### Explanation:
- This query parses Syslog messages for failed password attempts on Linux systems.
- It extracts the username and IP address from the log message.
- It counts failed attempts by user and IP address in 10-minute windows.
- It flags potential brute force attacks using the same threshold as the Windows query (10 attempts in 10 minutes).

### Use Case:
This query helps identify potential unauthorized access attempts through password guessing on Linux systems.

## Query 5: Detect Rare One-Time Devices Connected to a Specific Machine

```kusto
let DeviceNameParam = "<replace this with full computer name>";
let devices =
    DeviceEvents
    | where ActionType == "PnpDeviceConnected"
    | extend parsed=parse_json(AdditionalFields)
    | project 
        DeviceDescription=tostring(parsed.DeviceDescription),
        ClassName=tostring(parsed.ClassName),
        DeviceId=tostring(parsed.VendorIds),
        VendorIds=tostring(parsed.VendorIds),
        DeviceName, Timestamp ;
devices 
| where DeviceName == DeviceNameParam
| summarize TimesConnected=count(), FirstTime=min(Timestamp), LastTime=max(Timestamp) by DeviceId, DeviceDescription, ClassName, VendorIds, DeviceName
| where LastTime - FirstTime < 1d
| join kind=leftanti 
  (devices | summarize Machines=dcount(DeviceName) by DeviceId, DeviceDescription, VendorIds | where Machines > 5)
  on DeviceId, DeviceDescription, VendorIds
```

### Explanation:
- This query looks for rare, one-time device connections to a specific machine.
- It filters PnpDeviceConnected events for a specific machine (defined by DeviceNameParam).
- It summarizes device connections, looking for those used within 24 hours.
- It excludes common devices seen across multiple machines in the organization (more than 5 machines).

### Use Case:
This query helps identify potentially suspicious device connections, such as unauthorized USB devices or other hardware that might be used for data exfiltration or introducing malware.

## Query 6: Map Uncommon Storage Devices Across the Organization

```kusto
DeviceEvents
| where ActionType == "PnpDeviceConnected"
| extend parsed=parse_json(AdditionalFields)
| extend
    DeviceDescription=tostring(parsed.DeviceDescription),
    ClassName=tostring(parsed.ClassName)
| where
    ClassName in ("DiskDrive", "CDROM")
    or ClassName contains "nas"
    or ClassName contains "SCSI"
    or (ClassName == "USB" and DeviceDescription contains "storage")
| summarize ComputerCount=dcount(DeviceName) by ClassName, DeviceDescription, DeviceName
| where ComputerCount < 10
```

### Explanation:
- This query identifies uncommon storage devices connected across the organization.
- It focuses on storage-related device classes (DiskDrive, CDROM, NAS, SCSI, USB storage).
- It counts the number of unique computers each device is connected to.
- It filters for devices seen on fewer than 10 computers.

### Use Case:
This query helps identify potentially unauthorized or suspicious storage devices being used across the organization, which could indicate data exfiltration attempts.

## Query 7: USB Storage Device Connections

```kusto
DeviceEvents
| project Timestamp, DeviceName, ActionType, AdditionalFields
| where ActionType == 'PnpDeviceConnected'
| extend PNP = parsejson(AdditionalFields)
| extend ClassName = PNP.ClassName
| extend DeviceId = PNP.DeviceId
| extend DeviceDescription = PNP.DeviceDescription
| extend VendorId = PNP.VendorIds
| where DeviceId startswith @'USBSTOR\'
| project-away ActionType, AdditionalFields, PNP
| sort by Timestamp desc
```

### Explanation:
- This query specifically tracks USB storage device connections.
- It filters for PnpDeviceConnected events.
- It extracts detailed information about the connected devices.
- It focuses specifically on USB storage devices (DeviceId starting with 'USBSTOR\').
- Results are sorted by timestamp in descending order.

### Use Case:
This query helps monitor and audit USB storage device usage across the organization, which is crucial for data loss prevention and detecting potential insider threats.

## General Usage in Threat Hunting

These queries form a comprehensive set of tools for proactive threat hunting:

1. **Regular Execution**: Run these queries regularly to establish a baseline of normal activity in your environment.
2. **Anomaly Detection**: Look for anomalies or sudden changes in the patterns these queries detect.
3. **Contextual Investigation**: Investigate any alerts generated, looking at surrounding context and additional logs.
4. **Threshold Adjustment**: Adjust thresholds (like the number of failed login attempts, CPU usage percentage, or device connection counts) based on your environment's normal behavior.
5. **Incident Response Integration**: Use the results to feed into your incident response process if actual threats are detected.
6. **Customization**: Adapt and expand these queries based on your specific environment, threat model, and newly discovered indicators of compromise (IoCs).

Remember, these queries are starting points in a larger threat hunting process. They should be used in conjunction with other security tools, threat intelligence, and human analysis for comprehensive threat detection and response.
