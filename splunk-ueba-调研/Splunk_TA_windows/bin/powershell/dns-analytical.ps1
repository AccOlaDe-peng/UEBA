# Resolve Splunk home from environment
$SplunkHome = $env:SPLUNK_HOME

# Save paths (AnalyticalDNS example)
Set-Variable -Name "LogFolder" -Value "$SplunkHome\var\log\Splunk_TA_windows\AnalyticalDNS"
Set-Variable -Name "MonitoredLogFile" -Value "$LogFolder\dns_log.log"

# Use the variables above in the existing script
$logPath = $MonitoredLogFile
$checkpointFile = "$LogFolder\last_timestamp.txt"
$lastTimestamp = $null

# Ensure directory exists
if (!(Test-Path $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder | Out-Null
}

# Check for existing timestamp
if (Test-Path $checkpointFile) {
    $lastTimestamp = Get-Content $checkpointFile | Out-String
    $lastTimestamp = [datetime]::ParseExact($lastTimestamp.Trim(), "yyyy-MM-dd HH:mm:ss", $null)
} else {
    # Default: Start from 36 hours ago if no timestamp file exists
    $lastTimestamp = (Get-Date).AddHours(-36)
}

# Fetch new events after the last timestamp (analytical log must be read oldest-first)
$events = @(
    Get-WinEvent -LogName "Microsoft-Windows-DNSServer/Analytical" -Oldest |
        Where-Object { $_.TimeCreated -gt $lastTimestamp }
)

if ($events.Count -gt 0) {
    # Write each event as XML
    $events | ForEach-Object { $_.ToXml() } | Out-File -FilePath $logPath -Encoding UTF8

    # Update checkpoint with the newest event time
    $latestEventTime = ($events | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    $latestEventTime.ToString("yyyy-MM-dd HH:mm:ss") | Out-File -FilePath $checkpointFile -Force
}
