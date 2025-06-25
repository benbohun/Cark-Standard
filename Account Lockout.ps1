# Prompt for the account name (SAMAccountName, e.g., jdoe)
$User = Read-Host "Enter the account (SAMAccountName) to search lockout-related events for"

# Get date range for the last 24 hours
$StartTime = (Get-Date).AddHours(-24)

# Lockout and related event IDs
$EventIDs = @(4740, 4625, 4771, 4776)

Write-Host "`nSearching for lockout and related events for '$User' in the last 24 hours..." -ForegroundColor Cyan

# Search Security log for relevant events
$Events = Get-WinEvent -FilterHashtable @{
    LogName='Security';
    ID=$EventIDs;
    StartTime=$StartTime
} -ErrorAction SilentlyContinue

if ($null -eq $Events) {
    Write-Host "No relevant events found in the last 24 hours." -ForegroundColor Yellow
    return
}

# Parse each event for username match and display info
$Results = foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $EventData = $Xml.Event.EventData.Data

    switch ($Event.Id) {
        4740 { $TargetUser = $EventData | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text' }
        4625 { $TargetUser = $EventData | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text' }
        4771 { $TargetUser = $EventData | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text' }
        4776 { $TargetUser = $EventData | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text' }
        default { $TargetUser = $null }
    }

    if ($TargetUser -ieq $User) {
        [PSCustomObject]@{
            TimeCreated   = $Event.TimeCreated
            EventID       = $Event.Id
            EventType     = switch ($Event.Id) {
                                4740 { "Account Locked Out" }
                                4625 { "Failed Logon" }
                                4771 { "Kerberos Pre-auth Failed" }
                                4776 { "NTLM Auth Failed" }
                                default { "Other" }
                            }
            SourceHost    = ($EventData | Where-Object { $_.Name -eq "WorkstationName" } | Select-Object -ExpandProperty '#text')
            DC            = $Event.MachineName
        }
    }
}

if ($Results) {
    Write-Host "`nAccount lockout and related events found:`n" -ForegroundColor Green
    $Results | Sort-Object TimeCreated | Format-Table TimeCreated, EventType, SourceHost, DC -AutoSize
} else {
    Write-Host "`nNo events found for account '$User' in the last 24 hours." -ForegroundColor Yellow
}
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# PowerShell Script: List all AD account lockouts in last 24 hours (local or remote DC)

Write-Host "------------------------------------------------------" -ForegroundColor Cyan
Write-Host "      Active Directory Account Lockouts (24 Hours)" -ForegroundColor Cyan
Write-Host "------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""

# Prompt for DC, default to local if blank
$DC = Read-Host "Enter the Domain Controller name to query (leave blank for local machine)"
if ([string]::IsNullOrWhiteSpace($DC)) {
    $DC = $env:COMPUTERNAME
    Write-Host "No DC entered. Using local machine: $DC" -ForegroundColor Yellow
} else {
    Write-Host "Using Domain Controller: $DC" -ForegroundColor Yellow
}

$StartTime = (Get-Date).AddHours(-24)
Write-Host "Scanning Security event logs for lockout events since $StartTime ..." -ForegroundColor Yellow

try {
    $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
        LogName = 'Security'
        ID      = 4740
        StartTime = $StartTime
    } -ErrorAction Stop
}
catch {
    Write-Host "Error: Unable to read Security event log on $DC. Please ensure your account has 'Event Log Readers' rights on this DC." -ForegroundColor Red
    return
}

if (!$Events -or $Events.Count -eq 0) {
    Write-Host "`n✅ No account lockouts detected in the last 24 hours on $DC." -ForegroundColor Green
    return
}

Write-Host "`n🔍 Processing events..." -ForegroundColor Yellow

$Results = foreach ($Event in $Events) {
    $Xml = [xml]$Event.ToXml()
    $EventData = $Xml.Event.EventData.Data

    [PSCustomObject]@{
        Time             = $Event.TimeCreated
        UserName         = $EventData | Where-Object { $_.Name -eq "TargetUserName" } | Select-Object -ExpandProperty '#text'
        SourceWorkstation= $EventData | Where-Object { $_.Name -eq "WorkstationName" } | Select-Object -ExpandProperty '#text'
        DomainController = $Event.MachineName
    }
}

Write-Host "`n🚨 $($Results.Count) account lockout(s) detected in the last 24 hours on $DC:" -ForegroundColor Red
$Results | Sort-Object Time | Format-Table Time, UserName, SourceWorkstation, DomainController -AutoSize

Write-Host "`n✅ Script complete." -ForegroundColor Green
Write-Host "------------------------------------------------------" -ForegroundColor Cyan

# Optional: Export to CSV
# $Results | Export-Csv -Path "$env:USERPROFILE\Desktop\AD_Lockouts_Last24Hrs_$DC.csv" -NoTypeInformation
# Write-Host "Results exported to your Desktop as 'AD_Lockouts_Last24Hrs_$DC.csv'"

At line:51 char:88
+ ... unt) account lockout(s) detected in the last 24 hours on $DC:" -Foreg ...
+                                                              ~~~~
Variable reference is not valid. ':' was not followed by a valid variable name character. Consider using ${} to delimit the name.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : InvalidVariableReferenceWithDrive
