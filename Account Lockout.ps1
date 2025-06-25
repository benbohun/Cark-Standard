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
