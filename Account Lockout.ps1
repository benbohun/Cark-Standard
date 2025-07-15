<#
.SYNOPSIS
    Export CyberArk PAS accounts for user CAG1896a, with all extended properties to CSV (including Logon and Reconcile account if present).
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = "PASAccounts_CAG1896a_ExtendedReport.csv"
)

$ErrorActionPreference = "Stop"

if (!(Get-Module -ListAvailable -Name psPAS)) {
    Write-Host "psPAS module not found, installing..." -ForegroundColor Yellow
    Install-Module psPAS -Scope CurrentUser -Force
}
Import-Module psPAS

$UPCred = Get-Credential
Write-Host "Connecting to CyberArk..." -ForegroundColor Cyan
$header = Get-IdentityHeader -IdentityTenantURL "aat4012.id.cyberark.cloud" -psPASFormat -PCloudSubdomain "cna-prod" -UPCreds $UPCred
Use-PASSession $header
Write-Host "Authentication successful!" -ForegroundColor Green

Write-Host "Fetching platforms and safes..." -ForegroundColor Cyan
$platforms = Get-PASPlatform
$safes = Get-PASSafe

$platformsht = @{}
$platforms | ForEach-Object { $platformsht[$_.PlatformID] = $_ }
$safesht = @{}
$safes | ForEach-Object { $safesht[$_.SafeName] = $_ }

Write-Host "Fetching CyberArk accounts for CAG1896a..." -ForegroundColor Cyan
$accounts = Get-PASAccount | Where-Object { $_.userName -ieq 'CAG1896a' }

if (!$accounts -or $accounts.Count -eq 0) {
    Write-Warning "No accounts found for user CAG1896a! Please check the username, connection, or permissions."
    exit
}

$report = @()

# Collect all custom/imported property names
$importedPropsList = @()
foreach ($acct in $accounts) {
    if ($acct.platformAccountProperties) {
        $importedPropsList += $acct.platformAccountProperties.PSObject.Properties.Name
    }
}
$importedPropsList = $importedPropsList | Select-Object -Unique

$counter = 0
$total = $accounts.Count

foreach ($acct in $accounts) {
    $counter++
    Write-Progress -Activity "Processing accounts..." -Status "$counter of $total" -PercentComplete (($counter/$total)*100)

    try {
        $details = Get-PASAccount -id $acct.id

        $platformInfo = $null
        if ($details.platformId -and $platformsht.ContainsKey($details.platformId)) {
            $platformInfo = $platformsht[$details.platformId]
        }
        $safeInfo = $null
        if ($details.safeName -and $safesht.ContainsKey($details.safeName)) {
            $safeInfo = $safesht[$details.safeName]
        }

        $logonAccount = $null
        $reconcileAccount = $null
        if ($details.platformAccountProperties) {
            $logonAccount = $details.platformAccountProperties['LogonAccount']
            if (-not $logonAccount) { $logonAccount = $details.platformAccountProperties['Logon Account'] }
            $reconcileAccount = $details.platformAccountProperties['ReconcileAccount']
            if (-not $reconcileAccount) { $reconcileAccount = $details.platformAccountProperties['Reconcile Account'] }
        }

        $customProps = @{}
        foreach ($p in $importedPropsList) {
            $customProps[$p] = $null
            if ($details.platformAccountProperties -and $details.platformAccountProperties.$p) {
                $customProps[$p] = $details.platformAccountProperties.$p
            }
        }

        $reportObj = [PSCustomObject]@{
            id                       = $details.id
            SafeName                 = $details.safeName
            PlatformID               = $details.platformId
            PlatformName             = $platformInfo.Details.Name
            Name                     = $details.name
            Address                  = $details.address
            UserName                 = $details.userName
            SecretType               = $details.secretType
            SecretStatus             = $details.secretManagement.Status
            AccountManaged           = $details.secretManagement.automaticManagementEnabled
            ManualManagementReason   = $details.secretManagement.manualManagementReason
            ManagingCPM              = $safeInfo.ManagingCPM
            CreatedTime              = $details.createdTime
            CategoryModificationTime = $details.categoryModificationTime
            RestrictedToSpecificMachines = $details.remoteMachinesAccess.accessRestrictedToRemoteMachines
            RemoteMachines               = $details.remoteMachinesAccess.remoteMachines
            DualControl   = $platformInfo.Details.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval.IsActive
            ExclusiveUse  = $platformInfo.Details.PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess.IsActive
            OneTime       = $platformInfo.Details.PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess.IsActive
            RequireReason = $platformInfo.Details.PrivilegedAccessWorkflows.RequireUsersToSpecifyReasonForAccess.IsActive
            ChangeManual     = $platformInfo.Details.CredentialsManagementPolicy.Change.AllowManual
            ChangeOnAdd      = $platformInfo.Details.CredentialsManagementPolicy.Change.AutoOnAdd
            ChangeAuto       = $platformInfo.Details.CredentialsManagementPolicy.Change.PerformAutomatic
            ChangeDays       = $platformInfo.Details.CredentialsManagementPolicy.Change.RequirePasswordEveryXDays
            ChangeLast       = if ($details.secretManagement.lastModifiedTime) { (Get-Date -Date "01-01-1970").AddSeconds([double]$details.secretManagement.lastModifiedTime) } else { $null }
            ChangeNext       = if ($details.secretManagement.lastModifiedTime -and $platformInfo.Details.CredentialsManagementPolicy.Change.RequirePasswordEveryXDays) { (Get-Date -Date "01-01-1970").AddSeconds([double]$details.secretManagement.lastModifiedTime).AddDays($platformInfo.Details.CredentialsManagementPolicy.Change.RequirePasswordEveryXDays) } else { $null }
            ChangeInReset    = $platformInfo.Details.CredentialsManagementPolicy.SecretUpdateConfiguration.ChangePasswordInResetMode
            VerifyManual = $platformInfo.Details.CredentialsManagementPolicy.Verification.AllowManual
            VerifyOnAdd  = $platformInfo.Details.CredentialsManagementPolicy.Verification.AutoOnAdd
            VerifyAuto   = $platformInfo.Details.CredentialsManagementPolicy.Verification.PerformAutomatic
            VerifyDays   = $platformInfo.Details.CredentialsManagementPolicy.Verification.RequirePasswordEveryXDays
            VerifyLast   = if ($details.secretManagement.lastVerifiedTime) { (Get-Date -Date "01-01-1970").AddSeconds([double]$details.secretManagement.lastVerifiedTime) } else { $null }
            VerifyNext   = if ($details.secretManagement.lastVerifiedTime -and $platformInfo.Details.CredentialsManagementPolicy.Verification.RequirePasswordEveryXDays) { (Get-Date -Date "01-01-1970").AddSeconds([double]$details.secretManagement.lastVerifiedTime).AddDays($platformInfo.Details.CredentialsManagementPolicy.Verification.RequirePasswordEveryXDays) } else { $null }
            ReconcileManual = $platformInfo.Details.CredentialsManagementPolicy.Reconcile.AllowManual
            ReconcileUnSync = $platformInfo.Details.CredentialsManagementPolicy.Reconcile.AutomaticReconcileWhenUnsynced
            ObjectName = $details.name
            LogonAccount = $logonAccount
            ReconcileAccount = $reconcileAccount
        }

        foreach ($k in $importedPropsList) {
            $reportObj | Add-Member -MemberType NoteProperty -Name $k -Value $customProps[$k] -Force
        }

        $report += $reportObj

    } catch {
        Write-Warning "Failed to process account: $($acct.id) - $_"
    }
}

try {
    $report | Export-Csv -NoTypeInformation -Path $ReportPath
    Write-Host "`nFull extended CyberArk account report exported to: $ReportPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to export report to $ReportPath. $_"
}

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
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
Write-Host "------------------------------------------------------" -ForegroundColor Cyan
Write-Host "      Active Directory Account Lockouts (24 Hours)" -ForegroundColor Cyan
Write-Host "------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""

# Prompt for DC, default to local if blank
$DC = Read-Host "Enter the Domain Controller name to query (leave blank for local machine)"
if ([string]::IsNullOrWhiteSpace($DC)) {
    $DC = $env:COMPUTERNAME
    Write-Host ("No DC entered. Using local machine: {0}" -f $DC) -ForegroundColor Yellow
} else {
    Write-Host ("Using Domain Controller: {0}" -f $DC) -ForegroundColor Yellow
}

$StartTime = (Get-Date).AddHours(-24)
Write-Host ("Scanning Security event logs for lockout events since {0} ..." -f $StartTime) -ForegroundColor Yellow

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

Write-Host ("`n🚨 {0} account lockout(s) detected in the last 24 hours on {1}:" -f $Results.Count, $DC) -ForegroundColor Red
$Results | Sort-Object Time | Format-Table Time, UserName, SourceWorkstation, DomainController -AutoSize

Write-Host "`n✅ Script complete." -ForegroundColor Green
Write-Host "------------------------------------------------------" -ForegroundColor Cyan
