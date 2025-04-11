# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Prompt for CyberArk credentials
$cred = Get-Credential
$Username = $cred.UserName
$Password = $cred.GetNetworkCredential().Password

# CyberArk Privilege Cloud
$Subdomain = "alliantcredit"
$BaseURL = "https://$Subdomain.privilegecloud.cyberark.com/PasswordVault/API"

# Auth
$AuthURL = "$BaseURL/auth/Cyberark/Logon/"
try {
    $AuthToken = Invoke-RestMethod -Uri $AuthURL -Method POST -Body (@{ username = $Username; password = $Password } | ConvertTo-Json) -ContentType "application/json"
    Write-Host "✅ Authentication succeeded." -ForegroundColor Green
} catch {
    Write-Host "❌ Authentication failed: $_" -ForegroundColor Red
    exit
}

# Set Headers
$Headers = @{
    Authorization = $AuthToken
    "Content-Type" = "application/json"
}

# Get all safes
$SafesURL = "$BaseURL/Safes"
try {
    $SafesResponse = Invoke-RestMethod -Uri $SafesURL -Headers $Headers -Method GET
    $SafeList = $SafesResponse.safes
    Write-Host "`n🧾 Total safes found: $($SafeList.Count)" -ForegroundColor Green
    if ($SafeList.Count -eq 0) {
        Write-Host "⚠️ No safes found. Confirm user has Safe listing permissions." -ForegroundColor Red
        exit
    }
} catch {
    Write-Host "❌ Failed to retrieve safes: $_" -ForegroundColor Red
    exit
}

# Prepare report
$SafeMembersReport = @()

foreach ($Safe in $SafeList) {
    $SafeName = $Safe.safeName
    $SafeUrlId = $Safe.safeUrlId
    $SafeOwner = $Safe.safeOwner
    $EncodedSafeId = [System.Web.HttpUtility]::UrlEncode($SafeUrlId)

    Write-Host "`n➡️ Safe: $SafeName  (ID: $SafeUrlId)" -ForegroundColor Cyan
    $MembersURL = "$BaseURL/Safes/$EncodedSafeId/Members/"

    try {
        $MembersResponse = Invoke-RestMethod -Uri $MembersURL -Method GET -Headers $Headers
        $MemberCount = $MembersResponse.Members.Count
        Write-Host "👥 Members in safe: $MemberCount" -ForegroundColor Yellow

        if ($MemberCount -eq 0) {
            Write-Host "⚠️  No visible members. May be due to permission limits." -ForegroundColor DarkYellow
            continue
        }

        foreach ($Member in $MembersResponse.Members) {
            $Perm = $Member.Permissions

            $SafeMembersReport += [PSCustomObject]@{
                SafeName                        = $SafeName
                SafeUrlId                       = $SafeUrlId
                SafeOwner                       = $SafeOwner
                MemberName                      = $Member.memberName
                MemberType                      = $Member.memberType
                MembershipExpirationDate        = $Member.membershipExpirationDate
                IsExpiredMembershipEnable       = $Member.isExpiredMembershipEnable
                IsPredefinedUser                = $Member.isPredefinedUser

                UseAccounts                     = $Perm.useAccounts
                RetrieveAccounts                = $Perm.retrieveAccounts
                ListAccounts                    = $Perm.listAccounts
                AddAccounts                     = $Perm.addAccounts
                UpdateAccountContent            = $Perm.updateAccountContent
                UpdateAccountProperties         = $Perm.updateAccountProperties
                InitiateCPMAccountMgmt          = $Perm.initiateCPMAccountManagementOperations
                SpecifyNextAccountContent       = $Perm.specifyNextAccountContent
                RenameAccounts                  = $Perm.renameAccounts
                DeleteAccounts                  = $Perm.deleteAccounts
                UnlockAccounts                  = $Perm.unlockAccounts
                ManageSafe                      = $Perm.manageSafe
                ManageSafeMembers               = $Perm.manageSafeMembers
                BackupSafe                      = $Perm.backupSafe
                ViewAuditLog                    = $Perm.viewAuditLog
                ViewSafeMembers                 = $Perm.viewSafeMembers
                AccessWithoutConfirmation       = $Perm.accessWithoutConfirmation
                CreateFolders                   = $Perm.createFolders
                DeleteFolders                   = $Perm.deleteFolders
                MoveAccountsAndFolders          = $Perm.moveAccountsAndFolders
                RequestsAuthorizationLevel1     = $Perm.requestsAuthorizationLevel1
                RequestsAuthorizationLevel2     = $Perm.requestsAuthorizationLevel2
            }
        }
    } catch {
        Write-Host "❌ Error retrieving members for safe '$SafeName': $_" -ForegroundColor Red
    }
}

# Export report if data exists
$OutputFile = "CyberArk_SafeMembers_DebugReport.csv"
if ($SafeMembersReport.Count -gt 0) {
    $SafeMembersReport | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "`n✅ Report exported to: $OutputFile" -ForegroundColor Cyan
} else {
    Write-Host "`n❌ No safe members collected. Exiting." -ForegroundColor Red
}

# Log off
$LogoffURL = "$BaseURL/auth/Logoff"
Invoke-RestMethod -Uri $LogoffURL -Method POST -Headers $Headers | Out-Null
Write-Host "🔒 Logged out." -ForegroundColor Gray
