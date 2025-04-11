# Force PowerShell to use TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Prompt for CyberArk credentials
$cred = Get-Credential
$Username = $cred.UserName
$Password = $cred.GetNetworkCredential().Password

# CyberArk Privilege Cloud details
$Subdomain = "alliantcredit"
$BaseURL = "https://$Subdomain.privilegecloud.cyberark.com/PasswordVault/API"

# Authentication URL
$AuthURL = "$BaseURL/auth/Cyberark/Logon/"

# Authenticate
try {
    $AuthToken = Invoke-RestMethod -Uri $AuthURL -Method POST -Body (@{ username = $Username; password = $Password } | ConvertTo-Json) -ContentType "application/json"
    Write-Host "✅ Authentication successful." -ForegroundColor Green
} catch {
    Write-Host "❌ Authentication failed: $_" -ForegroundColor Red
    exit
}

# Set headers
$Headers = @{
    Authorization = $AuthToken
    "Content-Type" = "application/json"
}

# Fetch all safes
$SafesURL = "$BaseURL/Safes"
try {
    $SafesResponse = Invoke-RestMethod -Uri $SafesURL -Headers $Headers -Method GET
    $SafeList = $SafesResponse.safes
    Write-Host "📦 Retrieved $($SafeList.Count) safes." -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to retrieve safes: $_" -ForegroundColor Red
    exit
}

# Prepare report array
$SafeMembersReport = @()

# Iterate over each safe
foreach ($Safe in $SafeList) {
    $SafeName = $Safe.safeName
    $SafeOwner = $Safe.safeOwner
    $EncodedSafeName = [System.Web.HttpUtility]::UrlEncode($SafeName)
    $MembersURL = "$BaseURL/Safes/$EncodedSafeName/Members"

    try {
        $MembersResponse = Invoke-RestMethod -Uri $MembersURL -Headers $Headers -Method GET
        foreach ($Member in $MembersResponse.Members) {
            $Perm = $Member.Permissions

            $SafeMembersReport += [PSCustomObject]@{
                SafeName                        = $SafeName
                SafeOwner                       = $SafeOwner
                MemberName                      = $Member.memberName
                MemberType                      = $Member.memberType
                MembershipExpirationDate        = $Member.membershipExpirationDate
                IsExpiredMembershipEnable       = $Member.isExpiredMembershipEnable
                IsPredefinedUser                = $Member.isPredefinedUser

                # Permissions (22 fields)
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
        Write-Host "⚠️ Could not retrieve members for safe '$SafeName': $_" -ForegroundColor Yellow
    }
}

# Export to CSV
$OutputFile = "CyberArk_SafeMembers_FullPermissions.csv"
$SafeMembersReport | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "✅ Safe member report exported to: $OutputFile" -ForegroundColor Cyan

# Log off session
$LogoffURL = "$BaseURL/auth/Logoff"
Invoke-RestMethod -Uri $LogoffURL -Headers $Headers -Method POST | Out-Null
Write-Host "🔒 Logged out successfully." -ForegroundColor Gray
