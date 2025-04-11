
# Step 3: Retrieve Safe Members and Permissions
$SafeMembersReport = @()

foreach ($Safe in $Safes) {
    $SafeName = $Safe.safeName
    Write-Log "🔹 Retrieving members for Safe: ${SafeName}"

    try {
        # Fetch Safe Members using Get-PASSafeMember
        $SafeMembers = Get-PASSafeMember -SafeName $SafeName

        if ($SafeMembers.Count -eq 0) {
            Write-Log "⚠️ No members found for Safe: ${SafeName}"
        }

        foreach ($Member in $SafeMembers) {
            # Ensure permission values are directly fetched from the API response
            $SafeMembersReport += [PSCustomObject]@{
                SafeName                                    = $SafeName
                Member                                      = $Member.MemberName
                MemberType                                  = $Member.MemberType
                UseAccounts                                = $Member.Permissions.useAccounts
                RetrieveAccounts                           = $Member.Permissions.retrieveAccounts
                ListAccounts                               = $Member.Permissions.listAccounts
                AddAccounts                                = $Member.Permissions.addAccounts
                UpdateAccountContent                      = $Member.Permissions.updateAccountContent
                UpdateAccountProperties                   = $Member.Permissions.updateAccountProperties
                InitiateCPMAccountManagementOperations    = $Member.Permissions.initiateCPMAccountManagementOperations
                SpecifyNextAccountContent                 = $Member.Permissions.specifyNextAccountContent
                RenameAccounts                            = $Member.Permissions.renameAccounts
                DeleteAccounts                            = $Member.Permissions.deleteAccounts
                UnlockAccounts                            = $Member.Permissions.unlockAccounts
                ManageSafe                                = $Member.Permissions.manageSafe
                ManageSafeMembers                         = $Member.Permissions.manageSafeMembers
                BackupSafe                                = $Member.Permissions.backupSafe
                ViewAuditLog                              = $Member.Permissions.viewAuditLog
                ViewSafeMembers                           = $Member.Permissions.viewSafeMembers
                AccessWithoutConfirmation                 = $Member.Permissions.accessWithoutConfirmation
                CreateFolders                             = $Member.Permissions.createFolders
                DeleteFolders                             = $Member.Permissions.deleteFolders
                MoveAccountsAndFolders                    = $Member.Permissions.moveAccountsAndFolders
                RequestsAuthorizationLevel1              = $Member.Permissions.requestsAuthorizationLevel1
                RequestsAuthorizationLevel2              = $Member.Permissions.requestsAuthorizationLevel2
            }
        }
        Write-Log "✅ Retrieved $($SafeMembers.Count) members for Safe: ${SafeName}"
    } catch {
        Write-Log "❌ ERROR: Failed to retrieve members for Safe: ${SafeName} - $_"
    }
}

# Step 4: Export Safe Member Report to CSV
$CsvFilePath = "E:\Installation Media\RemovePendingAccount\SafeMemberReport.csv"  # Update this path as needed
$SafeMembersReport | Export-Csv -Path $CsvFilePath -NoTypeInformation

Write-Log "✅ Safe Member Report successfully exported to: $CsvFilePath"
Write-Log "🔹 Safe Member Report generation completed."
