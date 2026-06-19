<#
.SYNOPSIS
Gets Exchange Online mailbox archive size information.

.DESCRIPTION
This script connects to Exchange Online and displays archive mailbox information for users.

.NOTES
Author: Faisal
License: MIT
Disclaimer: Test before running in production.
#>

# Connect to Exchange Online
Connect-ExchangeOnline

# Get mailboxes with archive information
Get-Mailbox -ResultSize Unlimited | Select-Object `
    DisplayName,
    UserPrincipalName,
    ArchiveStatus,
    AutoExpandingArchiveEnabled
