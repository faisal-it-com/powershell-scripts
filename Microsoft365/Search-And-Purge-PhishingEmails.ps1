<#
.SYNOPSIS
Searches for suspected phishing, scam, or spam emails in Microsoft 365 mailboxes and optionally deletes them.

.DESCRIPTION
This script connects to Microsoft Purview Security & Compliance PowerShell, asks the admin for mandatory
and optional email indicators, creates a Compliance Search, shows the estimated results, and then asks
whether to soft-delete or hard-delete the matched emails.

.NOTES
Author: Faisal
Website: https://faisal.it.com
Category: Exchange Online / Security
License: MIT
Disclaimer: Test before running in production.

REQUIREMENTS:
- ExchangeOnlineManagement PowerShell module
- Microsoft Purview permissions:
  - Compliance Search role to search
  - Search and Purge role to delete
- ExchangeOnlineManagement v3.9.0 or later is recommended for eDiscovery cmdlets with -EnableSearchOnlySession.

IMPORTANT:
- PowerShell purge can remove a maximum of 10 items per mailbox per action.
- Unindexed items are not deleted by New-ComplianceSearchAction -Purge.
- HardDelete is destructive. Use carefully.
#>

# =========================
# Helper Functions
# =========================

function Write-Section {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Read-MandatoryInput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    do {
        $value = Read-Host $Prompt

        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Host "This value is required. Please enter a value." -ForegroundColor Yellow
        }
    }
    while ([string]::IsNullOrWhiteSpace($value))

    return $value.Trim()
}

function Escape-KqlValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.Replace('"', '\"')
}

function Wait-ComplianceSearch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SearchName
    )

    do {
        Start-Sleep -Seconds 10
        $search = Get-ComplianceSearch -Identity $SearchName

        Write-Host "Search status: $($search.Status) | Estimated items: $($search.Items) | Size: $($search.Size)" -ForegroundColor Gray
    }
    while ($search.Status -notin @("Completed", "PartiallySucceeded", "Failed", "Stopped"))

    return $search
}

function Wait-ComplianceSearchAction {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ActionName
    )

    do {
        Start-Sleep -Seconds 10
        $action = Get-ComplianceSearchAction -Identity $ActionName

        Write-Host "Purge status: $($action.Status)" -ForegroundColor Gray
    }
    while ($action.Status -notin @("Completed", "PartiallySucceeded", "Failed", "Stopped"))

    return $action
}

function Parse-SuccessResults {
    param(
        [string]$SuccessResults
    )

    $results = @()

    if ([string]::IsNullOrWhiteSpace($SuccessResults)) {
        return $results
    }

    $lines = $SuccessResults -split "`n"

    foreach ($line in $lines) {
        $cleanLine = $line.Trim()

        if ($cleanLine -match "Location:\s*(?<Mailbox>[^,]+).*Item count:\s*(?<Count>\d+)") {
            $results += [PSCustomObject]@{
                Mailbox   = $matches["Mailbox"].Trim()
                ItemCount = [int]$matches["Count"]
            }
        }
    }

    return $results
}

# =========================
# Start Script
# =========================

Write-Section "Microsoft 365 Phishing / Scam / Spam Email Search and Purge"

Write-Host "This script will search Exchange Online mailboxes for a suspicious email." -ForegroundColor Yellow
Write-Host "You will be asked to confirm before any delete action is started." -ForegroundColor Yellow
Write-Host ""

# =========================
# Check Module
# =========================

Write-Section "Checking PowerShell Module"

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host "ExchangeOnlineManagement module is not installed." -ForegroundColor Red
    Write-Host "Install it first using:" -ForegroundColor Yellow
    Write-Host "Install-Module ExchangeOnlineManagement -Scope CurrentUser" -ForegroundColor White
    return
}

Import-Module ExchangeOnlineManagement

# =========================
# Connect to Microsoft 365 Compliance PowerShell
# =========================

Write-Section "Connect to Microsoft 365 Security & Compliance PowerShell"

$adminUpn = Read-MandatoryInput "Enter your admin UPN"

try {
    Connect-IPPSSession -UserPrincipalName $adminUpn -EnableSearchOnlySession
}
catch {
    Write-Host "Failed to connect using -EnableSearchOnlySession. Trying normal connection..." -ForegroundColor Yellow

    try {
        Connect-IPPSSession -UserPrincipalName $adminUpn
    }
    catch {
        Write-Host "Failed to connect to Security & Compliance PowerShell." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }
}

# =========================
# Mandatory Questions
# =========================

Write-Section "Mandatory Email Information"

$subject = Read-MandatoryInput "Enter the email subject or part of the subject"
$sender  = Read-MandatoryInput "Enter the sender email address"
$dateRaw = Read-MandatoryInput "Enter the received date, for example 2026-06-19"

try {
    $receivedDate = [datetime]::Parse($dateRaw)
}
catch {
    Write-Host "Invalid date format. Please use a format like 2026-06-19." -ForegroundColor Red
    return
}

$startDate = $receivedDate.ToString("yyyy-MM-dd")
$endDate   = $receivedDate.AddDays(1).ToString("yyyy-MM-dd")

# =========================
# Optional Questions
# =========================

Write-Section "Optional Email Information"

$keyword = Read-Host "Optional: Enter a body keyword, URL, domain, or phrase found in the email. Press Enter to skip"
$messageId = Read-Host "Optional: Enter the Internet Message ID if you have it. Press Enter to skip"

Write-Host ""
Write-Host "Search scope:" -ForegroundColor Cyan
Write-Host "1. All Exchange Online mailboxes"
Write-Host "2. Specific mailbox or mailboxes"

$scopeChoice = Read-Host "Choose search scope. Default is 1"

$mailboxes = @("All")

if ($scopeChoice -eq "2") {
    $mailboxInput = Read-MandatoryInput "Enter mailbox email addresses separated by commas"
    $mailboxes = $mailboxInput.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
}

# =========================
# Build KQL Query
# =========================

Write-Section "Building Search Query"

$escapedSubject = Escape-KqlValue $subject
$escapedSender  = Escape-KqlValue $sender

$queryParts = @()

$queryParts += 'subject:"{0}"' -f $escapedSubject
$queryParts += 'from:"{0}"' -f $escapedSender
$queryParts += 'received>={0}' -f $startDate
$queryParts += 'received<{0}' -f $endDate

if (-not [string]::IsNullOrWhiteSpace($keyword)) {
    $escapedKeyword = Escape-KqlValue $keyword.Trim()
    $queryParts += '"{0}"' -f $escapedKeyword
}

if (-not [string]::IsNullOrWhiteSpace($messageId)) {
    $escapedMessageId = Escape-KqlValue $messageId.Trim()
    $queryParts += 'internetmessageid:"{0}"' -f $escapedMessageId
}

$contentMatchQuery = $queryParts -join " AND "

Write-Host "The search query will be:" -ForegroundColor Yellow
Write-Host $contentMatchQuery -ForegroundColor White

Write-Host ""
$confirmQuery = Read-Host "Continue with this search? Type YES to continue"

if ($confirmQuery -ne "YES") {
    Write-Host "Search cancelled." -ForegroundColor Yellow
    return
}

# =========================
# Create and Start Compliance Search
# =========================

Write-Section "Starting Compliance Search"

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$searchName = "Phishing-Search-$timestamp"

try {
    New-ComplianceSearch `
        -Name $searchName `
        -ExchangeLocation $mailboxes `
        -ContentMatchQuery $contentMatchQuery | Out-Null

    Start-ComplianceSearch -Identity $searchName | Out-Null
}
catch {
    Write-Host "Failed to create or start the compliance search." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

Write-Host "Search created: $searchName" -ForegroundColor Green
Write-Host "Waiting for search to complete..." -ForegroundColor Yellow

$completedSearch = Wait-ComplianceSearch -SearchName $searchName

if ($completedSearch.Status -eq "Failed") {
    Write-Host "Search failed. No delete action will be performed." -ForegroundColor Red
    return
}

# =========================
# Show Search Results
# =========================

Write-Section "Search Result Summary"

Write-Host "Search name: $searchName"
Write-Host "Status: $($completedSearch.Status)"
Write-Host "Estimated matched items: $($completedSearch.Items)"
Write-Host "Estimated total size: $($completedSearch.Size)"

$mailboxResults = Parse-SuccessResults -SuccessResults $completedSearch.SuccessResults

if ($mailboxResults.Count -gt 0) {
    Write-Host ""
    Write-Host "Mailboxes with matching items:" -ForegroundColor Cyan
    $mailboxResults | Sort-Object Mailbox | Format-Table Mailbox, ItemCount -AutoSize
}
else {
    Write-Host ""
    Write-Host "Mailbox-level result details were not available in SuccessResults." -ForegroundColor Yellow
}

if ([int]$completedSearch.Items -eq 0) {
    Write-Host "No matching messages found. Nothing to delete." -ForegroundColor Green
    return
}

# =========================
# Ask Delete Type
# =========================

Write-Section "Delete Action"

Write-Host "Choose what to do with the matched emails:" -ForegroundColor Yellow
Write-Host "1. Soft delete - moves messages to Recoverable Items. Safer option."
Write-Host "2. Hard delete - marks messages for permanent removal. Use carefully."
Write-Host "3. Do not delete. Search only."

$deleteChoice = Read-Host "Choose 1, 2, or 3"

switch ($deleteChoice) {
    "1" {
        $purgeType = "SoftDelete"
    }
    "2" {
        $purgeType = "HardDelete"
    }
    "3" {
        Write-Host "No delete action performed." -ForegroundColor Yellow
        return
    }
    default {
        Write-Host "Invalid choice. No delete action performed." -ForegroundColor Red
        return
    }
}

Write-Host ""
Write-Host "You selected: $purgeType" -ForegroundColor Red
Write-Host "This will run a purge action against the search results." -ForegroundColor Red
Write-Host "Reminder: PowerShell purge can remove a maximum of 10 items per mailbox per action." -ForegroundColor Yellow

$finalConfirm = Read-Host "Type DELETE to start the $purgeType action"

if ($finalConfirm -ne "DELETE") {
    Write-Host "Delete action cancelled." -ForegroundColor Yellow
    return
}

# =========================
# Start Purge
# =========================

Write-Section "Starting $purgeType Purge"

try {
    New-ComplianceSearchAction `
        -SearchName $searchName `
        -Purge `
        -PurgeType $purgeType `
        -Confirm:$false | Out-Null
}
catch {
    Write-Host "Failed to start purge action." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

$purgeActionName = "$searchName`_Purge"

Write-Host "Purge action created: $purgeActionName" -ForegroundColor Green
Write-Host "Waiting for purge action to complete..." -ForegroundColor Yellow

$completedAction = Wait-ComplianceSearchAction -ActionName $purgeActionName

# =========================
# Final Result
# =========================

Write-Section "Final Result"

Write-Host "Purge action status: $($completedAction.Status)"
Write-Host "Purge type: $purgeType"
Write-Host "Search name: $searchName"
Write-Host "Purge action name: $purgeActionName"

Write-Host ""
Write-Host "Estimated messages targeted for deletion: $($completedSearch.Items)" -ForegroundColor Cyan

if ($mailboxResults.Count -gt 0) {
    Write-Host ""
    Write-Host "Mailboxes where matching messages were found before purge:" -ForegroundColor Cyan
    $mailboxResults | Sort-Object Mailbox | Format-Table Mailbox, ItemCount -AutoSize
}

Write-Host ""
Write-Host "Important:" -ForegroundColor Yellow
Write-Host "- The number above is based on the Compliance Search result before purge."
Write-Host "- PowerShell purge removes a maximum of 10 items per mailbox per action."
Write-Host "- If more than 10 matching items existed in one mailbox, repeat the search carefully."
Write-Host "- If the mailbox is under hold or retention, the message may be moved out of user view but still retained by Microsoft 365."

Write-Host ""
Write-Host "Done." -ForegroundColor Green
