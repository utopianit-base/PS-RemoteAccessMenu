# Supplier Remote Access Menu
# Purpose: Can be used as a secure menu that's presented to users (e.g. suppliers) to
# present buttons based on the servers (or clients) that the user has access to.
# Access to governed by AD group membership of Auto Groups where an Admin group is
# automatically generated for all computer objects under a certain OU.
# The group is added to the local Administrators group of the server by GPO and the
# user is added into the group.
# 
# The script is designed to be used as an RDS Published Application and is used to only
# allow the user to start sanctioned MSTSC.exe sessions.
#
# A Default.RDP file is used as the basis for the MSTSC settings for each connection.
# A transaction log is generated under the Logs folder.
#
# The script files and config files must be protected so that ONLY local Administrators
# of the RDS Session Host server (or whereever it's being run from) have write access
# and the users only have read and execute access. No credentials are listed in the
# script or config file.
#
# Author: chris@utopianit.co.uk
#
#region Setup
Import-Module ActiveDirectory

Set-Location $PSScriptRoot
Remove-Module PSScriptMenuGui -ErrorAction SilentlyContinue

try {
    Import-Module PSScriptMenuGui -ErrorAction Stop
}
catch {
    Write-Warning $_
    Write-Verbose 'Attempting to import from parent directory...' -Verbose
    Import-Module '..\'
}

#endregion

$SAGGroupOU         = "OU=Server Admin Groups,OU=Groups,OU=Development,DC=companyinc,DC=com"
$SupplierUsername   = $env:USERNAME
$Organisationname   = "Company Inc"
$DNSDomainName      = "mydomain.com"
$bAllowGroupNesting = $true # Should group nesting be supported for the Admin groups? If not, make this $False. Has minor performance impact if enabled.
$LogPath            = ".\Logs"                           # Path to Folder used to store logs
$LogDaysToKeep      = 31                                 # Days to keep log files (Default 31 Days)

Function Get-HostNameFromSAG([string]$SAGGroup) {
    # Convert SGG-SAG-DEV-LTHT10-Admin into DEV-LTHT10
    $Result = $SAGGroup.ToUpper().Replace('-ADMIN','').Replace('SGG-SAG-','')
    Return $Result
}


Function Get-MSTSCCommand($Hostname) {
    $Arguments = "Default.rdp /v $($Hostname).$($DNSDomainName):3389 /f /control /noConsentPrompt"
    $Command    = "C:\Windows\System32\MSTSC.exe"
    Return [pscustomobject]@{
        Command   = $Command
        Arguments = $Arguments
    }
}

Function Get-PuttyCommand($Hostname,$SessionLogPath) {
    $Arguments = "-ssh $($Hostname).$($DNSDomainName) -P 22"
    $Command    = "C:\Program Files\Putty\Putty.exe"

    if($SessionLogPath) {
        $Arguments = "$($Arguments) -sessionlog '$($SessionLogPath)'"
    }
    Return [pscustomobject]@{
        Command   = $Command
        Arguments = $Arguments
    }
}

function Get-UserNestedGroups {
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
        
        $groups = @()
    
        # Get all groups the user is a direct member of
        $userGroups = Get-ADPrincipalGroupMembership -Identity $User | Select-Object name,distinguishedname
        
        # Seed the groups to return with the initial direct groups
        $groups = $userGroups

        # Loop through each group
        foreach ($group in $userGroups) {
    
            # Get all nested groups for this group
            $nested = Get-ADGroup -Identity $group.distinguishedname -Properties name | Get-ADGroupMember -Recursive | Where-Object {$_.objectClass -eq 'group'} | Select-Object name,distinguishedname
    
            # Add any nested groups to the list
            $groups += $nested | Select-Object -Unique name,distinguishedname
        }
    
        # Return a custom object with the unique groups
        return ($groups | Select-Object -Unique name,distinguishedname)
    }

#############################################################

# Setup Logging using Transcript
$LogFileDate = Get-Date -Format "yyyyddMM-HHmmss"
$LogFile = "$($LogPath)\SRDS_$($SupplierUsername)_$($LogFileDate).log"

Start-Transcript -Path $LogFile 

$UserObject = Get-ADuser -Identity $SupplierUsername -Properties *

if($true -eq $bAllowGroupNesting) {
    $SAGGroups  = $(Get-UserNestedGroups -User $UserObject | Where-Object distinguishedname -Like "*$SAGGroupOU" | Select-Object distinguishedname).distinguishedname
} else {
    $SAGGroups  = $UserObject.MemberOf -like "*$SAGGroupOU"
}

If($null -eq $SAGGroups) {
    write-host "No access granted." -ForegroundColor Red
    Start-Sleep -Seconds 5
    # Logoff
}

# Remove Cache File
If(Test-Path ".\Cache\$($SupplierUsername).csv") {
    Remove-Item -Path ".\Cache\$($SupplierUsername).csv" -Force
}

ForEach($SAGGroupDN in $SAGGroups) {
    $GroupObject    = Get-ADGroup -Identity $SAGGroupDN -Properties Name,Description
    $ServerHostname = Get-HostNameFromSAG -SAGGroup $GroupObject.Name
    $ServerObject   = Get-ADComputer -Identity $ServerHostname -Properties name,operatingSystem

    if($ServerObject.operatingSystem -match "Windows") {
        $CommandLine    = Get-MSTSCCommand -Hostname $ServerHostname
        $SectionTitle = "RDP Access [$($SupplierUsername)]"
    } else {
        $SessionLogPath = "$($LogPath)\SRDS_$($SupplierUsername)_$($LogFileDate)-SSH.log"
        $CommandLine    = Get-PuttyCommand -Hostname $ServerHostname -SessionLogPath $SessionLogPath
        $SectionTitle = "SSH Access [$($SupplierUsername)]"
    }

    # Generate object to export to CSV for use by the Menu function
    # Section, Method, Command, Arguments, Name, Description
    $ServerAccess = [pscustomobject]@{
        Section     = $SectionTitle
        Method      = "cmd"
        Command     = $CommandLine.Command
        Arguments   = $CommandLine.Arguments
        Name        = $ServerHostname
        Description = $GroupObject.Description
    }

    $ServerAccess | Export-CSV -Path ".\Cache\$($SupplierUsername).csv" -Append
}

$params = @{
    csvPath = ".\Cache\$($SupplierUsername).csv"

    windowTitle = "$($Organisationname) Supplier Remote Access"
    buttonForegroundColor = 'Azure'
    buttonBackgroundColor = '#4034eb'
    iconPath =    ".\Icons\desktop1.ico"
    hideConsole = $true
    noExit = $false
    Verbose = $true
}

Show-ScriptMenuGui @params
Stop-Transcript
# Log off
