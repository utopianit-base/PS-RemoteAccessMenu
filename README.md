# PS-RemoteAccessMenu
PowerShell based script that displays buttons to access RDP or SSH sessions based on AD group membership.

# Overview
This was designed for use as a cost effective alternative to many of the 3rd party supplier remote access platforms.
The script would be presented to a published desktop on a Windows Server 2022 (for example) RDS farm. Only the
PowerShell script would be published and any high privilege supplier accounts on the AD would be added to a
corresponding AD group to grant access to the published application.

# Usage
The script can be used as a secure menu that's presented to users (e.g. suppliers) to
present buttons based on the servers (or clients) that the user has access to.
Access to governed by AD group membership of Auto Groups where an Admin group is
automatically generated for all computer objects under a certain OU.
The group is added to the local Administrators group of the server by GPO and the
user is added into the group.

The script is designed to be used as an RDS Published Application and is used to only
allow the user to start sanctioned MSTSC.exe sessions.

A Default.RDP file is used as the basis for the MSTSC settings for each connection.
A transaction log is generated under the Logs folder. This can be amended as required.

The script files and config files must be protected so that ONLY local Administrators
of the RDS Session Host server (or whereever it's being run from) have write access
and the users only have read and execute access. No credentials are listed in the
script or config file.

# Modules
The script require the ActiveDirectory and PSScriptMenuGui modules.
The ActiveDirectory functions are used for group checking and the PSScriptMenuGui module is used
to display the dialog box, title and buttons in a flexible and easily scripted manner.

# Security
The security of the solution requires adequate hardening of the RDS servers used as they are expected to ONLY be used
for running MSTSC and Putty. As such, the resource allocations may not need to be overly high, especially with a limited
number of suppliers or internal admin users.

Desktop access for the same group should be denied as this would circumvent the arbitary controls that the script
aims to put in place.

The AD groups governing access to the remote servers must also be heavily controlled with appropriate auditing and process
to ensure that suppliers or internal admins aren't unnecessarily granted access or retain access for a time beyond the initial
requirements.

As with any such custom solution, while this offers a cost effective supplier remote access method, it is not a replacement and lacks
key functionality that may be required by your organisation. Key functions that a 3rd party solution may offer include comprehensive
and non-reputation auditing, one time passwords, two-factor authentication or multi-factor authentication integration and
session recording.

# Icons 
There is an Icons folder that contains ICO files. These are used for the title icon and can be amended as required.
