<p align="center">
  <a href="https://github.com/vreguibar/EguibarIT.AutoLabSetup"><img src="https://img.shields.io/github/license/vreguibar/EguibarIT.AutoLabSetup.svg"></a>
  <a href="https://github.com/vreguibar/EguibarIT.AutoLabSetup"><img src="https://img.shields.io/github/languages/top/vreguibar/EguibarIT.AutoLabSetup.svg"></a>
  <a href="https://github.com/vreguibar/EguibarIT.AutoLabSetup"><img src="https://img.shields.io/github/languages/code-size/vreguibar/EguibarIT.AutoLabSetup.svg"></a>
</p>

<p align="center">
  <a href="https://www.linkedin.com/in/VicenteRodriguezEguibar"><img src="https://img.shields.io/badge/LinkedIn-VicenteRodriguezEguibar-0077B5.svg?logo=LinkedIn"></a>
</p>

# EguibarIT.AutoLabSetup

Automated scripts to provision and setup an AD environment (Including Delegation Model &amp; Tier Model)

## Files and Folders

The main scripts are numbered from 1 to 5, each having a specific purpose. All requiered files are copied by the file _CreateProfile.ps1 and then being "called" on each stage.

## _CreateProfile.ps1

This is the first script to be executed. It contains the default user/password (Don't use it in PROD... just a test environment) and depending os VM location, it will either create a PowerShellDirect or PSSession to copy the files (from a harcoded path. This will have to change!!!) and configure the OS to start the overall process. This script is remotely accessing the host, and making remote configurations through the session.

This script will:

- Use default (harcoded to the script) uswername and password
- Create the corresponding session (Remote PSSession or PowerShell Direct)
- Create a NEW local Administrator
- Configure display, networkprofile, location, execution policy, default shell, locales, trusted hosts.
- Set registry keys for automatic logon
- Create Scheduled Task so any user who logon will have CMD and SConfig among the default shell.
- Create Scheduled Task that will execute the next script.
- Copy all requiered files to the session.
- Check if more than 1 disk is configured (in our case DC's have 6 disks, so it will initialize, format and configure accordingly).

Reboot the VM.

## 1-BasicConfig.ps1

This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.
The main goal of this script is to have a basic, secure OS to start working with.

This script will:

- Set a transcript output
- Import the corresponding modules
- Load the XML configuration file
- Check and configure IPv4 and IPv6 stack
- Fine-Tune network card and TCP
- Apply security settings
- Define services startup (Automatic, Manual & Disabled)
- Download modules from PowerShellGallery (of course EguibarIT modules :-))
- Check and install lates PowerShell
- Check and change ComputerName, Organization, Time sync
- Rename default Administrator account
- Set registry keys for automatic logon
- Create Scheduled Task that will execute the next script.
- Configure Power options
- Install .NET 3.x
- Configure Boot
- Apply security template (SecTemp.inf)

Reboot the VM.

## 2-AddFeatures.ps1

This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.
The main goal of this script is to install all needed features.

This script will:

- Set a transcript output
- Import the corresponding modules
- Load the XML configuration file
- Install DNS feature
- Install DNS Management feature if not Core
- Install .Net Framework feature
- Install File Server feature
- Install File Server Management feature if not Core
- Install DFS-Namespace feature
- Install DFS Management feature if not Core
- Install DFS-Replication feature
- Install Group Policy Management feature
- Install Windows Backup feature
- Install AD-Domain-Services feature
- Install AD-Domain-Services feature if not Core
- Add IPv4 & IPv6 DNS reverse lookup zones
- Set registry keys for automatic logon
- Create Scheduled Task that will execute the next script.

Reboot the VM.

## 3-PromoteDC.ps1

This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.
The main goal of this script is to promote the server to the first domain controller.

This script will:

- Set a transcript output
- Import the corresponding modules
- Load the XML configuration file
- Check if more than 1 disk is configured (in our case DC's have 6 disks, so it will initialize, format and configure accordingly).
- Promote the server to the First Domain Controller in the new forest.
- Set default domain
- Set registry keys for automatic logon
- Read configuration if needs LAPS extension or not. Schedule task with the corresponding script.

Reboot the VM.

## LAPS-Extension.ps1

This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.
The main goal of this script is to verify LAPS Schema extension exists. Add it in case it does not.

This script will:

- Set a transcript output
- Import the corresponding modules
- Load the XML configuration file
- Read all schema attributes and store it on $guidMap variable. This will show if LAPS extension exists or not.
- Set registry keys for automatic logon
- Check for LAPS attribute, Schema Admin privileges and extend schema. Additional reboot might be needed.
- Create Scheduled Task that will execute the next script.

Reboot the VM.

## 4-ConfigureDom.ps1

This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.

This script will:

- Set a transcript output
- Import the corresponding modules
- Load the XML configuration file
- Define Naming Conventions Hashtable
- Get SYSVOL location
- Copy BGInfo and some scripts to NETLOGON
- Configure DNS zones (Forward and Reverse) to be AD integrated, Set Ageing and Scavenging and define default forwarders.
- Normalize (rename) Admin and Guest in case those aren't correct.
- Read Configuration in order to define which additional "roles" must be created.
- Implement Tiering & Delegation Model (New-CentralItOU)
- Create and Configure new GPOs
- Create new Sites and Subnets (IPv4 & IPv6).
- Create and Configure DFS shares
- Create Group Policy Repository (PolicyDefinition) and copy latest ADMX/ADML templates
- Enable Recycle-Bin
- Remove default permission for all users to add workstations to the domain
- Add UPN suffixes to the domain
- Set registry keys for automatic logon
- Create Scheduled Task that will execute the next script.

Reboot the VM.

## 5-PopulateDom.ps1

This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.

This script will:

- Set a transcript output
- Import the corresponding modules
- Load the XML configuration file
- Define Naming Conventions Hashtable
- Read users CSV file and create any SITE OU defined
- Read users CSV file and create each user (172 users)
- Read ServiceAccounts CSV and create all SA, MSA and gMSA in the list, each per defined tier
- Read group CSV file and create each group with its corresponding membership
- Read Share CSV file and create each share with its corresponding group & group membership
- Create Semi-Privileged users on Tier0, Tier1 and Tier2
- Grant roles to each previous created Semi-Privileged user
- Set default password (don't do this in PROD) and never expire PWD for above mentioned accounts.
- Pre-stage Privileged Access Workstations (PAWs) on Tier0, Tier1 and Tier2
- Get DC gMSA to schedule housekeeping tasks and grant access to all Domain Controllers.
- Housekeeping Admincount on Users and Groups
- Housekeeping Privileged Users
- Housekeeping Privileged Computers
- Housekeeping Privileged Groups
- Housekeeping NON Privileged Groups
- Housekeeping Semi-Privileged Key Pair
- Housekeeping for Service Accounts

Reboot the VM.

# Folders

Some folders are needed in order to run the scripts and associated functions

## Pic

This folder contains pic in jpg format for each user defined on the Users CSV file. This file is sized so the pic can be uploaded to the User object "thumbnailphoto" attribute. Although this is not necessary, this setup uses a Logon Script that creates the corresponding files on the disk, and the registry keys, so when the user logon the pic is displayed.

## SecTmpl

This folder contains the GPO templates used on the environment. When creating the OU's, if a backup key is present (GUID), it will look into this folder. If backup GPO exist, it will automatically import the settings.
If any new GPO is exported, the content under the GUID folder can be placed here.

### MapGuidsToGpoNames.ps1

Working with GUID as folder names is not easy. In order to identify those folders this script will translate the GUIDs to the name of each GPO.

# Configuration Files

All configuration files used are XML. The main file is called Config.XML, but any other file with different data might be parsed to the scripts, meanwhile the node structure is respected and it contains the needed information.

# CSV Files

These files contain data to create objects, as Service accounts, Shares or users.

## group.csv

List of groups, with Group Membership and destination site OU.

## mngdsvcacc.csv

List of Service Accounts, group membership and assigned Tier

## Shares.csv

List of shares to be created on each Site OU

## StarWars-Users.csv

Full list of users, with many attributes, to create on its corresponding Site OU

# Other Files

## Convert-To-Ad-Thumbnail.ps1

Function that reduces size so it can be uploaded to AD "thumbnailphoto" attribute

## Enable FW for Remote Management.txt

File with some PowerShell code to configure host-based firewall for remote administration

## SecTemp.inf

Security Template file with initial configuration for the windows device. Beside the many settings this file contains, there are 2 important ones for our automated setup.

<b>Rename Administrator account</b> This will rename the default Administrator account to whatever name is provided. Due this fact, script 1-BasicConfig.ps1 is executed under the second admin account generated on previous step. Failing to do will generate an error of kind "Security Mapping" truncating the script.

<b>Logon Banner (Title & Message)</b> Although nice to have, if this is present, the automated logon will not work.

## Set-ADAllAdminPictures.ps1

As mentioned above, there are pic for each user created. These scripts do upload the pics into AD. For the pic to be displayed on windows, several folders, registry keys and defined size JPG files must exist; and are created at the first logon. This script does this for all defined users, so first logon of those, the pic is displayed.

## Set-ADPicture.ps1

This script is copied to the NETLOGON folder, and using a GPO Scheduled task, it will be triggered at every logon of any user. This file helps display the individual PIC of the user.

## Unattend.xml

Windows Unattend file for automatic deployment and configuration of the OS.
