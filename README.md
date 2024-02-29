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

More info at:
 <a href="https://eguibarit.eu/automate-lab-environment-setup/>EguibarIT Automated Lab Setup</a>

<h1>Files and Folders</h1>
The main scripts are numbered from 1 to 5, each having a specific purpose. All requiered files are copied by the file _CreateProfile.ps1 and then being "called" on each stage.

<h2>_CreateProfile.ps1</h2>
This is the first script to be executed. It contains the default user/password (Don't use it in PROD... just a test environment) and depending os VM location, it will either create a PowerShellDirect or PSSession to copy the files (from a Harcoded path. This will have to change!!!) and configure the OS to start the overall process. This script is remotely accessing the host, and making remote configurations through the session.

This script will:
<ul>
<li>Use default (harcoded to the script) uswername and password</li>
<li>Create the corresponding session (Remote PSSession or PowerShell Direct)</li>
<li>Create a NEW local Administrator</li>
<li>Configure display, networkprofile, location, execution policy, default shell, locales, trusted hosts.</li>
<li>Set registry keys for automatic logon</li>
<li>Create Scheduled Task so any user who logon will have CMD and SConfig among the default shell.</li>
<li>Create Scheduled Task that will execute the next script.</li>
<li>Copy all requiered files to the session.</li>
<li>Check if more than 1 disk is configured (in our case DC's have 6 disks, so it will initialize, format and configure accordingly).</li>
</ul>
Reboot the VM.

<h2>1-BasicConfig.ps1</h2>
This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.
The main goal of this script is to have a basic, secure OS to start working with.

This script will:
<ul>
<li>Set a transcript output</li>
<li>Import the corresponding modules</li>
<li>Load the XML configuration file</li>
<li>Check and configure IPv4 and IPv6 stack</li>
<li>Fine-Tune network card and TCP</li>
<li>Apply security settings</li>
<li>Define services startup (Automatic, Manual & Disabled)</li>
<li>Download modules from PowerShellGallery (of course EguibarIT modules :-))</li>
<li>Check and install lates PowerShell</li>
<li>Check and change ComputerName, Organization, Time sync</li>
<li>Rename default Administrator account</li>
<li>Set registry keys for automatic logon</li>
<li>Create Scheduled Task that will execute the next script.</li>
<li>Configure Power options</li>
<li>Install .NET 3.x</li>
<li>Configure Boot</li>
<li>Apply security template (SecTemp.inf)</li>
</ul>
Reboot the VM.

<h2>2-AddFeatures.ps1</h2>
This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.
The main goal of this script is to install all needed features.

This script will:
<ul>
<li>Set a transcript output</li>
<li>Import the corresponding modules</li>
<li>Load the XML configuration file</li>
<li>Install DNS feature</li>
<li>Install DNS Management feature if not Core</li>
<li>Install .Net Framework feature</li>
<li>Install File Server feature</li>
<li>Install File Server Management feature if not Core</li>
<li>Install DFS-Namespace feature</li>
<li>Install DFS Management feature if not Core</li>
<li>Install DFS-Replication feature</li>
<li>Install Group Policy Management feature</li>
<li>Install Windows Backup feature</li>
<li>Install AD-Domain-Services feature</li>
<li>Install AD-Domain-Services feature if not Core</li>
<li>Add IPv4 & IPv6 DNS reverse lookup zones</li>
<li>Set registry keys for automatic logon</li>
<li>Create Scheduled Task that will execute the next script.</li>
</ul>
Reboot the VM.

<h2>3-PromoteDC.ps1</h2>
This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.
The main goal of this script is to promote the server to the first domain controller.

This script will:
<ul>
<li>Set a transcript output</li>
<li>Import the corresponding modules</li>
<li>Load the XML configuration file</li>
<li>Check if more than 1 disk is configured (in our case DC's have 6 disks, so it will initialize, format and configure accordingly).</li>
<li>Promote the server to the First Domain Controller in the new forest.</li>
<li>Set default domain</li>
<li>Set registry keys for automatic logon</li>
<li>Read configuration if needs LAPS extension or not. Schedule task with the corresponding script.</li>
</ul>
Reboot the VM.

<h2>LAPS-Extension.ps1</h2>
This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.
The main goal of this script is to verify LAPS Schema extension exists. Add it in case it does not.

This script will:
<ul>
<li>Set a transcript output</li>
<li>Import the corresponding modules</li>
<li>Load the XML configuration file</li>
<li>Read all schema attributes and store it on $guidMap variable. This will show if LAPS extension exists or not.</li>
<li>Set registry keys for automatic logon</li>
<li>Check for LAPS attribute, Schema Admin privileges and extend schema. Additional reboot might be needed.</li>
<li>Create Scheduled Task that will execute the next script.</li>
</ul>
Reboot the VM.

<h2>4-ConfigureDom.ps1</h2>
This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.

This script will:
<ul>
<li>Set a transcript output</li>
<li>Import the corresponding modules</li>
<li>Load the XML configuration file</li>
<li>Define Naming Conventions Hashtable</li>
<li>Get SYSVOL location</li>
<li>Copy BGInfo and some scripts to NETLOGON</li>
<li>Configure DNS zones (Forward and Reverse) to be AD integrated, Set Ageing and Scavenging and define default forwarders.</li>
<li>Normalize (rename) Admin and Guest in case those aren't correct.</li>
<li>Read Configuration in order to define which additional "roles" must be created.</li>
<li>Implement Tiering & Delegation Model (New-CentralItOU)</li>
<li>Create and Configure new GPOs</li>
<li>Create new Sites and Subnets (IPv4 & IPv6).</li>
<li>Create and Configure DFS shares</li>
<li>Create Group Policy Repository (PolicyDefinition) and copy latest ADMX/ADML templates</li>
<li>Enable Recycle-Bin</li>
<li>Remove default permission for all users to add workstations to the domain</li>
<li>Add UPN suffixes to the domain</li>
<li>Set registry keys for automatic logon</li>
<li>Create Scheduled Task that will execute the next script.</li>
</ul>
Reboot the VM.

<h2>5-PopulateDom.ps1</h2>
This script is already on the host on the PsScript folder on the C: drive, and is called locally by the previous scheduled task.

This script will:
<ul>
<li>Set a transcript output</li>
<li>Import the corresponding modules</li>
<li>Load the XML configuration file</li>
<li>Define Naming Conventions Hashtable</li>
<li>Read users CSV file and create any SITE OU defined</li>
<li>Read users CSV file and create each user (172 users)</li>
<li>Read ServiceAccounts CSV and create all SA, MSA and gMSA in the list, each per defined tier</li>
<li>Read group CSV file and create each group with its corresponding membership</li>
<li>Read Share CSV file and create each share with its corresponding group & group membership</li>
<li>Create Semi-Privileged users on Tier0, Tier1 and Tier2</li>
<li>Grant roles to each previous created Semi-Privileged user</li>
<li>Set default password (don't do this in PROD) and never expire PWD for above mentioned accounts.</li>
<li>Pre-stage Privileged Access Workstations (PAWs) on Tier0, Tier1 and Tier2</li>
<li>Get DC gMSA to schedule housekeeping tasks and grant access to all Domain Controllers.</li>
<li>Housekeeping Admincount on Users and Groups</li>
<li>Housekeeping Privileged Users</li>
<li>Housekeeping Privileged Computers</li>
<li>Housekeeping Privileged Groups</li>
<li>Housekeeping NON Privileged Groups</li>
<li>Housekeeping Semi-Privileged Key Pair</li>
<li>Housekeeping for Service Accounts</li>
</ul>
Reboot the VM.

<h1>Folders</h1>
Some folders are needed in order to run the scripts and associated functions

<h2>Pic</h2>
This folder contains pic in jpg format for each user defined on the Users CSV file. This file is sized so the pic can be uploaded to the User object "thumbnailphoto" attribute. Although this is not necessary, this setup uses a Logon Script that creates the corresponding files on the disk, and the registry keys, so when the user logon the pic is displayed.

<h2>SecTmpl</h2>
This folder contains the GPO templates used on the environment. When creating the OU's, if a backup key is present (GUID), it will look into this folder. If backup GPO exist, it will automatically import the settings.
If any new GPO is exported, the content under the GUID folder can be placed here.

<h3>MapGuidsToGpoNames.ps1</h3>
Working with GUID as folder names is not easy. In order to identify those folders this script will translate the GUIDs to the name of each GPO.

<h1>Configuration Files</h1>
All configuration files used are XML. The main file is called Config.XML, but any other file with different data might be parsed to the scripts, meanwhile the node structure is respected and it contains the needed information.

<h1>CSV Files</h1>
These files contain data to create objects, as Service accounts, Shares or users.

<h2>group.csv</h2>
List of groups, with Group Membership and destination site OU.

<h2>mngdsvcacc.csv</h2>
List of Service Accounts, group membership and assigned Tier

<h2>Shares.csv</h2>
List of shares to be created on each Site OU

<h2>StarWars-Users.csv</h2>
Full list of users, with many attributes, to create on its corresponding Site OU

<h1>Other Files</h1>

<h2>Convert-To-Ad-Thumbnail.ps1</h2>
Function that reduces size so it can be uploaded to AD "thumbnailphoto" attribute

<h2>Enable FW for Remote Management.txt</h2>
File with some PowerShell code to configure host-based firewall for remote administration

<h2>SecTemp.inf</h2>
Security Template file with initial configuration for the windows device. Beside the many settings this file contains, there are 2 important ones for our automated setup.

<b>Rename Administrator account</b> This will rename the default Administrator account to whatever name is provided. Due this fact, script 1-BasicConfig.ps1 is executed under the second admin account generated on previous step. Failing to do will generate an error of kind "Security Mapping" truncating the script.

<b>Logon Banner (Title & Message)</b> Although nice to have, if this is present, the automated logon will not work.

<h2>Set-ADAllAdminPictures.ps1</h2>
As mentioned above, there are pic for each user created. These scripts do upload the pics into AD. For the pic to be displayed on windows, several folders, registry keys and defined size JPG files must exist; and are created at the first logon. This script does this for all defined users, so first logon of those, the pic is displayed.

<h2>Set-ADPicture.ps1</h2>
This script is copied to the NETLOGON folder, and using a GPO Scheduled task, it will be triggered at every logon of any user. This file helps display the individual PIC of the user.

<h2>Unattend.xml</h2>
Windows Unattend file for automatic deployment and configuration of the OS.
