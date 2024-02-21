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

<h1>Files and Folders</h1>
The main scripts are numbered from 1 to 5, each having a specific purpose. All requiered files are copied by the file _CreateProfile.ps1 and then being "called" on each stage.

<h2>_CreateProfile.ps1</h2>
This is the first script to be executed. It contains the default user/password (Don't use it in PROD... just a test environment) and depending os VM location, it will either create a PowerShellDirect or PSSession to copy the files and configure the OS to start the overall process. This script is remotely accessing the host, and making remote configurations through the session.

This script will:
Use default (harcoded to the script) uswername and password
Create the corresponding session (Remote PSSession or PowerShell Direct)
Create a NEW local Administrator
Configure display, networkprofile, location, execution policy, default shell, locales, trusted hosts.
Set registry keys for automatic logon
Create Scheduled Task so any user who logon will have CMD and SConfig among the default shell.
Create Scheduled Task that will execute the next script.
Copy all requiered files to the session.
Check if more than 1 disk is configured (in our case DC's have 6 disks, so it will initialize, format and configure accordingly).

Reboot the VM.

<h2>1-BasicConfig.ps1</h2>
This script is already on the host, and is called locally by the previous scheduled task.

<h2>2-AddFeatures.ps1</h2>

<h2>3-PromoteDC.ps1</h2>

<h2>LAPS-Extension.ps1</h2>

<h2>4-ConfigureDom.ps1</h2>

<h2>5-PopulateDom.ps1</h2>
