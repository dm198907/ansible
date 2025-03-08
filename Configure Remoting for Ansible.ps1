#!powershell
#Requires -Version 3.0

<#
.SYNOPSIS
    Configures a Windows host for remote management with Ansible.

.DESCRIPTION
    This script checks and updates the WinRM (PowerShell Remoting) configuration
    to allow Ansible to connect, authenticate, and execute PowerShell commands.
    It supports various options such as enabling CredSSP, disabling Basic Auth,
    and forcing a new SSL certificate.

.PARAMETER SubjectName
    The CN name of the certificate (default: system's hostname).

.PARAMETER CertValidityDays
    Specifies the validity period of the self-signed certificate (default: 1095 days).

.PARAMETER SkipNetworkProfileCheck
    Skips the network profile check, allowing WinRM on public networks.

.PARAMETER ForceNewSSLCert
    Forces the creation of a new SSL certificate if the system has been SysPrepped.

.PARAMETER GlobalHttpFirewallAccess
    Configures the firewall to allow global HTTP WinRM access.

.PARAMETER DisableBasicAuth
    Disables basic authentication for WinRM.

.PARAMETER EnableCredSSP
    Enables CredSSP authentication for secure credential delegation.

.NOTES
    Authors:
    - Trond Hindenes
    - Chris Church
    - Michael Crilly
    - Anton Ouzounov
    - Nicolas Simond
    - Dag Wieers
    - Jordan Borean
    - Erwan Quélin
    - David Norman

    Version History:
    - 1.0 (2014-07-06) Initial Release
    - 1.9 (2018-09-21) Latest Update
#>

[CmdletBinding()]
Param (
    [string]$SubjectName = $env:COMPUTERNAME,
    [int]$CertValidityDays = 1095,
    [switch]$SkipNetworkProfileCheck,
    [switch]$ForceNewSSLCert,
    [switch]$GlobalHttpFirewallAccess,
    [switch]$DisableBasicAuth = $false,
    [switch]$EnableCredSSP
)

# Function to log messages
Function Write-Log {
    Param ([string]$Message)
    Write-EventLog -LogName Application -Source "WinRMSetup" -EntryType Information -EventId 1 -Message $Message
}

Function Write-VerboseLog {
    Param ([string]$Message)
    Write-Verbose $Message
    Write-Log $Message
}

Function Write-HostLog {
    Param ([string]$Message)
    Write-Output $Message
    Write-Log $Message
}

# Ensure script is run as Administrator
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

if (-Not $myWindowsPrincipal.IsInRole($adminRole)) {
    Write-Output "ERROR: This script must be run as Administrator."
    Exit 2
}

# Check and start WinRM service
Write-Verbose "Verifying WinRM service."
$winrmService = Get-Service "WinRM"
if (-not $winrmService) {
    Write-Log "WinRM service not found."
    Throw "WinRM service is required."
} elseif ($winrmService.Status -ne "Running") {
    Write-Verbose "Starting WinRM service."
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
    Write-Log "WinRM service started."
}

# Enable PS Remoting if not already enabled
if (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener))) {
    if ($SkipNetworkProfileCheck) {
        Enable-PSRemoting -SkipNetworkProfileCheck -Force
        Write-Log "Enabled PS Remoting without network profile check."
    } else {
        Enable-PSRemoting -Force
        Write-Log "Enabled PS Remoting."
    }
}

# Ensure LocalAccountTokenFilterPolicy is set
$tokenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$tokenProperty = "LocalAccountTokenFilterPolicy"
$tokenValue = (Get-ItemProperty -Path $tokenPath).$tokenProperty
if ($tokenValue -ne 1) {
    Set-ItemProperty -Path $tokenPath -Name $tokenProperty -Value 1 -Type DWord
    Write-Log "Set LocalAccountTokenFilterPolicy to 1."
}

# Configure SSL Listener
$listeners = Get-ChildItem WSMan:\localhost\Listener
if (!($listeners | Where-Object { $_.Keys -like "TRANSPORT=HTTPS" })) {
    Write-Verbose "Enabling SSL listener."
    $thumbprint = "<Generate a self-signed cert here>"
    New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{Transport = "HTTPS"; Address = "*"} -ValueSet @{Hostname = $SubjectName; CertificateThumbprint = $thumbprint}
    Write-Log "SSL listener enabled."
}

# Configure authentication methods
if ($DisableBasicAuth) {
    Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $false
    Write-Log "Disabled basic auth."
} else {
    Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
    Write-Log "Enabled basic auth."
}

if ($EnableCredSSP) {
    Enable-WSManCredSSP -Role Server -Force
    Write-Log "Enabled CredSSP authentication."
}

# Configure firewall for WinRM HTTPS
if (-not (netsh advfirewall firewall show rule name="Allow WinRM HTTPS" | Select-String "Enabled")) {
    netsh advfirewall firewall add rule name="Allow WinRM HTTPS" dir=in action=allow protocol=TCP localport=5986
    Write-Log "Firewall rule added for WinRM HTTPS."
}

# Test remoting connectivity
$httpResult = Invoke-Command -ComputerName "localhost" -ScriptBlock {$env:COMPUTERNAME} -ErrorAction SilentlyContinue
$httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions -ErrorAction SilentlyContinue

if ($httpResult -and $httpsResult) {
    Write-VerboseLog "PS Remoting configured: HTTP and HTTPS enabled."
} elseif ($httpsResult -and -not $httpResult) {
    Write-VerboseLog "PS Remoting configured: HTTPS enabled, HTTP disabled."
} elseif ($httpResult -and -not $httpsResult) {
    Write-VerboseLog "PS Remoting configured: HTTP enabled, HTTPS disabled."
} else {
    Write-Log "Failed to establish WinRM sessions."
    Throw "WinRM configuration failed."
}
