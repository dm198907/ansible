# Ensure WinRM is enabled
function Enable-WinRM {
    Write-Output "Enabling WinRM..."
    Enable-PSRemoting -Force
    if ($?) {
        Write-Output "WinRM enabled successfully."
    } else {
        Write-Output "Failed to enable WinRM."
    }
}

# Install the required Windows feature
function Install-WindowsFeature {
    param (
        [string]$FeatureName
    )
    
    Write-Output "Installing feature: $FeatureName..."
    Install-WindowsFeature -Name $FeatureName
    if ($?) {
        Write-Output "Feature $FeatureName installed successfully."
    } else {
        Write-Output "Failed to install feature: $FeatureName."
    }
}

# Configure the firewall to allow WinRM
function Configure-Firewall {
    Write-Output "Configuring firewall for WinRM..."
    
    $firewallRules = @(
        "Allow WinRM HTTP",
        "Allow WinRM HTTPS"
    )
    
    foreach ($rule in $firewallRules) {
        Write-Output "Adding firewall rule: $rule..."
        netsh advfirewall firewall add rule name="$rule" protocol=TCP dir=in localport=5985 action=allow
        if ($?) {
            Write-Output "Firewall rule $rule added successfully."
        } else {
            Write-Output "Failed to add firewall rule: $rule."
        }
    }
}

# Set the LocalAccountTokenFilterPolicy registry value
function Set-LocalAccountTokenFilterPolicy {
    Write-Output "Setting LocalAccountTokenFilterPolicy to 1..."
    
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regName = "LocalAccountTokenFilterPolicy"
    
    if (-not (Test-Path $regPath)) {
        Write-Output "Registry path $regPath does not exist. Creating it..."
        New-Item -Path $regPath -Force
    }
    
    Set-ItemProperty -Path $regPath -Name $regName -Value 1
    if ($?) {
        Write-Output "LocalAccountTokenFilterPolicy set successfully."
    } else {
        Write-Output "Failed to set LocalAccountTokenFilterPolicy."
    }
}

# Main script execution
Write-Output "Starting script execution..."

Enable-WinRM
Install-WindowsFeature -FeatureName "Windows-Server-Backup"
Configure-Firewall
Set-LocalAccountTokenFilterPolicy

Write-Output "Script execution completed."
