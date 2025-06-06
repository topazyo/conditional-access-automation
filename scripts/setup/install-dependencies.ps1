#Requires -Version 5.1

<#
.SYNOPSIS
    Installs necessary PowerShell modules for the project.
.DESCRIPTION
    This script checks for and installs the Microsoft.Graph and Pester PowerShell modules.
    It also checks if the script is run with Administrator privileges, as module installation
    to AllUsers scope typically requires it.
.NOTES
    Ensure your PowerShell execution policy allows running scripts.
    You can check with `Get-ExecutionPolicy` and set it with `Set-ExecutionPolicy`.
    For example, `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`.
#>

# Check for Administrator Privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator privileges are recommended to install modules for all users. Please re-run this script as an Administrator if you encounter issues."
}

# Define a helper function to install modules if they are not already present
function Install-ModuleIfNotExists {
    param (
        [string]$ModuleName,
        [string]$Scope = "CurrentUser" # Default to CurrentUser, can be AllUsers
    )

    Write-Host "Checking if module '$ModuleName' is installed..."
    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Host "Module '$ModuleName' is already installed."
    } else {
        Write-Host "Module '$ModuleName' not found. Attempting to install..."
        try {
            Install-Module $ModuleName -Scope $Scope -Force -Confirm:$false -ErrorAction Stop
            Write-Host "Module '$ModuleName' installed successfully."
        } catch {
            Write-Error "Failed to install module '$ModuleName'. Error: $($_.Exception.Message)"
            Write-Warning "If installing for 'AllUsers', please ensure you are running this script with Administrator privileges."
        }
    }
}

# Install Microsoft.Graph SDK
# This module is used for interacting with Microsoft Graph API.
# Installing for AllUsers is common for SDKs and often requires admin rights.
Install-ModuleIfNotExists -ModuleName "Microsoft.Graph" -Scope "AllUsers"

# Install Pester
# Pester is a testing framework for PowerShell.
# Typically installed for the current user for development and testing purposes.
Install-ModuleIfNotExists -ModuleName "Pester" -Scope "CurrentUser"

Write-Host "Dependency installation script finished."
