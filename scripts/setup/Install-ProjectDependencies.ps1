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
        [string]$RequiredVersion = $null, # Add RequiredVersion parameter
        [string]$Scope = "CurrentUser" # Default to CurrentUser, can be AllUsers
    )

    Write-Host "Checking if module '$ModuleName' (Version: $($RequiredVersion | Out-String | ForEach-Object {$_.Trim()}) ) is installed..." # Updated message
    # Check if the specific version is installed
    $moduleInstalled = Get-Module -ListAvailable -Name $ModuleName | Where-Object { $RequiredVersion -eq $null -or $_.Version.ToString() -eq $RequiredVersion }

    if ($moduleInstalled) {
        Write-Host "Module '$ModuleName' (Version: $($RequiredVersion | Out-String | ForEach-Object {$_.Trim()}) ) is already installed." # Updated message
    } else {
        Write-Host "Module '$ModuleName' (Version: $($RequiredVersion | Out-String | ForEach-Object {$_.Trim()}) ) not found or version mismatch. Attempting to install/update..." # Updated message
        try {
            if ($RequiredVersion) {
                Install-Module $ModuleName -RequiredVersion $RequiredVersion -Scope $Scope -Force -Confirm:$false -ErrorAction Stop
            } else {
                Install-Module $ModuleName -Scope $Scope -Force -Confirm:$false -ErrorAction Stop
            }
            Write-Host "Module '$ModuleName' (Version: $($RequiredVersion | Out-String | ForEach-Object {$_.Trim()}) ) installed/updated successfully." # Updated message
        } catch {
            Write-Error "Failed to install module '$ModuleName' (Version: $($RequiredVersion | Out-String | ForEach-Object {$_.Trim()}) ). Error: $($_.Exception.Message)" # Updated message
            Write-Warning "If installing for 'AllUsers', please ensure you are running this script with Administrator privileges."
        }
    }
}

# Install Microsoft.Graph SDK
# This module is used for interacting with Microsoft Graph API.
# Installing for AllUsers is common for SDKs and often requires admin rights.
Install-ModuleIfNotExists -ModuleName "Microsoft.Graph" -RequiredVersion "2.10.0" -Scope "AllUsers"

# Install Pester
# Pester is a testing framework for PowerShell.
# Typically installed for the current user for development and testing purposes.
Install-ModuleIfNotExists -ModuleName "Pester" -RequiredVersion "5.5.0" -Scope "CurrentUser"

Write-Host "Dependency installation script finished."
