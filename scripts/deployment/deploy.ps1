param (
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$true)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Import required modules
Import-Module "./src/modules/policy-management/policy_manager.ps1"

# Initialize logging
$logPath = "./logs/deployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $logPath

try {
    # Load configuration
    $config = Get-Content $ConfigPath | ConvertFrom-Json
    
    # Initialize policy manager
    $policyManager = [ConditionalAccessPolicyManager]::new($TenantId)
    
    # Deploy policies
    foreach ($policy in $config.policies) {
        Write-Host "Deploying policy: $($policy.DisplayName)"
        
        if (-not $WhatIf) {
            $policyManager.DeployPolicy($policy)
        }
        else {
            Write-Host "WhatIf: Would deploy policy $($policy.DisplayName)"
        }
    }
}
catch {
    Write-Error "Deployment failed: $_"
    throw
}
finally {
    Stop-Transcript
}