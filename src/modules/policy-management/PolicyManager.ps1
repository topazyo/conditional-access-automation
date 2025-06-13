# Base class for policy management
class ConditionalAccessPolicyManager {
    [string]$TenantId
    [hashtable]$PolicyConfiguration
    hidden [object]$GraphConnection

    ConditionalAccessPolicyManager([string]$tenantId) {
        $this.TenantId = $tenantId
        $this.Initialize()
    }

    hidden [void]Initialize() {
        try {
            $this.GraphConnection = Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"
            Write-Verbose "Successfully initialized Graph connection"
        }
        catch {
            throw "Failed to initialize Graph connection: $_"
        }
    }

    [hashtable]GetPolicyMap() {
        try {
            $policies = Get-MgIdentityConditionalAccessPolicy
            $policyMap = @{}
            
            foreach ($policy in $policies) {
                $policyMap[$policy.Id] = @{
                    Name = $policy.DisplayName
                    State = $policy.State
                    Conditions = $policy.Conditions
                    GrantControls = $policy.GrantControls
                    RiskLevel = $this.CalculatePolicyRisk($policy)
                }
            }
            return $policyMap
        }
        catch {
            Write-Error "Failed to retrieve policy map: $_"
            throw
        }
    }

    [void]DeployPolicy([hashtable]$policyDefinition) {
        try {
            # Validate the incoming policy definition first
            $this.ValidatePolicyDefinition($policyDefinition)

            $policyName = $policyDefinition.DisplayName
            Write-Verbose "Attempting to deploy policy: '$policyName'."

            # Retrieve all existing policies to check for existence by DisplayName
            # Note: This call can be time-consuming in environments with many policies.
            # Consider optimizing if this becomes a bottleneck (e.g., by maintaining a cache or more specific queries if possible).
            $existingPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
            if ($null -eq $existingPolicies) {
                # This might happen if there are absolutely no policies or if permissions are insufficient (though caught by SilentlyContinue)
                $existingPolicies = @() # Ensure it's an array
                Write-Verbose "No existing policies found or unable to retrieve them. Proceeding to create new policy."
            }

            # Find policies with the same DisplayName
            # DisplayNames are not guaranteed to be unique by Azure AD.
            $matchingPolicies = $existingPolicies | Where-Object { $_.DisplayName -eq $policyName } | Select-Object -First 2 # Select first 2 to detect duplicates

            $foundPolicy = $null
            if ($matchingPolicies.Count -gt 1) {
                Write-Warning "Multiple existing policies found with DisplayName '$policyName'. This is ambiguous. Policy deployment will be skipped for this item."
                Write-Warning "Please ensure Conditional Access Policy DisplayNames are unique if you intend to update them by name."
                # Optionally, throw an error or handle as per specific requirements for duplicates.
                # For now, we skip to prevent unintended updates.
                return # Or throw an exception
            } elseif ($matchingPolicies.Count -eq 1) {
                $foundPolicy = $matchingPolicies[0]
                Write-Verbose "Found existing policy with DisplayName '$policyName' (Id: $($foundPolicy.Id)). Proceeding with update."
            }

            if ($foundPolicy) {
                # Update existing policy
                # The BodyParameter for Update-MgIdentityConditionalAccessPolicy should be the complete policy object.
                # Ensure $policyDefinition includes all necessary properties for an update.
                # Note: The 'Id' property should not be part of the body parameter for update.
                # Graph SDK cmdlets usually take ID as a separate parameter.
                # However, some cmdlets might expect ID in the body. Double check SDK behavior if issues arise.
                # For Update-Mg*, ID is typically a direct parameter.

                # We need to remove 'id' from the hash table if it exists, as it's passed via -ConditionalAccessPolicyId
                # Also, ensure other read-only properties that might have come from a Get- operation are not in $policyDefinition
                # if $policyDefinition was derived from an existing object.
                # For this implementation, assume $policyDefinition is a "clean" definition of desired state.

                # The $policyDefinition *is* the body parameter.
                # If $policyDefinition contains an 'id' key, it might cause issues depending on how the cmdlet handles it.
                # Best practice is to ensure $policyDefinition is purely the desired state representation without read-only fields like 'id', 'createdDateTime', etc.
                # If $policyDefinition comes from a file, it should be clean.

                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $foundPolicy.Id -BodyParameter $policyDefinition
                Write-Verbose "Successfully updated existing policy: '$($policyDefinition.DisplayName)' (Id: $($foundPolicy.Id))"
            }
            else {
                # Create new policy
                # $policyDefinition is already validated.
                $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyDefinition
                Write-Verbose "Successfully deployed new policy: '$($newPolicy.DisplayName)' (Id: $($newPolicy.Id))"
            }
        }
        catch {
            $errorMessage = "Failed to deploy policy '$($policyDefinition.DisplayName)'."
            if ($_.Exception.Message) {
                $errorMessage += " Error: $($_.Exception.Message)"
            }
            if ($_.ErrorDetails.Message) { # For Graph API errors
                 $errorMessage += " Graph Error: $($_.ErrorDetails.Message)"
            }
            Write-Error $errorMessage
            throw # Re-throw the original exception to allow higher-level handling if needed
        }
    }

    [void]RemovePolicy([string]$policyId, [switch]$WhatIf) {
        if ([string]::IsNullOrEmpty($policyId)) {
            throw "Policy ID cannot be empty."
        }

        Write-Verbose "Attempting to remove policy with ID: '$policyId'."

        if ($WhatIf) {
            Write-Host "WhatIf: Would remove Conditional Access Policy with ID: '$policyId'."
            return
        }

        try {
            Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId -ErrorAction Stop
            Write-Host "Successfully removed Conditional Access Policy with ID: '$policyId'."
        }
        catch {
            $errorMessage = "Failed to remove policy with ID '$policyId'. Error: $($_.Exception.Message)"
            Write-Error $errorMessage
            throw # Re-throw the original exception to allow the caller to handle it
        }
    }

    hidden [void]ValidatePolicyDefinition([hashtable]$policy) {
        # Attempt to get DisplayName for more informative error messages
        $policyDisplayNameForError = "'Unnamed Policy'"
        if ($null -ne $policy -and $policy.PSObject.Properties.Name.Contains('DisplayName') -and -not [string]::IsNullOrEmpty($policy.DisplayName)) {
            $policyDisplayNameForError = "'$($policy.DisplayName)'"
        }

        if ($null -eq $policy) {
            throw "Policy definition provided is null. Cannot validate."
        }

        $requiredProperties = @('DisplayName', 'State', 'Conditions', 'GrantControls')
        foreach ($prop in $requiredProperties) {
            # Use PSObject.Properties.Name.Contains for robust key check on PSCustomObject or Hashtable
            if (-not $policy.PSObject.Properties.Name.Contains($prop)) {
                throw "Policy definition ${policyDisplayNameForError} missing required top-level property: '$prop'."
            }
        }

        # Validate 'Conditions' structure
        if ($policy.Conditions -isnot [hashtable] -and $policy.Conditions -isnot [pscustomobject]) {
            throw "Policy ${policyDisplayNameForError}: property 'Conditions' must be a hashtable or object."
        }
        $requiredConditionsKeys = @('Users', 'Applications') # Minimum required condition sets
        foreach ($key in $requiredConditionsKeys) {
            if (-not $policy.Conditions.PSObject.Properties.Name.Contains($key)) {
                throw "Policy ${policyDisplayNameForError}: 'Conditions' property missing required sub-property: '$($key)'."
            }
            # Check if the sub-property itself is of the correct type (hashtable/object)
            # Accessing $policy.Conditions.$key directly is fine after checking key existence
            if ($policy.Conditions.$key -isnot [hashtable] -and $policy.Conditions.$key -isnot [pscustomobject]) {
                throw "Policy ${policyDisplayNameForError}: 'Conditions.$($key)' must be a hashtable or object."
            }
        }
        # Example deeper check (optional for this pass, but good for robustness):
        # if ($policy.Conditions.Users.PSObject.Properties.Name.Contains('includeUsers') -and
        #     $policy.Conditions.Users.includeUsers -isnot [array]) {
        #     throw "Policy ${policyDisplayNameForError}: 'Conditions.Users.includeUsers' should be an array."
        # }


        # Validate 'GrantControls' structure
        if ($policy.GrantControls -isnot [hashtable] -and $policy.GrantControls -isnot [pscustomobject]) {
            throw "Policy ${policyDisplayNameForError}: property 'GrantControls' must be a hashtable or object."
        }
        if (-not $policy.GrantControls.PSObject.Properties.Name.Contains('Operator')) {
            throw "Policy ${policyDisplayNameForError}: 'GrantControls' property missing required sub-property: 'Operator'."
        }
        # Graph API is case-sensitive for 'OR'/'AND' for GrantControls.Operator
        if ($policy.GrantControls.Operator -ne 'OR' -and $policy.GrantControls.Operator -ne 'AND') {
            throw "Policy ${policyDisplayNameForError}: 'GrantControls.Operator' must be 'OR' or 'AND'. Found: '$($policy.GrantControls.Operator)'."
        }
        # Typically, if Operator is OR/AND, BuiltInControls should exist, even if empty array for some "grant" scenarios.
        # If Operator is Block, BuiltInControls might be null or not present, as block is the control.
        # The Graph API might be more lenient here, but for a well-defined policy, Operator implies need for BuiltInControls or CustomAuthenticationFactors.
        if ($policy.GrantControls.Operator -ne "block") { # 'block' is a valid value for GrantControls, but it means no other controls are specified. Graph API actually has GrantControls = $null for block.
             # This check might be too strict as GrantControls can be null for block or include builtInControls = @("block")
             # A more accurate check would be: if ($null -eq $policy.GrantControls.BuiltInControls -and $null -eq $policy.GrantControls.CustomAuthenticationFactors)
             # For now, we ensure Operator is present and valid. The specific structure of grant controls beyond Operator
             # can be quite varied (e.g. can be null if state is 'disabled' and 'enabledForReportingButNotEnforced').
             # The Graph API itself will be the ultimate validator for complex grant control structures.
        }
         Write-Verbose "Policy definition $policyDisplayNameForError passed basic validation."
    }

    hidden [string]CalculatePolicyRisk([object]$policy) {
        $riskScore = 0

        # 1. User Scope Risk
        if ($null -ne $policy.Conditions.Users) {
            # Check for 'All' users first
            if ($policy.Conditions.Users.IncludeUsers -contains 'All') {
                # Differentiate if 'All' includes guests.
                # GuestOrExternalUserTypes 'guestOrExternalUser', 'internalGuest', 'externalMember', 'serviceProvider'
                # If IncludeGuestsOrExternalUsers is used with specific GuestOrExternalUserTypes, it's more targeted than a blanket "All users" that might implicitly include them.
                # For simplicity, if IncludeUsers is 'All', we check ExcludeGuestsOrExternalUsers or specific guest types in ExcludeUsers.
                # A common way 'All Users' might include guests is if no guest-specific exclusions are set.
                # This is a heuristic. The actual meaning of "All" can depend on tenant settings for guests.
                $allUsersIncludesGuests = $true # Assume 'All' includes guests unless explicitly excluded.

                if (($policy.Conditions.Users.ExcludeUsers -ne $null -and $policy.Conditions.Users.ExcludeUsers.Count -gt 0) -or `
                    ($policy.Conditions.Users.ExcludeGuestsOrExternalUsers -ne $null -and $policy.Conditions.Users.ExcludeGuestsOrExternalUsers.Count -gt 0) -or `
                    ($policy.Conditions.Users.IncludeGuestsOrExternalUsers -eq $false) ) { # This property doesn't exist, logic simplified
                    # This is a simplification. A more robust check would inspect the contents of ExcludeUsers for guest-related dynamic groups or roles.
                    # For now, any exclusion when 'All' is included might reduce the "all includes guests" risk.
                    # Let's assume if 'All' is picked and no specific guest *exclusions* are obvious, it's higher risk.
                    # A more direct check would be to see if 'GuestsOrExternalUsers' is part of IncludeUsers, but 'All' is a special keyword.
                }

                if ($policy.Conditions.Users.IncludeGuestsOrExternalUsers -contains "all" -or $policy.Conditions.Users.IncludeGuestsOrExternalUsers -contains "guestsOrExternalUsers" ) { # Check if guests are explicitly included or part of 'all'
                     $riskScore += 4 # 'All' users, explicitly including or implying all guests
                     Write-Verbose "Risk: +4 (All users, including guests)"
                } elseif ($policy.Conditions.Users.IncludeUsers -contains 'All') { # 'All' users, but guests might be excluded or not explicitly included
                    $riskScore += 3
                    Write-Verbose "Risk: +3 (All users, guests status less clear or potentially excluded)"
                }

            } elseif ($null -ne $policy.Conditions.Users.IncludeGroups -and $policy.Conditions.Users.IncludeGroups.Count -gt 5) {
                $riskScore += 2 # Many specific groups
                Write-Verbose "Risk: +2 (Many user groups: $($policy.Conditions.Users.IncludeGroups.Count))"
            } elseif (($null -ne $policy.Conditions.Users.IncludeUsers -and $policy.Conditions.Users.IncludeUsers.Count > 0) -or `
                      ($null -ne $policy.Conditions.Users.IncludeGroups -and $policy.Conditions.Users.IncludeGroups.Count > 0)) {
                $riskScore += 1 # Few specific groups/users
                Write-Verbose "Risk: +1 (Few specific users/groups)"
            }
        } else {
            $riskScore += 1 # No specific user condition might mean it applies broadly depending on other conditions or is an incomplete policy
            Write-Verbose "Risk: +1 (User conditions are null or not defined)"
        }

        # 2. Application Scope Risk
        if ($null -ne $policy.Conditions.Applications) {
            if ($policy.Conditions.Applications.IncludeApplications -contains 'All') {
                $riskScore += 3
                Write-Verbose "Risk: +3 (All applications)"
            } elseif ($null -ne $policy.Conditions.Applications.IncludeApplications -and $policy.Conditions.Applications.IncludeApplications.Count -gt 5) {
                $riskScore += 2 # Many specific applications
                Write-Verbose "Risk: +2 (Many applications: $($policy.Conditions.Applications.IncludeApplications.Count))"
            } elseif ($null -ne $policy.Conditions.Applications.IncludeApplications -and $policy.Conditions.Applications.IncludeApplications.Count > 0) {
                $riskScore += 1 # Few specific applications
                Write-Verbose "Risk: +1 (Few specific applications)"
            }
        } else {
            $riskScore += 1 # No specific app condition
             Write-Verbose "Risk: +1 (Application conditions are null or not defined)"
        }
        
        # Check for legacy authentication (ClientAppTypes condition)
        if ($null -ne $policy.Conditions.ClientAppTypes -and $policy.Conditions.ClientAppTypes -contains 'Other') {
            $riskScore += 2 # Legacy auth is a significant risk factor
            Write-Verbose "Risk: +2 (Legacy authentication client app types allowed/targeted)"
        }

        # 3. Grant Controls (Good controls lower risk score)
        if ($null -ne $policy.GrantControls) {
            if ($policy.GrantControls.BuiltInControls -contains 'mfa') {
                $riskScore -= 2
                Write-Verbose "Risk: -2 (MFA enforced)"
            }
            if ($policy.GrantControls.BuiltInControls -contains 'compliantDevice') {
                $riskScore -= 1
                Write-Verbose "Risk: -1 (Compliant device required)"
            }
            if ($policy.GrantControls.BuiltInControls -contains 'block') {
                $riskScore -= 1 # Blocking access is generally a strong risk mitigation for the matched conditions
                Write-Verbose "Risk: -1 (Access is blocked)"
            }
        }

        # 4. Session Controls
        if ($null -ne $policy.SessionControls -and $null -ne $policy.SessionControls.SignInFrequency) {
            # SignInFrequency.Value is in hours if Type is 'hours', or days if Type is 'days'. Assuming 'Value' holds the numeric part.
            # For simplicity, let's assume if it's set, it's in hours for this heuristic. A more robust check would convert based on 'Type'.
            # A common default for "remember MFA" is 14 days (336 hours). Let's consider > 24 hours a slight risk increase.
            if ($policy.SessionControls.SignInFrequency.Value -gt 24 -and ($policy.SessionControls.SignInFrequency.Type -eq "hours" -or $policy.SessionControls.SignInFrequency.Type -eq "days") ) { # Simplified: if value > 24 (assume hours for basic check)
                 # If type is days, value > 1 (day) is already > 24 hours.
                if ($policy.SessionControls.SignInFrequency.Type -eq "days" -and $policy.SessionControls.SignInFrequency.Value -gt 1){
                     $riskScore += 1
                     Write-Verbose "Risk: +1 (Sign-in frequency $($policy.SessionControls.SignInFrequency.Value) days is long)"
                } elseif ($policy.SessionControls.SignInFrequency.Type -eq "hours" -and $policy.SessionControls.SignInFrequency.Value -gt 24) {
                     $riskScore += 1
                     Write-Verbose "Risk: +1 (Sign-in frequency $($policy.SessionControls.SignInFrequency.Value) hours is long)"
                }
            }
        } else {
            # Sign-in frequency not set or session controls are null
            $riskScore += 1
            Write-Verbose "Risk: +1 (Sign-in frequency not set or session controls are null)"
        }

        Write-Verbose "Final calculated risk score for policy '$($policy.DisplayName)': $riskScore"

        # 5. Risk Level Mapping
        if ($riskScore -ge 5) {
            return 'High'
        }
        elseif ($riskScore -ge 2) {
            return 'Medium'
        }
        else {
            return 'Low' # Handles scores < 2, including negative scores
        }
    }
}