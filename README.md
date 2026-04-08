# Azure Conditional Access Automation Framework

![Build Status](https://github.com/topazyo/conditional-access-automation/workflows/CA%20Policy%20Deployment/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.2+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Azure](https://img.shields.io/badge/Azure-Entra%20ID-0089D6.svg)](https://azure.microsoft.com/services/active-directory/)

Enterprise-grade automation framework for managing Azure/Entra ID Conditional Access policies at scale. Built from real-world experience managing complex security requirements in mid-to-large organizations.

## 🚀 Features

- **Policy Lifecycle Management**
  - Automated policy deployment and updates via [ConditionalAccessPolicyManager](src/modules/policy-management/policy_manager.ps1)
  - Conflict detection and resolution using [PolicyValidator](src/modules/validation/policy_validator.ps1)
  - Version control and rollback capabilities

# Azure Conditional Access Automation Framework

Lightweight PowerShell framework to define, validate, deploy, and monitor Azure/Entra ID Conditional Access (CA) policies.

This repository contains PowerShell modules and scripts intended for teams that manage Conditional Access at scale and want automated validation, risk scoring, and deployment tooling that can run in CI or locally.

## What This Repo Contains (verified)
- Policy lifecycle management: `src/modules/policy-management/policy_manager.ps1` (ConditionalAccessPolicyManager class)
- Policy validation: `src/modules/validation/policy_validator.ps1`
- Compliance checks: `src/modules/compliance/compliance_manager.ps1`
- Risk scoring: `src/modules/risk/risk_assessor.ps1`
- Monitoring/reporting hooks: `src/modules/reporting/policy_monitor.ps1`
- Deployment scripts and templates: `scripts/deployment/deploy.ps1`, `templates/deployment/ca-policies.yaml`
- Tests: unit and integration tests under `tests/` (Pester)

## Quickstart (minutes)
1. Install prerequisites (PowerShell 7.2+ recommended) and modules:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Install-Module Pester -Scope CurrentUser -Force
```

2. Clone and open the repo in VS Code:

```bash
git clone https://github.com/topazyo/conditional-access-automation.git
cd conditional-access-automation
code .
```

3. Run unit tests:

```powershell
Invoke-Pester ./tests -CI
```

4. (Optional) Deploy example policies to an Azure/Entra tenant. The example deployment script consumes `templates/deployment/ca-policies.yaml`:

```powershell
# Replace <TENANT_ID> and set appropriate credentials or run interactive login
./scripts/deployment/deploy.ps1 -TenantId <TENANT_ID> -ConfigPath ./templates/deployment/ca-policies.yaml
```

Notes:
- The deployment scripts use Microsoft Graph cmdlets when available. If Graph cmdlets are not installed, scripts include offline/test fallbacks for local development and CI mocks.

## Prerequisites
- PowerShell 7.2 or higher
- Microsoft.Graph PowerShell module (for real deployments)
- Pester (for running tests)
- An Azure/Entra tenant and appropriate service principal or user credentials for deployments

## Configuration

Environment variables used by scripts (confirm in your environment):

- `TENANT_ID` (or `-TenantId` parameter): required for real deployments
- `CLIENT_ID`, `CLIENT_SECRET` (CI/service principal secrets — do NOT commit)
- `LOG_ANALYTICS_WORKSPACE_ID` (optional) — referenced by monitoring modules

If you add secrets to your CI, use your platform's secrets store — do not commit credentials.

TODO: Verify exact env var names required by CI workflows and list them here. See `.github/workflows/ca-policy-deployment.yml` for current usage.

## Usage (developer-focused)

- Inspect and import modules in PowerShell for interactive development. Example:

```powershell
Import-Module ./src/modules/policy-management/policy_manager.ps1
$mgr = [ConditionalAccessPolicyManager]::new('<tenant-id>')
# $mgr methods: DeployPolicy, RemovePolicy, EvaluateAccess (see source for exact method names)
```

- Validate individual policy objects using the validator module:

```powershell
Import-Module ./src/modules/validation/policy_validator.ps1
# Call the exported validation functions (see file for function names)
```

- Use `scripts/deployment/deploy.ps1` for end-to-end deployments using YAML templates.

## Project Layout

- `src/modules/` — core PowerShell modules
  - `policy-management/policy_manager.ps1` — main policy manager class
  - `validation/policy_validator.ps1` — validation utilities
  - `compliance/compliance_manager.ps1` — compliance checks
  - `risk/risk_assessor.ps1` — risk scoring functions
  - `reporting/policy_monitor.ps1` — monitoring and Log Analytics hooks
- `scripts/` — operational scripts (deployment, maintenance)
- `templates/` — example configuration and YAML templates for deployment
- `tests/` — Pester unit and integration tests

## CI / Workflows

This repository contains a GitHub Actions workflow: `.github/workflows/ca-policy-deployment.yml`.

Important: the workflow's `validate` job references `PolicyValidator` usage that may not match the current `policy_validator.ps1` API. See TODOs below.

## Troubleshooting

- If Microsoft.Graph cmdlets are missing, install the module or run tests which use offline fallbacks.
- If CI validation fails, compare the workflow's expected method names with the functions in `src/modules/validation/policy_validator.ps1`.
- `PolicyMonitor.ConfigureLogAnalytics` is currently a placeholder — confirm send behavior before using in production.

## Contributing

Please read `CONTRIBUTING.md` for contributor guidelines. Keep changes small and add/update Pester tests for behavior changes.

## Security

Report security issues via the process described in `SECURITY.md`.

## License

MIT — see `LICENSE` for details.

## Changes made
- Rewrote README to be quickstart-first and aligned with current modules and scripts.
- Added TODOs for CI/workflow and env var verification.


This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Microsoft Graph API Documentation](https://docs.microsoft.com/graph/api/resources/conditionalaccesspolicy)
- [Azure/Entra ID Security Best Practices](https://docs.microsoft.com/azure/active-directory/conditional-access/best-practices)
- [PowerShell Team](https://github.com/PowerShell/PowerShell)

## 📊 Project Status

- ✅ Core Policy Management
- ✅ Compliance Engine
- ✅ Risk Assessment
- ✅ Basic Monitoring
- 🔄 Advanced Analytics (In Progress)
- 📅 ML-based Policy Recommendations (Planned)

## 🆘 Support

- For bugs and features, open an issue
- For security issues, see [SECURITY.md](SECURITY.md)
- For questions, join our [Discussions](https://github.com/topazyo/conditional-access-automation/discussions)

---

<p align="center">Made with ❤️ by security engineers for security engineers</p>