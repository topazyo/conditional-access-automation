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

- **Compliance & Risk Management**
  - Built-in compliance frameworks (ISO 27001, NIST 800-53, GDPR) via [ComplianceManager](src/modules/compliance/compliance_manager.ps1)
  - Real-time risk assessment with [RiskAssessor](src/modules/risk/risk_assessor.ps1)
  - Automated compliance reporting

- **Monitoring & Reporting**
  - Advanced policy effectiveness metrics via [PolicyMonitor](src/modules/reporting/policy_monitor.ps1)
  - User impact analysis
  - Custom Azure Monitor workbooks

- **Security & Governance**
  - Just-In-Time privileged access
  - Comprehensive audit logging
  - Role-based access control

## 📋 Prerequisites

- PowerShell 7.2 or higher
- Azure/Entra ID Premium P2 license
- Required Azure AD permissions:
  - Policy.ReadWrite.ConditionalAccess
  - Policy.Read.All
  - Directory.Read.All
  - AuditLog.Read.All

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/topazyo/conditional-access-automation.git
cd conditional-access-automation
```

2. Install required PowerShell modules:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

3. Configure your environment:
```powershell
Copy-Item .env.example .env
# Edit .env with your environment settings
```

## 🚦 Quick Start

1. **Basic Policy Deployment**
```powershell
Import-Module [`src/modules/policy-management/policy_manager.ps1`](src/modules/policy-management/policy_manager.ps1 )

$policyManager = [ConditionalAccessPolicyManager]::new($TenantId)
$policyManager.DeployPolicy("./templates/policies/baseline.yaml")
```

2. **Compliance Assessment**
```powershell
$complianceManager = [ComplianceManager]::new($TenantId)
$report = $complianceManager.AssessCompliance("ISO27001")
$report.GenerateReport("./reports/compliance-$(Get-Date -Format 'yyyyMMdd').pdf")
```

3. **Risk Analysis**
```powershell
$riskAssessor = [RiskAssessor]::new()
$riskReport = $riskAssessor.AnalyzePolicies()
$riskReport.ExportFindings("./reports/risk-assessment.xlsx")
```

## ⚙️ Configuration

| Variable | Required | Default | Description | Where Used |
|----------|----------|---------|-------------|------------|
| TENANT_ID | Yes | - | Azure tenant ID | .github/workflows/ca-policy-deployment.yml |
| CLIENT_ID | Yes | - | Azure app client ID | .github/workflows/ca-policy-deployment.yml |
| CLIENT_SECRET | Yes | - | Azure app client secret | .github/workflows/ca-policy-deployment.yml |

## 📖 Usage

- Deploy policies: `./scripts/deployment/deploy.ps1 -TenantId $TenantId -ConfigPath ./templates/deployment/ca-policies.yaml`
- Run tests: `Invoke-Pester ./tests -CI`
- Cleanup policies: `./scripts/maintenance/policy-cleanup.ps1 -TenantId $TenantId`

## 📁 Project Layout

- `src/modules/`: Core PowerShell classes (policy management, compliance, risk, validation, reporting)
- `templates/`: YAML/JSON configs for policies, reports, deployments
- `tests/`: Unit and integration tests
- `scripts/`: Deployment, maintenance, and setup scripts
- `docs/`: Architecture, deployment, and operations guides

## 🔄 CI/CD

Automated via [.github/workflows/ca-policy-deployment.yml](.github/workflows/ca-policy-deployment.yml): validates policies, runs tests, deploys to staging/production.

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🔒 Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## 📜 License

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