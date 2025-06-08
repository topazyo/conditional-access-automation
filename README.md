# Azure Conditional Access Automation Framework

![Build Status](https://github.com/yourusername/ca-automation/workflows/CA%20Policy%20Deployment/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.2+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Azure](https://img.shields.io/badge/Azure-Entra%20ID-0089D6.svg)](https://azure.microsoft.com/services/active-directory/)

Enterprise-grade automation framework for managing Azure/Entra ID Conditional Access policies at scale. Built from real-world experience managing complex security requirements in mid-to-large organizations.

## 🚀 Features

- **Policy Lifecycle Management**
  - Automated policy deployment and updates
  - Conflict detection and resolution
  - Designed for integration with version control systems (e.g., Git) for policy-as-code lifecycle management.

- **Compliance & Risk Management**
  - Built-in compliance frameworks (ISO 27001, NIST 800-53, GDPR)
  - Real-time risk assessment
  - Automated compliance reporting

- **Monitoring & Reporting**
  - Advanced policy effectiveness metrics
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
git clone https://github.com/yourusername/ca-automation.git
cd ca-automation
```

2. Install required PowerShell modules:
```powershell
./scripts/setup/Install-ProjectDependencies.ps1
```

3. Configure your environment:
```powershell
Copy-Item .env.example .env
# Edit .env with your environment settings (ensure .env is in .gitignore)
```

## 🚦 Quick Start

1. **Basic Policy Deployment**
```powershell
Import-Module ./src/modules/policy-management/PolicyManager.ps1

$policyManager = [ConditionalAccessPolicyManager]::new($TenantId)
$policyManager.DeployPolicy("./templates/policies/security-baseline.yaml")
```

2. **Compliance Assessment**
```powershell
Import-Module ./src/modules/compliance/ComplianceManager.ps1 # Ensure module is imported

$complianceManager = [ComplianceManager]::new($TenantId)
# For custom frameworks: $customFrameworks = @{...}; $complianceManager = [ComplianceManager]::new($TenantId, $customFrameworks)

$reportFramework = "ISO27001"
$reportOutputPath = "./reports/compliance-$reportFramework-$(Get-Date -Format 'yyyyMMdd').csv"
$complianceManager.GenerateComplianceReport($reportFramework, $reportOutputPath)
Write-Host "Compliance report generated at $reportOutputPath"
```

3. **Risk Analysis**
```powershell
Import-Module ./src/modules/risk/RiskAssessor.ps1 # Ensure module is imported
Import-Module ./src/modules/policy-management/PolicyManager.ps1 # To get policies

$policyMgr = [ConditionalAccessPolicyManager]::new($TenantId)
# Get-MgIdentityConditionalAccessPolicy requires Graph connection, PolicyManager handles this.
# Retrieve actual policy objects for analysis.
$allCaPolicies = Get-MgIdentityConditionalAccessPolicy -All # Assuming connection is established.
                                                                # Or use $policyMgr.GetPolicyMap().Values if only basic properties are needed by RiskAssessor.
                                                                # For GenerateRiskReport, full policy objects are better.

$riskAssessor = [RiskAssessor]::new()
# For custom risk model: $customFactors = @{...}; $customWeights = @{...}; $riskAssessor = [RiskAssessor]::new($customFactors, $customWeights)

$riskReportData = $riskAssessor.GenerateRiskReport($allCaPolicies) # GenerateRiskReport expects an array of policy objects

# Example: Exporting the risk report data to JSON
$riskReportPath = "./reports/risk-assessment-$(Get-Date -Format 'yyyyMMdd').json"
$riskReportData | ConvertTo-Json -Depth 5 | Out-File -Path $riskReportPath
Write-Host "Risk assessment report (JSON) generated at $riskReportPath"
```

## 📊 Sample Dashboard

**Dashboard Status:** Azure Monitor Workbook KQL queries are available in `src/modules/reporting/dashboards/policy-monitoring.kql`. The full visual dashboard/GUI is a planned feature (see `docs/ROADMAP.md`).

The built-in monitoring dashboard provides real-time visibility into:
- Policy effectiveness metrics
- User impact analysis
- Compliance status
- Risk indicators

## 🏗️ Architecture

```mermaid
graph TD
    A[Policy Management] -->|Deploys| B[Azure/Entra ID]
    C[Compliance Engine] -->|Monitors| B
    D[Risk Assessment] -->|Analyzes| B
    E[Monitoring] -->|Collects| B
    F[Reporting] -->|Generates| G[Insights]
    H[Automation] -->|Orchestrates| A
```

## 🔒 Security Considerations

- All deployments require approved pull requests
- Changes are validated against security baselines
- Automated conflict detection prevents policy overlap
- Just-In-Time access for privileged operations
- Comprehensive audit logging
- For more details, see [Security Considerations](docs/security/README.md).

## 📖 Documentation

Detailed documentation is available in the [docs](./docs) directory:
- [Architecture Overview](docs/architecture/README.md)
- [Deployment Guide](docs/deployment/README.md)
- [Operation Manual](docs/operations/README.md)
- [Security Considerations](docs/security/README.md)

## 🧪 Testing

Run the test suite:
```powershell
Invoke-Pester ./tests -CI
```

Coverage report will be generated in `./coverage/report.html`

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Microsoft Graph API Documentation](https://docs.microsoft.com/graph/api/resources/conditionalaccesspolicy)
- [Azure/Entra ID Security Best Practices](https://docs.microsoft.com/azure/active-directory/conditional-access/best-practices)
- [PowerShell Team](https://github.com/PowerShell/PowerShell)

## 📊 Project Status

- ✅ Core Policy Management & Foundational Features (see Roadmap for details)
- 🔄 Advanced Analytics & Enhanced "What If" (In Progress)
- 📅 ML-based Recommendations & GUI (Planned)

## 🆘 Support

- For bugs and features, open an issue
- For security issues, see [SECURITY.md](SECURITY.md)
- For questions, join our [Discussions](https://github.com/topazyo/ca-automation/discussions)

## 🗺️ Roadmap

See our [project roadmap](docs/ROADMAP.md) for planned features and enhancements.

---

<p align="center">Made with ❤️ by security engineers for security engineers</p>