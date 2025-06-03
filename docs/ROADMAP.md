# Project Roadmap

This document outlines the planned features and enhancements for the Azure Conditional Access Automation Framework.

## Near-Term (In Progress / Next Up)

-   **Advanced Analytics**: (In Progress)
    -   Develop more sophisticated analytics for policy impact and effectiveness.
    -   Integrate with Azure Sentinel for advanced threat detection scenarios related to Conditional Access.
-   **Enhanced "What If" Functionality**:
    -   Provide more granular simulation capabilities for policy changes beyond the native Azure AD "What If" tool.
    -   Allow batch simulations and comparison reports.
-   **GUI / Web Interface**:
    -   Develop a simple web interface (potentially using Azure Functions and static web apps) for easier policy management, visualization, and reporting, targeted at users less comfortable with pure PowerShell or JSON.

## Mid-Term (Planned)

-   **ML-based Policy Recommendations**: (Planned)
    -   Explore machine learning models to suggest optimal policy configurations based on organizational sign-in patterns, risk profiles, and emerging threats.
    -   This could include identifying overly permissive policies or suggesting new policies to mitigate identified risks.
-   **Expanded Compliance Frameworks**:
    -   Add pre-defined policy sets and reporting capabilities for more compliance frameworks (e.g., PCI DSS, HIPAA, SOC 2).
-   **Integration with ITSM Tools**:
    -   Develop connectors or webhooks to allow integration with popular ITSM tools (e.g., ServiceNow, Jira, Azure DevOps Boards) for change management ticketing, approval workflows, and incident tracking related to CA policies.

## Long-Term (Ideas / Exploration)

-   **Automated Policy Remediation**:
    -   Develop capabilities to automatically detect and remediate non-compliant, risky, or drifted policy configurations based on defined baselines or security recommendations.
    -   This would likely involve careful safeguards and approval mechanisms.
-   **Cross-Cloud Conditional Access Management**:
    -   Explore possibilities for extending the framework's principles and automation capabilities to manage similar identity-based access control policies in other cloud environments (e.g., AWS IAM, GCP Identity Platform).
-   **Policy Orchestration for Complex Scenarios**:
    -   Investigate ways to manage dependencies and orchestrate changes across multiple related policies for complex business or security scenarios.

## Completed Features

*(Reflecting common capabilities for a mature version of such a framework)*

-   **Core Policy Lifecycle Management**:
    -   Creation, deployment, update, and deletion of Conditional Access policies as code.
    -   Support for JSON-based policy definitions.
    -   Version control integration.
-   **Compliance Engine (Baseline Examples)**:
    -   Initial set of example policies aligned with common standards (e.g., ISO 27001, NIST 800-53, GDPR concepts like MFA for admins).
-   **Risk Assessment Module (Conceptual)**:
    -   Tools or scripts to help identify risky user configurations or policy gaps (e.g., users without MFA, legacy authentication usage).
-   **Basic Monitoring & Reporting**:
    -   Scripts to report on existing policy configurations and their assignments.
    -   Basic logging of script operations.
-   **Just-In-Time (JIT) Privileged Access (Integration Ideas)**:
    -   Guidance or examples on how CA policies can complement Azure AD PIM for JIT access.
-   **Comprehensive Audit Logging**:
    -   Ensuring all changes made by the framework are auditable via Azure AD audit logs and version control.
-   **Role-Based Access Control (RBAC) for Automation**:
    -   Guidance on setting up Service Principals or Managed Identities with appropriate, least-privilege RBAC for managing CA policies.

---

*This roadmap is subject to change based on evolving Azure capabilities, security landscape, and community feedback. Contributions and suggestions are highly encouraged!*
