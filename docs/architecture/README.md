# Conditional Access Automation Architecture

This document describes the high-level architecture and the source files that implement each responsibility. The implementation is PowerShell-based and organized under `src/modules/`.

## Core Components (implemented)

- Policy Management: `src/modules/policy-management/policy_manager.ps1` — manages policy creation, update, and deletion via Microsoft Graph or offline/test fallbacks.
- Validation: `src/modules/validation/policy_validator.ps1` — validation rules and conflict detection utilities.
- Compliance: `src/modules/compliance/compliance_manager.ps1` — compliance assessments and report generation.
- Risk: `src/modules/risk/risk_assessor.ps1` — scoring functions to quantify policy risk.
- Reporting: `src/modules/reporting/policy_monitor.ps1` — hooks for Log Analytics and monitoring (some functions are placeholders).

## Security Considerations (practical)

- Authentication: code assumes Microsoft Graph cmdlets and supports both interactive login and service principal authentication. The repo does not currently include automated service principal creation scripts (see TODOs).
- Authorization: rely on Azure/Entra roles and least-privilege service principals for CI/deployment.
- Audit & Logging: modules attempt to surface audit-friendly outputs; integrate with your SIEM/Log Analytics for production use.

## Implementation Guidelines

- Policy changes should be covered by Pester unit tests and, where feasible, integration tests under `tests/`.
- Use `-WhatIf` or dry-run modes in `scripts/deployment/deploy.ps1` when testing changes against live tenants.

TODOs
- Provide scripted helpers in `scripts/setup/` to create service principals and configure Log Analytics.
- Expand `src/modules/reporting/policy_monitor.ps1` to implement `ConfigureLogAnalytics` and end-to-end ingestion.