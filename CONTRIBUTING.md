# Contributing to CA Automation Framework

Thanks for contributing! This project uses PowerShell modules and Pester tests; the guidance below helps maintainers accept changes quickly.

## Code of Conduct

This project follows the Contributor Covenant. Please be respectful and follow community guidelines when contributing.

## How to Contribute

- Reporting bugs: open an issue with steps to reproduce, PowerShell version, and any logs. Include relevant templates if provided.
- Suggesting enhancements: open a feature request describing the use case and expected behavior; include example policy snippets if helpful.
- Pull requests: keep changes focused, add or update Pester tests for behavior changes, and update documentation when APIs or scripts change.

## Development Setup (local)

1. Fork and clone the repository.
2. Install prerequisites (PowerShell 7.2+, Microsoft.Graph, Pester):

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
Install-Module Pester -Scope CurrentUser -Force
```

3. Open the project in VS Code and import modules for interactive work. Example:

```powershell
Import-Module ./src/modules/policy-management/policy_manager.ps1
$mgr = [ConditionalAccessPolicyManager]::new('<tenant-id>')
```

4. Run tests during development:

```powershell
Invoke-Pester ./tests -CI
```

## Style & Testing

- Follow PowerShell best practices and the existing code style.
- Add unit tests (Pester) for any new behavior and ensure tests pass locally.
- Keep PRs small and document interface changes in `README.md`.

If you intend to modify CI workflows, please open an issue first so maintainers can coordinate secrets and runner requirements.