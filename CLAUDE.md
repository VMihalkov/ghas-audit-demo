# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a GitHub Advanced Security (GHAS) Audit Demo repository designed to:
- Demonstrate automated security compliance workflows using GitHub Actions
- Serve as a teaching tool for Pluralsight course on GHAS compliance automation
- Provide a template for organizations to audit their GitHub security posture

## Development Commands

### Current State
The project is in initial scaffolding phase. No build/test/lint commands are configured yet.

When implementing features, you'll need to:
```bash
# Install dependencies (when added to package.json)
npm install

# No test/build/lint commands defined yet - these need to be implemented
```

## Architecture & Structure

### Planned Architecture (from PRD)
The repository should implement:

1. **GitHub Actions Workflows** (`.github/workflows/`)
   - `audit-security.yml` - Main audit workflow
   - `scheduled-audit.yml` - Scheduled security checks
   - `report-generation.yml` - Dashboard/report generation

2. **Core Components**
   - Integration with `gh-ghas-audit` CLI extension
   - Automated reporting to Issues/Discussions
   - Executive dashboard generation
   - Sample vulnerable applications for demonstrations

3. **Directory Structure** (to be implemented)
   ```
   ├── .github/workflows/    # GitHub Actions workflows
   ├── scripts/             # CLI helper scripts
   ├── templates/           # Report/dashboard templates
   ├── samples/             # Vulnerable demo applications
   ├── docs/                # Documentation
   └── src/                 # Main application code
   ```

### Key Implementation Notes

1. **Security Focus**: This is a security demonstration project. All code should follow security best practices and clearly document any intentional vulnerabilities in sample applications.

2. **GitHub Integration**: Heavy reliance on GitHub APIs and Actions. Use the GitHub CLI (`gh`) and Actions toolkit where appropriate.

3. **Reporting**: Generate markdown reports compatible with GitHub Issues and Discussions.

4. **Course Material**: Code should be clear and educational, suitable for students learning GHAS.

## Reference Materials

- `/reference/PRD.md` - Complete product requirements and implementation details
- `/reference/WAYPOINT - GHAS (1).md` - Pluralsight course outline and learning objectives

These documents contain the full vision and requirements for the project implementation.