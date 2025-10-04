<h1 align="center"> 🛠️✨Winfig </h1>

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg?style=for-the-badge)](https://github.com/PowerShell/PowerShell)
[![Chocolatey Compatible](https://img.shields.io/badge/Compatible%20with-Chocolatey-ff69b4.svg?style=for-the-badge)](https://chocolatey.org/)
[![Winget Compatible](https://img.shields.io/badge/Compatible%20with-Winget-228B22.svg?style=for-the-badge)](https://github.com/microsoft/winget-cli)
[![Windows](https://img.shields.io/badge/Windows-10%2B-0078d4.svg?style=for-the-badge)](https://www.microsoft.com/windows)

[![Issues](https://img.shields.io/github/issues/ToolsHive/Winfig.svg?style=flat-square)](https://github.com/ToolsHive/Winfig.git/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/ToolsHive/Winfig.svg?style=flat-square)](https://github.com/ToolsHive/Winfig.git/pulls)
[![Repo Size](https://img.shields.io/github/repo-size/ToolsHive/Winfig?style=flat-square)](https://github.com/ToolsHive/Winfig.git)
[![Last Commit](https://img.shields.io/github/last-commit/ToolsHive/Winfig?style=flat-square)](https://github.com/ToolsHive/Winfig.git/commits/main)

</div>

A small, battle-tested Windows configuration toolkit to bootstrap a developer-friendly environment on a fresh install.

**Highlights**:
- Minimal, well-tested `PowerShell` scripts and settings
- Opinionated defaults for productivity and development
- Modular design for easy customization and extension
- Focus on essential tools and configurations
- Designed for both personal and professional use

## Table of Contents
- [Table of Contents](#table-of-contents)
- [Features](#features)
- [Requirements](#requirements)
- [Post-Deployment Verification](#post-deployment-verification)
- [Safety \& Troubleshooting](#safety--troubleshooting)
- [Contributing](#contributing)
  - [Development Workflow](#development-workflow)
  - [Contribution Standards](#contribution-standards)
- [License](#license)


## Features
- **Modular Scripts**: Easily customize and extend your setup with modular scripts.
- **Essential Tools**: Focuses on essential tools and configurations for developers.
- **Opinionated Defaults**: Comes with sensible defaults to enhance productivity.
- **Cross-Platform**: While primarily for Windows, it can be adapted for other platforms with minor tweaks.
- **Custom Dotfiles** : Supports custom dotfiles for personalized configurations.
- **Automated Setup**: Automates the installation and configuration of tools and settings.

## Requirements
- Windows 10 or later
- PowerShell 5.1 or later
- Internet connection for downloading packages
- Administrator privileges for certain installations

## Post-Deployment Verification

1. **Configuration Wizard** - Complete the guided setup process
2. **System Integration** - Restart system to initialize all components
3. **Operational Validation** - Execute diagnostic verification procedures

> **Administrative Requirements**: Elevated PowerShell privileges required for proper installation.

## Safety & Troubleshooting

- Backup important config files before running. Testing in a VM is recommended.
- If you encounter repeated elevation prompts when using the iwr|iex one-liner, manually run the downloaded script from an elevated PowerShell window.
- If you get parser/encoding errors after download, ensure the file is saved in UTF-8 and hasn't been edited in a way that breaks quoted strings or backtick line continuations.
- If package manager installs fail, install the package manager (winget/choco) manually and re-run the script.

##  Contributing

Professional contributions are welcomed from the development community.

### Development Workflow

1. **Repository Fork** - Create independent development branch
2. **Feature Development** - Implement changes in isolated branch (`git checkout -b feature/enhancement`)
3. **Code Commitment** - Document changes with descriptive commit messages
4. **Branch Publication** - Push feature branch to forked repository
5. **Pull Request Submission** - Submit formal code review request

### Contribution Standards

- **Issue Reporting** - Utilize standardized issue templates for consistency
- **Enhancement Proposals** - Engage in architectural discussions prior to implementation
- **Documentation** - Maintain comprehensive documentation standards
- **Quality Assurance** - Implement comprehensive testing for new functionality

## License
This project is distributed under the [**MIT License**](LICENSE) © 2025 Armoghan-ul-Mohmin
