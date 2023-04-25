[![Maintained](https://img.shields.io/badge/Maintained%20by-XOAP-success)](https://xoap.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# Table of Contents

- [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Disclaimer](#disclaimer)
  - [Guidelines](#guidelines)
  - [Share the Love](#share-the-love)
  - [Contributing](#contributing)
  - [Bug Reports and Feature Requests](#bug-reports--feature-requests)
  - [Developing](#developing)
  - [Usage](#usage)

---

## Introduction

This is the XOAP PowerShell DSC configuration repository.

It is part of our XOAP Automation Forces Open Source community library to give you a quick start into Infrastructure as Code deployments with PowerShell DSC in addition to config.XO.

Please check the links for more info, including usage information and full documentation:

- [XOAP Website](https://xoap.io)
- [XOAP Documentation](https://docs.xoap.io)
- [Twitter](https://twitter.com/xoap_io)
- [LinkedIn](https://www.linkedin.com/company/xoap_io)

---

## Disclaimer

**All configurations are provided AS IS. We are not responsible for anything that happens inside your environment because you applied the configurations and didn´t test them thoroughly before doing so.**

Be sure to always test any of those configurations in separated test environment and test clients and servers.

>Some of the available DSC configurations make severe changes to security related configurations and could leave your Windows operating system in an unusable state.

So please test once, twice or trice.

---

## Guidelines

We are using the following guidelines to write code and make it easier for everyone to follow a distinctive guideline. Please check these links before starting to work on changes.

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

Git Naming Conventions are an important part of the development process. They describe how Branches, Commit Messages, Pull Requests and Tags should look like to make the easily understandable for everybody in the development chain.

[Git Naming Conventions](https://namingconvention.org/git/)

The Conventional Commits specification is a lightweight convention on top of commit messages. It provides an easy set of rules for creating an explicit commit history; which makes it easier to write automated tools on top of.

[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)

The better a Pull Request description is, the better a review can understand and decide on how to review the changes. This improves implementation speed and reduces communication between the requester and the reviewer resulting in much less overhead.

[Writing A Great Pull Request Description](https://www.pullrequest.com/blog/writing-a-great-pull-request-description/)

Versioning is a crucial part for everything as code. Without version tags you cannot clearly create a stable environment and be sure that your latest changes won't crash your production environment (sure it still can happen, but we are trying our best to implement everything that we can to reduce the risk)

[Semantic Versioning](https://semver.org)

---

## Share the Love
Like this project? Please give it a ★ on [our GitHub](https://github.com/xoap-io/xoap-uberagent-kibana-dashboards)! (it helps us a lot).

---

## Contributing

### Bug Reports & Feature Requests

Please use the issue tracker to report any bugs or file feature requests.

### Developing

If you are interested in being a contributor and want to get involved in developing this project, we would love to hear from you! Email us.

PRs are welcome. We follow the typical "fork-and-pull" Git workflow.

- Fork the repo on GitHub
- Clone the project to your own machine
- Commit changes to your own branch
- Push your work back up to your fork
- Submit a Pull Request so that we can review your changes

> NOTE: Be sure to merge the latest changes from "upstream" before making a pull request!

---

## Usage

### Local usage

On most supported Windows versions you don´t have to do anything. On windows versions prior to Windows Server 2016 or Windows 10 you should install Windows Management Framework 5.1.
You can download it [here](https://www.microsoft.com/en-us/download/details.aspx?id=54616).

#### Compile and Apply 

A typical DSC configuration looks like this:

```
Configuration MSTF_SecurityBaseline_Edge_v107_Computer
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node MSTF_SecurityBaseline_Edge_v107_Computer
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SitePerProcess'
         {
              ValueName = 'SitePerProcess'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }
    }
}
```

In order to compile this example you need to take care that all the referenced DSC modules are available locally.

You can check availability with:

```
Get-DcsResource
```

If DSC modules are missing, you can install them simply by e.g. running:

```
Install-Module SecurityPolicyDSC
```

It could be that you need to install PowerShellGet and the NuGet provider and that you have to trust the PSGallery to be able to install the DSC modules.

> Please be aware that this is the most basic example. We advise to always define the module versions in production environments before compiling them and to implement a versioning system to track changes to those DSC configurations. Not defining versions could lead to compiling errors because of functional changes between vmodule versions.

Defining the versions of the modules could look like this:

```
Configuration MSTF_SecurityBaseline_Edge_v107_Computer
{

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0' -ModuleVersion '2.1.0.0'

	Node MSTF_SecurityBaseline_Edge_v107_Computer
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SitePerProcess'
         {
              ValueName = 'SitePerProcess'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Edge'
         }
    }
}
```

So now that all DSC modules are available and the module versions are defined you need to run the following command in your Powershell to compile it locally:

```
. PATHTOYOURSCRIPT\MSTF_SecurityBaseline_Edge_v107_Computer.ps1
MSTF_SecurityBaseline_Edge_v107_Computer
```

You should now have a localhost.mof file in this location.

The last step is to apply this configuration to your local host:

```
Start-DscConfiguration -Path PATHTOYOURCONFIGURATION\MSTF_SecurityBaseline_Edge_v107_Computer -Verbose -Wait
```

> Please be sure to run all of these commands in PowerShell 5.1

---

### Usage in XOAP and config.XO

Refer to our documentation [here](https://docs.xoap.io/configuration-management/quickstarts/add-configurations/)
