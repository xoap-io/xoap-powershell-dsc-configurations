<#
.SYNOPSIS
    Template for new XOAP PowerShell DSC configurations.

.NOTES
    Naming rule: Configuration name = Node name = filename (without .ps1)
    Pattern:     VENDOR_PRODUCT_VERSION_TYPE
    Examples:    MSTF_SecurityBaseline_W2K22_Computer
                 Citrix_Virtual_Delivery_Agent
                 DoD_Windows_11_STIG_Computer_v1r3

    Module versions: check helper-scripts/install-psgallery-modules.ps1 for the
    canonical list. Always pin -ModuleVersion in production configurations.
#>

Configuration 'VENDOR_PRODUCT_VERSION_TYPE'  # Must match Node name and filename
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'  # No version pin by convention

    # Uncomment and pin versions as needed:
    #Import-DscResource -ModuleName 'GPRegistryPolicyDsc'      -ModuleVersion '1.2.0'
    #Import-DscResource -ModuleName 'AuditPolicyDSC'           -ModuleVersion '1.4.0.0'
    #Import-DscResource -ModuleName 'SecurityPolicyDSC'        -ModuleVersion '2.10.0.0'
    #Import-DscResource -ModuleName 'ComputerManagementDsc'    -ModuleVersion '10.0.0'

    Node 'VENDOR_PRODUCT_VERSION_TYPE'  # Must match Configuration name above
    {
        # --- Windows Features ---
        #WindowsOptionalFeature 'FeatureName'
        #{
        #    Name   = 'FeatureName'
        #    Ensure = 'Present'  # or 'Absent'
        #}

        # --- Services ---
        #Service 'ServiceName'
        #{
        #    Name        = 'ServiceName'
        #    State       = 'Running'
        #    StartupType = 'Automatic'
        #}

        # --- Registry / Policy ---
        #RegistryPolicyFile 'Registry(POL): HKLM:\Path\To\Key\ValueName'
        #{
        #    ValueName  = 'ValueName'
        #    ValueData  = 1
        #    ValueType  = 'Dword'  # String, Dword, MultiString, Binary
        #    TargetType = 'ComputerConfiguration'
        #    Key        = 'HKLM:\Path\To\Key'
        #}

        # --- Files and Directories ---
        #File 'DirectoryName'
        #{
        #    Type            = 'Directory'
        #    Ensure          = 'Present'
        #    DestinationPath = 'C:\Path\To\Directory'
        #}
    }
}

# Run after dot-sourcing: . .\VENDOR_PRODUCT_VERSION_TYPE.ps1
VENDOR_PRODUCT_VERSION_TYPE -OutputPath 'C:\DSC\VENDOR_PRODUCT_VERSION_TYPE'
