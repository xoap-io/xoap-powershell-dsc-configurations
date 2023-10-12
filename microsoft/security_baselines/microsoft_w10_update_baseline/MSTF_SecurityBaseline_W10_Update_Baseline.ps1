
Configuration 'MSTF_SecurityBaseline_W10_Update_Baseline'
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc' -ModuleVersion '1.2.0'
	Import-DSCResource -ModuleName 'AuditPolicyDSC' -ModuleVersion '1.4.0.0'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC' -ModuleVersion '2.10.0.0'

	Node 'MSTF_SecurityBaseline_W10_Update_Baseline'
	{
         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\5CA83367-6E45-459F-A27B-476B1D01C936\DCSettingIndex'
         {
              ValueName = 'DCSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\5CA83367-6E45-459F-A27B-476B1D01C936'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\5CA83367-6E45-459F-A27B-476B1D01C936\ACSettingIndex'
         {
              ValueName = 'ACSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\5CA83367-6E45-459F-A27B-476B1D01C936'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364\DCSettingIndex'
         {
              ValueName = 'DCSettingIndex'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364\ACSettingIndex'
         {
              ValueName = 'ACSettingIndex'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\DCSettingIndex'
         {
              ValueName = 'DCSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\ACSettingIndex'
         {
              ValueName = 'ACSettingIndex'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\E69653CA-CF7F-4F05-AA73-CB833FA90AD4\DCSettingIndex'
         {
              ValueName = 'DCSettingIndex'
              ValueData = 40
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Power\PowerSettings\E69653CA-CF7F-4F05-AA73-CB833FA90AD4'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
         {
              ValueName = 'DODownloadMode'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DOMinFileSizeToCache'
         {
              ValueName = 'DOMinFileSizeToCache'
              ValueData = 10
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DOMinBatteryPercentageAllowedToUpload'
         {
              ValueName = 'DOMinBatteryPercentageAllowedToUpload'
              ValueData = 60
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DOMaxCacheAge'
         {
              ValueName = 'DOMaxCacheAge'
              ValueData = 604800
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODelayBackgroundDownloadFromHttp'
         {
              ValueName = 'DODelayBackgroundDownloadFromHttp'
              ValueData = 300
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODelayForegroundDownloadFromHttp'
         {
              ValueName = 'DODelayForegroundDownloadFromHttp'
              ValueData = 60
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetDisablePauseUXAccess'
         {
              ValueName = 'SetDisablePauseUXAccess'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetUpdateNotificationLevel'
         {
              ValueName = 'SetUpdateNotificationLevel'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\UpdateNotificationLevel'
         {
              ValueName = 'UpdateNotificationLevel'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DoNotConnectToWindowsUpdateInternetLocations'
         {
              ValueName = 'DoNotConnectToWindowsUpdateInternetLocations'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\DisableDualScan'
         {
              ValueName = 'DisableDualScan'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ExcludeWUDriversInQualityUpdate'
         {
              ValueName = 'ExcludeWUDriversInQualityUpdate'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ElevateNonAdmins'
         {
              ValueName = 'ElevateNonAdmins'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetAutoRestartNotificationConfig'
         {
              ValueName = 'SetAutoRestartNotificationConfig'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AutoRestartNotificationSchedule'
         {
              ValueName = 'AutoRestartNotificationSchedule'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetAutoRestartRequiredNotificationDismissal'
         {
              ValueName = 'SetAutoRestartRequiredNotificationDismissal'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AutoRestartRequiredNotificationDismissal'
         {
              ValueName = 'AutoRestartRequiredNotificationDismissal'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetRestartWarningSchd'
         {
              ValueName = 'SetRestartWarningSchd'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\ScheduleRestartWarning'
         {
              ValueName = 'ScheduleRestartWarning'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\ScheduleImminentRestartWarning'
         {
              ValueName = 'ScheduleImminentRestartWarning'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AUPowerManagement'
         {
              ValueName = 'AUPowerManagement'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetDisableUXWUAccess'
         {
              ValueName = 'SetDisableUXWUAccess'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetAutoRestartDeadline'
         {
              ValueName = 'SetAutoRestartDeadline'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AutoRestartDeadlinePeriodInDays'
         {
              ValueName = 'AutoRestartDeadlinePeriodInDays'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AutoRestartDeadlinePeriodInDaysForFeatureUpdates'
         {
              ValueName = 'AutoRestartDeadlinePeriodInDaysForFeatureUpdates'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetComplianceDeadline'
         {
              ValueName = 'SetComplianceDeadline'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ConfigureDeadlineForQualityUpdates'
         {
              ValueName = 'ConfigureDeadlineForQualityUpdates'
              ValueData = 3
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ConfigureDeadlineForFeatureUpdates'
         {
              ValueName = 'ConfigureDeadlineForFeatureUpdates'
              ValueData = 7
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ConfigureDeadlineGracePeriod'
         {
              ValueName = 'ConfigureDeadlineGracePeriod'
              ValueData = 2
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\ConfigureDeadlineNoAutoReboot'
         {
              ValueName = 'ConfigureDeadlineNoAutoReboot'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetEngagedRestartTransitionSchedule'
         {
              ValueName = 'SetEngagedRestartTransitionSchedule'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\EngagedRestartTransitionSchedule'
         {
              ValueName = 'EngagedRestartTransitionSchedule'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\EngagedRestartSnoozeSchedule'
         {
              ValueName = 'EngagedRestartSnoozeSchedule'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\EngagedRestartDeadline'
         {
              ValueName = 'EngagedRestartDeadline'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\EngagedRestartTransitionScheduleForFeatureUpdates'
         {
              ValueName = 'EngagedRestartTransitionScheduleForFeatureUpdates'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\EngagedRestartSnoozeScheduleForFeatureUpdates'
         {
              ValueName = 'EngagedRestartSnoozeScheduleForFeatureUpdates'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\EngagedRestartDeadlineForFeatureUpdates'
         {
              ValueName = 'EngagedRestartDeadlineForFeatureUpdates'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetActiveHours'
         {
              ValueName = 'SetActiveHours'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\ActiveHoursStart'
         {
              ValueName = 'ActiveHoursStart'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\ActiveHoursEnd'
         {
              ValueName = 'ActiveHoursEnd'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetAutoRestartNotificationDisable'
         {
              ValueName = 'SetAutoRestartNotificationDisable'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetEDURestart'
         {
              ValueName = 'SetEDURestart'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\SetActiveHoursMaxRange'
         {
              ValueName = 'SetActiveHoursMaxRange'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ActiveHoursMaxRange'
         {
              ValueName = 'ActiveHoursMaxRange'
              ValueData = 10
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AutoInstallMinorUpdates'
         {
              ValueName = 'AutoInstallMinorUpdates'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AlwaysAutoRebootAtScheduledTime'
         {
              ValueName = 'AlwaysAutoRebootAtScheduledTime'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AlwaysAutoRebootAtScheduledTimeMinutes'
         {
              ValueName = 'AlwaysAutoRebootAtScheduledTimeMinutes'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\RebootWarningTimeoutEnabled'
         {
              ValueName = 'RebootWarningTimeoutEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\RebootWarningTimeout'
         {
              ValueName = 'RebootWarningTimeout'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAUAsDefaultShutdownOption'
         {
              ValueName = 'NoAUAsDefaultShutdownOption'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAUShutdownOption'
         {
              ValueName = 'NoAUShutdownOption'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers'
         {
              ValueName = 'NoAutoRebootWithLoggedOnUsers'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\RebootRelaunchTimeoutEnabled'
         {
              ValueName = 'RebootRelaunchTimeoutEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\RebootRelaunchTimeout'
         {
              ValueName = 'RebootRelaunchTimeout'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\RescheduleWaitTimeEnabled'
         {
              ValueName = 'RescheduleWaitTimeEnabled'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\RescheduleWaitTime'
         {
              ValueName = 'RescheduleWaitTime'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\IncludeRecommendedUpdates'
         {
              ValueName = 'IncludeRecommendedUpdates'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\EnableFeaturedSoftware'
         {
              ValueName = 'EnableFeaturedSoftware'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\DetectionFrequencyEnabled'
         {
              ValueName = 'DetectionFrequencyEnabled'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\DetectionFrequency'
         {
              ValueName = 'DetectionFrequency'
              ValueData = 6
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate'
         {
              ValueName = 'NoAutoUpdate'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions'
         {
              ValueName = 'AUOptions'
              ValueData = 4
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AutomaticMaintenanceEnabled'
         {
              ValueName = 'AutomaticMaintenanceEnabled'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay'
         {
              ValueName = 'ScheduledInstallDay'
              ValueData = 0
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallTime'
         {
              ValueName = 'ScheduledInstallTime'
              ValueData = 24
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallEveryWeek'
         {
              ValueName = 'ScheduledInstallEveryWeek'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFirstWeek'
         {
              ValueName = 'ScheduledInstallFirstWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallSecondWeek'
         {
              ValueName = 'ScheduledInstallSecondWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallThirdWeek'
         {
              ValueName = 'ScheduledInstallThirdWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallFourthWeek'
         {
              ValueName = 'ScheduledInstallFourthWeek'
              ValueData = ''
              Ensure = 'Absent'
              ValueType = 'String'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\AllowMUUpdateService'
         {
              ValueName = 'AllowMUUpdateService'
              ValueData = 1
              ValueType = 'Dword'
              TargetType = 'ComputerConfiguration'
              Key = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
         }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }
}
