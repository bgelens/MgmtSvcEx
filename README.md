# MgmtSvcEx

Windows Azure Pack shippes with the MgmtSvcAdmin module to expose Admin tasks via PowerShell. This module extend the capabilities of MgmtSvcAdmin and make it easier to use.

## Example use

Create a new plan and add VMM Service and quota's

```powershell
$Cred = Get-Credential -UserName admin.ben@azurepack.local -Message apicred
Get-MgmtSvcExToken `
    -AuthenticationSite https://sts.domain.local `
    -Type Adfs -AdfsAddress https://sts.domain.local `
    -User $Cred `
    -DisableCertificateValidation
Connect-MgmtSvcExAPI -Url https://wapadminapi.azurepack.local -IgnoreSSL

#Acquire and Import Admin API cert
Get-MgmtSvcExAPICertificate | Export-Certificate -FilePath C:\Users\admin.ben\Desktop\mycert.cer
Import-Certificate -CertStoreLocation Cert:\LocalMachine\My -FilePath C:\Users\admin.ben\Desktop\mycert.cer

#Create plan and add systemcenter RP
$Plan = Add-MgmtSvcPlan -DisplayName mynewplan -State Private -MaxSubscriptionsPerAccount -1
$rp = Get-MgmtSvcResourceProvider -Name systemcenter
$Plan | Add-MgmtSvcPlanService -ServiceName $RP.Name -InstanceId $RP.InstanceId

#create systemcenter quota
$QL = New-MgmtSvcQuotaList
$systemcenterquota = Add-MgmtSvcListQuota -QuotaList $QL -ServiceName systemcenter -ServiceInstanceId $RP.InstanceId

#Acquire Cloud
$CCCloud = Get-MgmtSvcExCloud -Name 'MyCloud'

#Setup Allowed Actions quota
$Actions = $CCCloud | New-MgmtSvcExQuotaSettingSCActions `
    -Checkpoint `
    -SaveVMState `
    -LibraryStoreAndDeploy `
    -ConsoleConnect #-CheckpointRestoreOnly -MaximumNetwork -MaximumBandwidthIn -MaximumBandwidthOut -MaximumVPNConnection -MaximumNATConnection

#Setup Clouds Quota
$Clouds = $CCCloud | New-MgmtSvcExQuotaSettingSCClouds #-VMCount -CPUCount -MemoryMB -StorageGB

#Setup custom settings quota 
$CustomSettings = New-MgmtSvcExQuotaSettingSCCustomSettings `
    -DisableNetworkExtension `
    -VMComputerNameSetting TenantDefined #-DREnabled -Name

#Setup Network quota
$VMNet = $CCCloud | Get-MgmtSvcExVMNetwork -Name 'ExampleNet'
$Networks = New-MgmtSvcExQuotaSettingSCNetworks -Network $VMNet

#Setup VMResources quota
$template = Get-MgmtSvcExVMTemplate
$hardwareprofile = Get-MgmtSvcExHardwareProfile
$galleryitems = Get-MgmtSvcExGalleryItem
$Resources = New-MgmtSvcExQuotaSettingSCVmResources `
    -VMTemplate $template `
    -HardwareProfile $hardwareprofile `
    -Cloud $CCCloud `
    -GalleryItem $galleryitems

#populate quota object
$null = Add-MgmtSvcQuotaSetting -Quota $systemcenterquota -Key Actions -Value $Actions
$null = Add-MgmtSvcQuotaSetting -Quota $systemcenterquota -Key Clouds -Value $Clouds
$null = Add-MgmtSvcQuotaSetting -Quota $systemcenterquota -Key VmResources -Value $Resources
$null = Add-MgmtSvcQuotaSetting -Quota $systemcenterquota -Key Networks -Value $Networks
$null = Add-MgmtSvcQuotaSetting -Quota $systemcenterquota -Key CustomSettings -Value $CustomSettings

#apply quota
$Plan | Update-MgmtSvcPlanQuota -QuotaList $QL
```

Update an existing plan quota settings to disable checkpoint controls

```powershell
$Cred = Get-Credential -UserName admin.ben@azurepack.local -Message apicred
Get-MgmtSvcExToken `
    -AuthenticationSite https://sts.domain.local `
    -Type Adfs -AdfsAddress https://sts.domain.local `
    -User $Cred `
    -DisableCertificateValidation
Connect-MgmtSvcExAPI -Url https://wapadminapi.azurepack.local -IgnoreSSL

$plan = Get-MgmtSvcPlan -DisplayName mynewplan
$plan | Update-MgmtSvcExQuotaSettingSCActions -Checkpoint $false -CheckpointRestoreOnly $false
```

Add / Remove Co Administrators

```powershell
$Cred = Get-Credential -UserName admin.ben@azurepack.local -Message apicred
Get-MgmtSvcExToken `
    -AuthenticationSite https://sts.domain.local `
    -Type Adfs -AdfsAddress https://sts.domain.local `
    -User $Cred `
    -DisableCertificateValidation
Connect-MgmtSvcExAPI -Url https://wapadminapi.azurepack.local -IgnoreSSL

$plan = Get-MgmtSvcPlan -DisplayName mynewplan
$sub = $plan | Get-MgmtSvcSubscription

# Add Co Admin
$sub | Add-MgmtSvcExCoAdministrator -CoAdministratorName 'new@admin.com'

# Remove Co Admin
$sub | Remove-MgmtSvcExCoAdministrator -CoAdministratorName 'old@admin.com'
```
