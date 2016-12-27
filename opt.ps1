<#
                   安装前优化脚本
按照安装手册进行，主要是将需要手动点击的项目变更为直接修改注册表项
编写人：杨波，email：bo.yang@non.agilent.com
ver：0.7
changelog:初次释放
changelog:引导bat脚本修改，一次运行即可，修改netfx3 non http激活参数，避免关联项无法激活导致的失败，修改网卡电源管理语句
changelog:部分注册表键值类型未指定，修正；添加操作系统判断部分；添加部分新内容
changelog:增减部分系统判断条件。修正语法错误
changelog:修改系统判断，增加语言判断，增加自动IP设定
changelog:修改引导bat，适应更多情况，加入管理员权限判断及运行提示
changelog:修改引导bat中管理员权限判断方式，增加自动启用netfx3功能。针对低版本powershell版本禁用了自动IP功能。
#>

#强制以管理员运行,如需直接运行本脚本，请将下一部分取消注释，并且提前修改powershell执行策略
<#$currentWi = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentWp = [Security.Principal.WindowsPrincipal]$currentWi
 
if( -not $currentWp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  $boundPara = ($MyInvocation.BoundParameters.Keys | foreach{
     '-{0} {1}' -f  $_ ,$MyInvocation.BoundParameters[$_]} ) -join ' '
  $currentFile = (Resolve-Path  $MyInvocation.InvocationName).Path
 
 $fullPara = $boundPara + ' ' + $args -join ' '
 Start-Process "$psHome\powershell.exe"   -ArgumentList "$currentFile $fullPara"   -verb runas
 return
}
#>

#检查操作系统版本
if ($psversiontable.BuildVersion -eq 7600) {
	Write-Warning '检测到未安装SP1的Windows 7，在安装光盘的disk6下面有补丁，请事先安装一下，大概需要一个小时的时间'
	exit
}
elseif ($psversiontable.BuildVersion.Major -eq 10){
	$OSVer = 10
}
elseif($psversiontable.BuildVersion.Major -eq 6 -and $psversiontable.BuildVersion.Minor -eq 1){
	$OSVer = 7
}
elseif ($psversiontable.BuildVersion.Major -eq 6 -and ($psversiontable.BuildVersion.Minor -eq 2 -or $psversiontable.BuildVersion.Minor -eq 3)) {
	$OSVer = 8
}

#检查系统当前的显示语言变量
$OSLang=[System.Globalization.Cultureinfo]::InstalledUICulture

#2
#显示文件扩展名
Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0

#标题栏中显示完整路径
Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState -Name FullPath -Value 1

#禁用共享向导
Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SharingWizardOn -Value 0

#4
#禁止自动更新在有用户登录的情况下重启计算机，此处与指导不同，主要考虑到可能有地方会允许仪器计算机联网，联网情况下关闭更新还是比较危险的，而不联网关闭更新也就没有意义了。
$AU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item $AU -Force
New-ItemProperty $AU -Name NoAutoRebootWithLoggedOnUsers -Type Dword -Value 1

#5
#禁用Application Experience服务
if($OSVer -ne 10){
	Set-Service -Name AeLookupSvc -StartupType Disabled -Status Stopped
}


#禁用Desktop Window Manager Session Manager服务，如果计算机配置较好，考虑到用户使用体验，此服务可以不禁用
if($OSVer -ne 10){
	Set-Service -Name UxSms -StartupType Disabled -Status Stopped
}

#6
#禁用索引服务
Set-Service -Name WSearch -StartupType Disabled
Stop-Service -Name WSearch

#7
#隐藏快速用户切换
New-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name HideFastUserSwitching -Type DWord -Value 1 -Force

#设置总是使用经典登陆
New-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LogonType -Type DWord -Value 0 -Force

#8
#将电源选项设置为“高性能”，默认使用powercfg工具调整，注册表方式被注释掉
#Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\ControlPanel\NameSpace\{025A5937-A6BE-4686-A844-36FE4BEC8B6D}' -Name PreferredPlan -Value 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /SETACTIVE SCHEME_MIN

#禁止空闲自动睡眠
powercfg /change standby-timeout-ac 0

#禁止空闲自动关闭硬盘
powercfg /change disk-timeout-ac 0

#9
#修改本地用户以自己的身份验证
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name ForceGuest -Type DWord -Value 0 -Force

#12修改网卡电源管理,此处脚本修改自https://gallery.technet.microsoft.com/scriptcenter/Disable-turn-off-this-f74e9e4a
Function Disable-OSCNetAdapterPnPCaptitlies
{
#find only physical network,if value of properties of adaptersConfigManagerErrorCode is 0,  it means device is working properly. 
#even covers enabled or disconnected devices.
#if the value of properties of configManagerErrorCode is 22, it means the adapter was disabled. 
	$PhysicalAdapters = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object{$_.PNPDeviceID -notlike "ROOT\*"  -and $_.Manufacturer -ne "Microsoft" -and $_.ConfigManagerErrorCode -eq 0 -and $_.ConfigManagerErrorCode -ne 22}
	Foreach($PhysicalAdapter in $PhysicalAdapters)
	{
		$PhysicalAdapterName = $PhysicalAdapter.Name
		#check the unique device id number of network adapter in the currently environment.
		$DeviceID = $PhysicalAdapter.DeviceID
		If([Int32]$DeviceID -lt 10)
		{
			$AdapterDeviceNumber = "000"+$DeviceID
		}
		Else
		{
			$AdapterDeviceNumber = "00"+$DeviceID
		}
		$KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber"
		Set-ItemProperty -Path $KeyPath -Name "PnPCapabilities" -Value 24	
	}
}
Disable-OSCNetAdapterPnPCaptitlies

#13启用netfx3非HTTP激活
if ($OSVer -ne 7) {
	if ($OSLang -eq 'zh-CN') {
		Write-Warning -Message '是否自动启用NetFx3及非HTTP激活？如选择否，则认为已经启用NetFX3，直接启用非HTTP激活功能，如选择是，请留意readme中的相关说明'
	}
	else {
		Write-Warning -Message 'Would like automatically enable NetFx3 and non-http-activation? Default only enable non-http-activation. If you select yes, please view the readme'
	}
	$netfx = Read-Host -Prompt '[Y]es or [N]o ? (default is no)'
	if ($netfx -eq 'y' -or $netfx -eq 'yes') {
		$sxsdisk = [System.Environment]::GetLogicalDrives()| Out-GridView -Title 'Select Partition' -PassThru
		$sxssource = Get-ChildItem -Path $sxsdisk -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'sxs'} | Out-GridView -Title 'Select sxs path' -PassThru
		Enable-WindowsOptionalFeature –Online –FeatureName WCF-NonHTTP-Activation -NoRestart -All -LimitAccess -Source $sxssource.fullname
	}
	else {
		Enable-WindowsOptionalFeature -Online -FeatureName WCF-NonHTTP-Activation -NoRestart -All
	}
}
else {
	&DISM /ONLINE /Enable-Feature /FeatureName:WAS-WindowsActivationService /FeatureName:WAS-ProcessModel /FeatureName:WAS-NetFxEnvironment /FeatureName:WAS-ConfigurationAPI /FeatureName:WCF-NonHTTP-Activation
}

#14 Intranet兼容性视图设置，默认禁用，如果为ECM客户端，则开启
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation' -Name IntranetCompatibilityMode -Value 0
if($OSLang.name -eq 'zh-CN'){
	Write-Warning "本计算机是否为ECM客户端?"
}
else {
	Write-Warning "Is this computer an ECM client? "
}

[string]$setreg = Read-Host -Prompt "[Y] Yes  or  [N] No   (default is 'N')"
If ($setreg -eq "y" -or $setreg -eq "yes") {
    Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation' -Name IntranetCompatibilityMode -Value 1
}

#15调整计算机外观为最佳性能（value=1：最佳体验）
Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects -Name VisualFXSetting -Type DWord -Value 2
#Set-ItemProperty HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects -Name VisualFXSetting -Value 2

#修改hosts 增加液相默认ip设为AGLC，7890B默认IP设置为AGGC，7820A默认IP设置为20GC，方便测试使用
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`r`n192.168.254.11`t`tAGLC`r`n192.168.0.29`t`tAGGC`r`n192.168.0.26`t`t20GC`r"

#修改数据执行保护(DEP)状态为仅为Windows程序启用
Invoke-Command {bcdedit /set nx Optin}

#增加本地回环适配器，防止OpenLab 2.0内容管理器激活失败
if($OSLang.name -eq 'zh-CN'){
	Write-Warning "是否安装本地回环网卡（默认为No。OpenLabCDS 2.x增加此网卡可以避免本地连接断开时激活失败的情况）"
}
else {
	Write-Warning 'Install a local loopback network adapter? If the workstation is OpenLab 2.x, this can avoid installation fail when local connection disconnected '
}
  [string]$netadp = Read-Host -Prompt "[Y] Yes  or  [N] No   (default is 'N')"
If ($netadp -eq "y" -or $netadp -eq "yes"){
	$path=Get-Location
	$devcon=$path.path + '\devcon'
	&$devcon install $env:windir\Inf\Netloop.inf *MSLOOP
}

#禁用windows防火墙，使用停止防火墙服务形式，注册表方式被注释
<#
$FW = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
$FWVAULE = '-Name EnableFirewall -Value 0'
Set-ItemProperty $FW\DomainProfile $FWVAULE
Set-ItemProperty $FW\PublicProfile $FWVAULE
Set-ItemProperty $FW\StandardProfile $FWVAULE
#>
Set-Service -Name MpsSvc -StartupType Disabled
Stop-Service -Name MpsSvc

#IE设置，发行商证书吊销检查
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\' -Name State -Value 0x23e00
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name CertificateRevocation -Value 0

#禁用WPF Fontcache 3.0.0.0
if ($OSVer -ne 10){
	Set-Service -Name FONTCACHE3.0.0.0 -Status Stopped -StartupType Disabled
}

#禁用UAC
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 0

#禁用系统还原
#删除注册表键，可能存在未知危险，暂不启用，使用cmdlet
<#
$SR= 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
New-Item $SR -Force
New-ItemProperty $SR -Name RPSessionInterval -Type Dword -Value 0
Remove-Item 'HKLM:\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SPP' -Recurse
#>
Disable-ComputerRestore -Drive ([System.Environment]::GetLogicalDrives())

#Openlab 0202不联网工作站加速注册表，注意：如果此计算机从未链接过互联网，应用此处优化后在进行上网浏览时会导致根证书无法更新而造成大多数https网页无法正常加载，需要手动恢复设置方可正常上网
New-Item HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot -Force
Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot -Name DisableRootAutoUpdate -Type DWord -Value 1
New-Item HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\SystemCertificates\AuthRoot -Force
Set-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\SystemCertificates\AuthRoot -Name DisableRootAutoUpdate -Type DWord -Value 1

#自动修改IP,win7需要将自带的powershell升级至V3以上的版本方可运行
if ($psversiontable.PSVersion.Major -gt 2) {
	if ($OSLang -eq 'zh-CN') {
		Write-Warning '是否自动设定单机版工作站所需要的计算机网卡地址? 按Y确认,直接回车跳过。
		如果选择自动设定，后面将会弹出本地网卡选择界面以及安装仪器类型界面,单击对应的项目后按右下角确定按钮
		完成后选定网卡的IP将被设定为192.168.x.100'
	}
	else {
		Write-Warning 'Whether to automatically set the stand-alone workstation required computer network adapter IP address?
		Press Y to confirm, directly enter to skip.
		If you select Auto Setup, the local NIC selection interface and instrument type interface will pop up.
		Click the corresponding item and press the OK button
		The select NIC''s IP will be set to 192.168.x.100'
	}
	[string]$ip = Read-Host -Prompt "[Y] Yes  or  [N] No   (default is 'N')"
	if ($ip -eq 'y' -or $ip -eq 'yes') {
		$ins = 'GC','LC' | Out-GridView -Title 'Selcet instument type' -PassThru
		if ($ins -eq 'GC') {
			$insip = '192.168.0.100'
		}
		elseif ($ins -eq 'LC') {
			$insip = '192.168.254.100'
		}
		if ($OSVer -ne 7) {
			$ipadp = Get-NetAdapter | Out-GridView -Title 'select adapter' -PassThru
			Set-NetIPInterface -InterfaceIndex $ipadp.interfaceindex -Dhcp Disabled
			Remove-NetIPAddress -InterfaceIndex $ipadp.interfaceindex -AddressFamily IPv4 -Confirm:$false
			New-NetIPAddress -InterfaceIndex $ipadp.interfaceindex -IPAddress $insip -PrefixLength 24 -AddressFamily IPv4
		}
		else {
			$ipadp = $PhysicalAdapters | Out-GridView -Title 'Select Adapter' -PassThru
			$win7ip = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where {$_.servicename -eq $ipadp.servicename}
			$win7ip.EnableStatic($insip,'255.255.255.0')
			#注释掉的netsh方式同样可用，如需启用，将上两行注释掉
			#netsh interface ipv4 set address $ipadp.NetConnectionID static $insip 255.255.255.0
		}
	}
}


#调整powershell脚本安全策略为远程脚本需签名
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned

#重启计算机提示
Write-Host  -ForegroundColor Green '脚本执行完毕，部分修改需要重启计算机后生效'