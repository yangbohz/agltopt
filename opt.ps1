<#
				   安装前优化脚本
按照安装手册进行，主要是将需要手动点击的项目变更为直接修改注册表项
编写人：杨波，email：bo.yang@non.agilent.com
ver：0.92
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
    Write-Warning '恭喜你，检测到未安装SP1的Windows 7，在安装光盘的disk6下面有补丁，请事先安装一下，大概需要一个小时的时间'
    exit
}
elseif ($psversiontable.BuildVersion.Major -eq 10) {
    $OSVer = 10
}
elseif ($psversiontable.BuildVersion.Major -eq 6 -and $psversiontable.BuildVersion.Minor -eq 1) {
    $OSVer = 7
}
elseif ($psversiontable.BuildVersion.Major -eq 6 -and ($psversiontable.BuildVersion.Minor -eq 2 -or $psversiontable.BuildVersion.Minor -eq 3)) {
    $OSVer = 8
}

#检查系统当前的显示语言变量
$OSLang = [System.Globalization.Cultureinfo]::InstalledUICulture

#运行选项选择
if ($OSLang -eq 'zh-CN') {
    Write-Warning -Message '是否自动启用NetFx3及非HTTP激活？如选择否，则认为已经启用NetFX3，直接启用非HTTP激活功能，如选择是，请留意readme中的相关说明'
    [string]$netfx = Read-Host -Prompt "[Y]es or [N]o   (default is no)"
    Write-Warning "本计算机是否为ECM客户端?"
    [string]$setie = Read-Host -Prompt "[Y]es or [N]o   (default is no)"
    Write-Warning "是否安装本地回环网卡（默认为No。OpenLabCDS 2.x增加此网卡可以避免本地连接断开时激活失败的情况）"
    [string]$netadp = Read-Host -Prompt "[Y]es or [N]o   (default is no)"
    Write-Warning '是否自动设定单机版工作站所需要的计算机网卡地址? 按Y确认,直接回车跳过。
	完成后选定网卡的IP将被设定为192.168.x.100'
    [string]$ip = Read-Host -Prompt "[Y]es or [N]o   (default is no)"
}
if ($OSLang -eq 'en-US') {
    Write-Warning -Message 'Would like automatically enable NetFx3 and non-http-activation? Default only enable non-http-activation. If you select yes, please view the readme'
    [string]$netfx = Read-Host -Prompt "[Y]es or [N]o   (default is no)"
    Write-Warning "Is this computer an ECM client? "
    [string]$setie = Read-Host -Prompt "[Y]es or [N]o   (default is no)"
    Write-Warning 'Install a local loopback network adapter? If the workstation is OpenLab 2.x, this can avoid installation fail when local connection disconnected '
    [string]$netadp = Read-Host -Prompt "[Y]es or [N]o   (default is no)"
    Write-Warning 'Whether to automatically set the stand-alone workstation required computer network adapter IP address?
	Press Y to confirm, directly enter to skip.
	If you select Auto Setup, the local NIC selection interface and instrument type interface will pop up.
	Click the corresponding item and press the OK button
	The select NIC''s IP will be set to 192.168.x.100'
    [string]$ip = Read-Host -Prompt "[Y]es or [N]o   (default is no)"
}

#检查各个相关项值
function checkvalue () {
    function av($value) {
        Add-Content -Path .\verify.txt -Value $value
    }

    $TimeStamp = Get-Date -Format o | ForEach-Object {$_ -replace ":", "-"}
    av ('>>>>>>>>>>STATUS CHECKED AT ' + $TimeStamp + ' ON ' + $env:COMPUTERNAME + '<<<<<<<<<<')

    $var = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    switch ($var.HideFileExt) {
        0 {av('文件扩展名已显示')}
        1 {av('文件扩展名未显示')}
    }

    switch ($var.SharingWizardOn) {
        0 {av('文件共享向导已关闭')}
        1 {av('文件共享向导已打开')}
    }

    $var = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState'
    switch ($var.FullPath) {
        0 {av('标题栏中显示简短路径')}
        1 {av('标题栏中显示完整路径')}
    }

    function SvcStTyp ($svcdsp, $svcname) {
        if ($psversiontable.PSVersion.Major -ge 5) {
            switch ((Get-Service -Name $svcname -ErrorAction SilentlyContinue).StartType) {
                $null {av($svcdsp + '服务未找到')}
                'Automatic' {av($svcdsp + '服务为自动启动状态')}
                'Manual' {av($svcdsp + '服务为手动启动状态')}
                'Disabled' {av($svcdsp + '服务为禁止启动状态')}
            }
        }
        else {
            switch ((Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='$svcname'").startmode) {
                $null {av($svcdsp + '服务未找到')}
                'Auto' {av($svcdsp + '服务为自动启动状态')}
                'Manual' {av($svcdsp + '服务为手动启动状态')}
                'Disabled' {av($svcdsp + '服务为禁止启动状态')}
            }
        }
    }

    SvcStTyp 'Application Experience' AeLookupSvc
    SvcStTyp 'Desktop Window Manager Session Manager' UxSms
    SvcStTyp '索引' WSearch
    SvcStTyp 'WPF字体缓存服务' 'FONTCACHE3.0.0.0'
    SvcStTyp 'Windows自动更新' wuauserv

    $var = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    switch ($var.HideFastUserSwitching) {
        1 {av('快速用户切换入口已隐藏')}
        0 {av('快速用户切换入口已显示')}
        $null {av('快速用户切换入口未设置（默认打开）')}
    }

    switch ($var.LogonType) {
        1 {av('未使用经典登陆')}
        0 {av('总是使用经典登陆')}
    }

    switch ($var.EnableLUA) {
        0 {av('UAC已彻底禁用')}
        1 {av('UAC已启用,WIN10请忽略此条')}
    }

    $var = powercfg.exe -getactivescheme
    $var = $var.substring(($var.lastindexof('(')) + 1 , $var.lastindexof(')') - $var.lastindexof('(') - 1 )
    av('活动的电源方案设置为:' + $var)

    $var = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation' -ErrorAction SilentlyContinue
    switch ($var.IntranetCompatibilityMode) {
        1 {av('IE Intranet兼容性视图已开启')}
        0 {av('IE Intranet兼容性视图已关闭')}
        $null {av('IE Intranet兼容性视图未设置')}
    }

    $var = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -ErrorAction SilentlyContinue
    switch ($var.VisualFXSetting) {
        1 {av('计算机视觉效果设置为最佳外观')}
        2 {av('计算机视觉效果设置为最佳性能')}
        0 {av('计算机视觉效果设置为自动决定')}
        3 {av('计算机视觉效果设置为自定义')}
        $null {av('计算机视觉效果设置为自动决定')}
    }

    $var = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing'
    switch ($var.state) {
        0x23c00 {av('发行商证书吊销情况需要检查')}
        0x23e00 {av('发行商证书吊销情况不做检查')}
    }

    $var = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    switch ($var.CertificateRevocation) {
        0 {av('服务器证书吊销情况不做检查')}
        1 {av('服务器证书吊销情况需要检查')}
    }

    $var = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients' -ErrorAction SilentlyContinue
    if ($var.'{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}' -notcontains $null) {
        av('系统还原已开启')
    }
    elseif ($var.'{3E7F07C9-6BC3-11DC-A033-0019B92BB8B1}' -notcontains $null) {
        av('系统还原部分开启（仅适用于WIN7）')
    }
    else { av('系统还原已关闭') }
    $var = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -ErrorAction SilentlyContinue
    switch ($var.DisableRootAutoUpdate) { 
        0 {av('检查证书更新开启')} 
        1 {av('检查证书更新已关闭(可以提高离线工作站性能)，但是在以后连接互联网时可能会出现HTTPS链接无法打开的现象')} 
    } 
    $var = Get-ChildItem -Recurse cert:\ | Where-Object {$_.Thumbprint -eq '4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5'} -ErrorAction SilentlyContinue 
    if ($null -eq $var) { 
        av('安装必要的根证书不存在') 
    } 
    else {
        av('检测到所需的根证书') 
    }
    $var = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters
    switch ($var.Type) {
        NTP {av('Windows自动设置时间为开启状态')  }
        NoSync {av('Windows自动设置时间为关闭状态')}
    }
}

checkvalue

#开始修改系统部分
#2 #显示文件扩展名 
Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0 
#标题栏中显示完整路径
Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState -Name FullPath -Value 1

#禁用共享向导
Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SharingWizardOn -Value 0

#4
#禁用windows自动更新
Set-Service -Name wuauserv -StartupType Disabled
Stop-Service -Name wuauserv

#5
#禁用Application Experience服务
if ($OSVer -ne 10) {
    Set-Service -Name AeLookupSvc -StartupType Disabled -Status Stopped
}


#禁用Desktop Window Manager Session Manager服务，如果计算机配置较好，考虑到用户使用体验，此服务可以不禁用
if ($OSVer -eq 7) {
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
& powercfg /SETACTIVE SCHEME_MIN

#禁止空闲自动睡眠
& powercfg /change standby-timeout-ac 0

#禁止空闲自动关闭硬盘
& powercfg /change disk-timeout-ac 0

#9
#修改本地用户以自己的身份验证
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name ForceGuest -Type DWord -Value 0 -Force

#12修改网卡电源管理,此处脚本修改自https://gallery.technet.microsoft.com/scriptcenter/Disable-turn-off-this-f74e9e4a
Function Disable-OSCNetAdapterPnPCaptitlies {
    #find only physical network,if value of properties of adaptersConfigManagerErrorCode is 0,  it means device is working properly. 
    #even covers enabled or disconnected devices.
    #if the value of properties of configManagerErrorCode is 22, it means the adapter was disabled. 
    $PhysicalAdapters = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object {$_.PNPDeviceID -notlike "ROOT\*" -and $_.Manufacturer -ne "Microsoft" -and $_.ConfigManagerErrorCode -eq 0 -and $_.ConfigManagerErrorCode -ne 22}
    Foreach ($PhysicalAdapter in $PhysicalAdapters) {
        #check the unique device id number of network adapter in the currently environment.
        $DeviceID = $PhysicalAdapter.DeviceID
        If ([Int32]$DeviceID -lt 10) {
            $AdapterDeviceNumber = "000" + $DeviceID
        }
        Else {
            $AdapterDeviceNumber = "00" + $DeviceID
        }
        $KeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\$AdapterDeviceNumber"
        Set-ItemProperty -Path $KeyPath -Name "PnPCapabilities" -Value 24	
    }
}
Disable-OSCNetAdapterPnPCaptitlies

#13启用netfx3非HTTP激活默认直接启用非HTTP激活，如果在运行选项中有指定，则进行netfx3安装
if ($OSVer -ne 7) {
    if ($netfx -eq 'y' -or $netfx -eq 'yes') {
        $sxsdisk = [System.Environment]::GetLogicalDrives()| Out-GridView -Title 'Select the sxs dirve' -PassThru
        $sxssource = Get-ChildItem -Path $sxsdisk -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'sxs'} | Out-GridView -Title 'Select sxs path' -PassThru
        Enable-WindowsOptionalFeature –Online –FeatureName NetFx3, WCF-NonHTTP-Activation -NoRestart -All -LimitAccess -Source $sxssource.fullname
    }
    else {
        Enable-WindowsOptionalFeature -Online -FeatureName WCF-NonHTTP-Activation -NoRestart -All
    }
}
else {
    &DISM /ONLINE /Enable-Feature /FeatureName:WAS-WindowsActivationService /FeatureName:WAS-ProcessModel /FeatureName:WAS-NetFxEnvironment /FeatureName:WAS-ConfigurationAPI /FeatureName:WCF-NonHTTP-Activation
}

#14 Intranet兼容性视图设置，默认禁用，如果为ECM客户端，则开启
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation' -Name IntranetCompatibilityMode -Type DWord -Value 0
If ($setie -eq "y" -or $setie -eq "yes") {
    Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation' -Name IntranetCompatibilityMode -Type DWord -Value 1
}

#15调整计算机外观为最佳性能（value=1：最佳体验）
Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects -Name VisualFXSetting -Type DWord -Value 2
#Set-ItemProperty HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects -Name VisualFXSetting -Value 2

#修改hosts 增加液相默认ip设为AGLC，7890B默认IP设置为AGGC，7820A默认IP设置为20GC，方便测试使用
Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`r`n192.168.254.11`t`tAGLC`r`n192.168.0.29`t`tAGGC`r`n192.168.0.26`t`t20GC`r"

#修改数据执行保护(DEP)状态为仅为Windows程序启用
Invoke-Command {bcdedit /set nx Optin}

#增加本地回环适配器，防止OpenLab 2.x内容管理器激活失败,增加前先进行检测，如果发现已经安装，则不再安装更多的虚拟网卡
If ($netadp -eq "y" -or $netadp -eq "yes") {
    # WIN7不可用get-netadapter cmdlet,改用下面的get-wmiobject
    # $isloopbackinstalled = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*loopback*"}
    $isloopbackinstalled = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object {$_.Name -like "*loopback*"}
    if ($null -eq $isloopbackinstalled) {
        $devcon = (Get-Location).path + "\Bin\devcon.exe"
        &$devcon install $env:windir\Inf\Netloop.inf *MSLOOP
    }
}

#禁用windows防火墙，停止防火墙服务形式可能会造成win10系统出问题，改用注册表方式

$FW = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
Set-ItemProperty ($FW + '\DomainProfile') -Name EnableFirewall -Value 0
Set-ItemProperty ($FW + '\PublicProfile') -Name EnableFirewall -Value 0
Set-ItemProperty ($FW + '\StandardProfile') -Name EnableFirewall -Value 0

# Set-Service -Name MpsSvc -StartupType Disabled
# Stop-Service -Name MpsSvc

#IE设置，发行商证书吊销检查
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing' -Name State -Value 0x23e00
Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name CertificateRevocation -Value 0

#禁用WPF Fontcache 3.0.0.0
Set-Service -Name FONTCACHE3.0.0.0 -Status Stopped -StartupType Disabled

#禁用UAC,老版本中仅仅修改EnableUAC注册表项，但是这样会导致win8及win10中的Modern应用无法打开，例如win10中的EDGE以及计算器，故在新版本中修改为温和的方式，仅仅禁用UAC提示，仅仅在检测到系统为win7后才彻底关闭UAC
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name PromptOnSecureDesktop -Value 0
# WIN7的额外修改，彻底关闭UAC
if ($OSVer -eq 7) {
    Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 0
}

#禁用系统还原
if ($OSVer -eq 7) {
    Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients' -Name '{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}' -ErrorAction SilentlyContinue
    Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients' -Name '{3E7F07C9-6BC3-11DC-A033-0019B92BB8B1}' -ErrorAction SilentlyContinue
}
else {
    # 增加错误忽略，否则会尝试关闭光驱上的系统还原时报错，对工程师造成困扰
    Disable-ComputerRestore -Drive ([System.Environment]::GetLogicalDrives()) -ErrorAction SilentlyContinue
}

#Openlab 不联网工作站加速注册表，注意：如果此计算机从未链接过互联网，应用此处优化后在进行上网浏览时会导致根证书无法更新而造成https网页无法正常加载，需要手动删除此处的设置·方可正常上网
New-Item HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot -Force
Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot -Name DisableRootAutoUpdate -Type DWord -Value 1
New-Item HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\SystemCertificates\AuthRoot -Force
Set-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\SystemCertificates\AuthRoot -Name DisableRootAutoUpdate -Type DWord -Value 1

#自动修改IP,win7需要将自带的powershell升级至V3以上的版本方可运行
if ($psversiontable.PSVersion.Major -gt 2) {
    if ($ip -eq 'y' -or $ip -eq 'yes') {
        $ins = 'GC', 'LC' | Out-GridView -Title '选择仪器类型 Selcet Instrument Type' -PassThru
        if ($ins -eq 'GC') {
            $insip = '192.168.0.100'
        }
        elseif ($ins -eq 'LC') {
            $insip = '192.168.254.100'
        }
        if ($OSVer -ne 7) {
            $ipadp = Get-NetAdapter | Out-GridView -Title '选择仪器连接的网卡 Select Adapter' -PassThru
            Set-NetIPInterface -InterfaceIndex $ipadp.interfaceindex -Dhcp Disabled
            Remove-NetIPAddress -InterfaceIndex $ipadp.interfaceindex -AddressFamily IPv4 -Confirm:$false
            New-NetIPAddress -InterfaceIndex $ipadp.interfaceindex -IPAddress $insip -PrefixLength 24 -AddressFamily IPv4
        }
        else {
            $ipadp = $PhysicalAdapters | Out-GridView -Title '选择仪器连接的网卡 Select Adapter' -PassThru
            $win7ip = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.servicename -eq $ipadp.servicename}
            $win7ip.EnableStatic($insip, '255.255.255.0')
            #注释掉的netsh方式同样可用，如需启用，将上两行注释掉
            #netsh interface ipv4 set address $ipadp.NetConnectionID static $insip 255.255.255.0
        }
    }
}

#检测所需的Verisign根证书，如未检测到，安装至本地计算机的受信任的根证书颁发机构中 
function Add-Cert ($CertHash) {
    $CertExist = Get-ChildItem -Recurse cert:\ | Where-Object {$_.Thumbprint -eq "$CertHash"}
    if ($null -eq $CertExist) {
        $CertPath = (Get-Location).Path + "\Bin\$CertHash.cer"
        if ($psversiontable.PSVersion.Major -gt "2") {
            Import-Certificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\Root
        }
        else {
            &certutil.exe -addstore -enterprise "ROOT" $CertPath
        }
    }
}
Add-Cert "4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5"
Add-Cert "3679ca35668772304d30a5fb873b0fa77bb70d54"
# $vericert = Get-ChildItem -Recurse cert:\ | Where-Object {$_.Thumbprint -eq '4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5'}
# if ($vericert -eq $null) {
#     $vericertpath = (Get-Location).Path + '\vericert.cer'
#     if ($psversiontable.PSVersion.Major -gt '2') {
#         Import-Certificate -FilePath $vericertpath -CertStoreLocation Cert:\LocalMachine\Root
#     }
#     else {
#         &certutil.exe -addstore -enterprise "ROOT" $vericertpath
#     }
# }

# 修改系统默认浏览器为IE，仅对win10生效。win10默认的EDGE浏览器无法在帮助系统中修锁关键字。折腾挺久，但是WIN10为了防止非法修改默认浏览器，在注册表中增加了校验值，必须手工通过系统界面进行修改，下面的全部注释掉
<#
$browserreg = 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\'
Remove-Item -Path ($browserreg + 'ftp') -Recurse
Remove-Item -Path ($browserreg + 'http') -Recurse
Remove-Item -Path ($browserreg + 'https') -Recurse
New-Item -ItemType Directory ($browserreg + 'ftp\UserChoice') -Force
Set-ItemProperty -Path ($browserreg + 'ftp\UserChoice') -Name ProgId -Value IE.FTP
New-Item -ItemType Directory ($browserreg + 'http\UserChoice') -Force
Set-ItemProperty -Path ($browserreg + 'http\UserChoice') -Name ProgId IE.HTTP
New-Item -ItemType Directory ($browserreg + 'https\UserChoice') -Force
Set-ItemProperty -Path ($browserreg + 'https\UserChoice') -Name ProgId IE.HTTPS
#>

# 以下为针对WIN10 1703更新部分
# 禁用地图更新
if ($OSVer -eq 10) {
    Set-ItemProperty -Path HKLM:\SYSTEM\Maps -Name AutoUpdateEnabled -Value 0 -Type DWord -ErrorAction SilentlyContinue
}

# 禁用系统的smartscreen检查
if ($psversiontable.BuildVersion.Build -eq 15063) {
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name 'SmartScreenEnabled' -Value 'Off' -Force
    New-ItemProperty -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Value 0 -Type DWord -Force
    New-ItemProperty -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter' -Name 'PreventOverride' -Value 0 -Type DWord -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost -Name 'EnableWebContentEvaluation' -Value 0 -Type DWord -Force
}

# Flashplayer受信任位置设置，2.x工作站flash互动教程无限转圈
if ($null -eq (Get-Content -Path C:\WINDOWS\system32\Macromed\Flash\FlashPlayerTrust\Agilent.txt -ErrorAction SilentlyContinue)) {
    New-Item -ItemType Directory C:\WINDOWS\system32\Macromed\Flash\FlashPlayerTrust
    Add-Content -Path C:\WINDOWS\system32\Macromed\Flash\FlashPlayerTrust\Agilent.txt -Value 'C:\Program Files (x86)\Agilent Technologies\OpenLABHelp'
}

# WIN10 时间问题修正(重新注册时间服务)
if ($OSVer -eq 10) {
    Stop-Service -Name W32Time -Force
    &w32tm.exe /unregister
    &w32tm.exe /register
    Start-Service -Name W32Time
}

#调整powershell脚本安全策略为远程脚本需签名
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned

checkvalue

#重启计算机提示
Write-Host  -ForegroundColor Green "脚本执行完毕，部分修改需要重启计算机后生效`nDONE, YOU NEED REBOOT THE COMPUTER"