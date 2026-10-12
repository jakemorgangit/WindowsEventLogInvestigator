<#
.SYNOPSIS
    Windows Event Log Investigator - collect, filter and visualise problem events for RCA.

.DESCRIPTION
    Collects Critical / Error / Warning events plus curated "key" informational events
    (reboots, SQL restarts, failovers, AG role changes, patching...) from one or more servers:

      * System and Application logs
      * SQL Server - every SQL provider registered in the Application log, plus the
        SQL Server ERRORLOG files and SQL Agent logs (SQLAGENT.OUT) for every instance
      * Failover Clustering - System log, FailoverClustering/Operational, Manager/Admin,
        CsvFs/Operational and Cluster-Aware Updating
      * Optional: Hyper-V, Security (failed logons, lockouts, log cleared), SCOM

    Events are categorised (SQL Server, Cluster, Storage, Network/AD, Power/Boot...),
    tagged with a plain-English description of well-known event IDs, and shown on an
    interactive timeline: stacked problem counts per time bucket, swim lanes per category
    (or computer / provider) and vertical marker lines for reboots, SQL restarts and
    failovers. Drag on the timeline to zoom, click a bar or dot to drill in, right-click
    to zoom out. Results export to CSV or a self-contained interactive HTML report.

    A collection can be saved as a session file (.json) holding every event, the collection
    log, the settings and the current filters / zoom. Open it on any machine (File > Open
    session, drag and drop, or -SessionPath) to review it without access to the servers.

    Run without parameters for the GUI, or with -NoGui for headless collection.

.PARAMETER ComputerName
    One or more computers to collect from (default: local computer). Remote collection
    uses the Remote Event Log Management firewall rules; SQL logs use Remote Registry
    and the admin shares (\\server\D$).

.PARAMETER StartTime
    Start of the time window. Defaults to EndTime minus -Hours.

.PARAMETER EndTime
    End of the time window. Defaults to now.

.PARAMETER Hours
    Size of the time window in hours when -StartTime is not given (default 24).

.PARAMETER Sources
    What to collect: System, Application, SQL, SQLLogs, Cluster, HyperV, Security, OpsMgr.

.PARAMETER IncludeInformation
    Also collect all Information-level events (noisy). Key informational events
    (reboots, failovers, SQL start/stop...) are always collected.

.PARAMETER MaxEventsPerQuery
    Safety cap per individual log query (default 5000).

.PARAMETER NoGui
    Collect without the GUI. Writes a session file + CSV + HTML to -OutputPath, or returns objects.

.PARAMETER OutputPath
    Folder for -NoGui output (session .json, CSV, HTML report, collection log).

.PARAMETER SessionPath
    One or more saved session files (.json) to open instead of collecting. Several files are
    merged (e.g. one per cluster node). With -NoGui they are converted to CSV + HTML.

.PARAMETER AutoRun
    GUI: start collecting as soon as the window opens.

.EXAMPLE
    .\WinEventLogInvestigator.ps1

.EXAMPLE
    .\WinEventLogInvestigator.ps1 -ComputerName SQLNODE1,SQLNODE2 -StartTime '2026-10-11 22:00' -EndTime '2026-10-12 02:00' -AutoRun

.EXAMPLE
    .\WinEventLogInvestigator.ps1 -ComputerName SQLNODE1 -Hours 72 -Sources System,SQL,SQLLogs,Cluster -NoGui -OutputPath C:\Temp\RCA

.EXAMPLE
    .\WinEventLogInvestigator.ps1 -SessionPath .\EventLogSession_SQLNODE1_20261012_093000.json
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [datetime]$StartTime,
    [datetime]$EndTime,
    [ValidateRange(1, 8760)][int]$Hours = 24,
    [string[]]$Sources = @('System', 'Application', 'SQL', 'SQLLogs', 'Cluster'),
    [switch]$IncludeInformation,
    [ValidateRange(100, 1000000)][int]$MaxEventsPerQuery = 5000,
    [switch]$NoGui,
    [string]$OutputPath,
    [string[]]$SessionPath,
    [switch]$AutoRun
)

# Accept comma separated lists too (powershell.exe -File passes 'a,b' as a single string)
$ComputerName = @($ComputerName | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ } | Select-Object -Unique)
$SessionPath = @($SessionPath | ForEach-Object { $_ -split ',' } | Where-Object { $_ } | ForEach-Object { (Resolve-Path -LiteralPath $_ -ErrorAction Stop).ProviderPath -replace '^\\\\\?\\', '' })
$validSources = 'System', 'Application', 'SQL', 'SQLLogs', 'Cluster', 'HyperV', 'Security', 'OpsMgr'
$Sources = @($Sources | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ } | ForEach-Object {
    $src = $_; $match = $validSources | Where-Object { $_ -eq $src }
    if (-not $match) { throw "Unknown source '$src'. Valid sources: $($validSources -join ', ')" }
    $match } | Select-Object -Unique)
if (-not $PSBoundParameters.ContainsKey('EndTime')) { $EndTime = Get-Date }
if (-not $PSBoundParameters.ContainsKey('StartTime')) { $StartTime = $EndTime.AddHours(-$Hours) }
if ($StartTime -ge $EndTime) { throw "StartTime ($StartTime) must be before EndTime ($EndTime)." }

# The GUI needs .NET Framework (WinForms charting); relaunch in Windows PowerShell when started from PowerShell 7.
if (-not $NoGui -and $PSVersionTable.PSEdition -eq 'Core') {
    $winPs = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $winPs)) { throw 'The GUI requires Windows PowerShell 5.1. Use -NoGui from PowerShell 7.' }
    Write-Host 'Relaunching in Windows PowerShell 5.1 (the GUI charting requires .NET Framework)...'
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', $PSCommandPath,
        '-ComputerName', ($ComputerName -join ','), '-StartTime', $StartTime.ToString('o'), '-EndTime', $EndTime.ToString('o'),
        '-MaxEventsPerQuery', $MaxEventsPerQuery, '-Sources', ($Sources -join ','))
    if ($IncludeInformation) { $relaunch += '-IncludeInformation' }
    if ($AutoRun) { $relaunch += '-AutoRun' }
    if ($SessionPath) { $relaunch += @('-SessionPath', ($SessionPath -join ',')) }
    & $winPs @relaunch
    return
}

#region ===================== Collector (runs locally or inside a background job) =====================
$Collector = {
    param([string]$Computer, [datetime]$Start, [datetime]$End, [string[]]$Sources, [int]$MaxEvents, [bool]$IncludeInfo)

    $isLocal = [string]::IsNullOrWhiteSpace($Computer) -or $Computer -in @('.', 'localhost', '127.0.0.1') -or
               $Computer -ieq $env:COMPUTERNAME -or $Computer -ieq "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
    $machine  = if ($isLocal) { $env:COMPUTERNAME } else { $Computer.ToUpper() }
    $results  = New-Object System.Collections.Generic.List[object]
    $runLog   = New-Object System.Collections.Generic.List[string]
    $seen     = @{}
    $startUtc = $Start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $endUtc   = $End.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $levelNames = @{ 1 = 'Critical'; 2 = 'Error'; 3 = 'Warning'; 4 = 'Information' }
    $problemLevels = if ($IncludeInfo) { @(1, 2, 3, 4, 0) } else { @(1, 2, 3) }
    $sqlProviderRx = '^(MSSQL|SQLAgent|SQLSERVERAGENT|SQLWriter|SQLBrowser|SQLIS|SQLTELEMETRY|SQLCEIP|SSISTELEMETRY|SQLDumper|SQLVDI|SQLBackupToUrl|MSOLAP|ReportServer|SQL Server)'
    # Service Control Manager 7036/7040 are only kept for services that matter for SQL/cluster RCA
    $serviceInterestRx = '(?i)SQL|Cluster|MSDTC|Distributed Transaction|Analysis Services|Reporting Services|Integration Services|Power BI|Windows Update|Windows Modules Installer|Hyper-V|Volume Shadow|Netlogon|Windows Time'

    function Write-RunLog([string]$Text) { $runLog.Add(('{0:HH:mm:ss} [{1}] {2}' -f (Get-Date), $machine, $Text)) }
    function Write-Step([string]$Text) { Write-Progress -Activity "Collecting from $machine" -Status $Text }

    #---- Categories --------------------------------------------------------------------------
    $categoryCache = @{}
    function Get-EventCategory([string]$LogName, [string]$Provider) {
        $key = "$LogName|$Provider"
        if ($categoryCache.ContainsKey($key)) { return $categoryCache[$key] }
        $cat = $null
        if ($LogName -eq 'Security') { $cat = 'Security' }
        elseif ($LogName -eq 'Operations Manager') { $cat = 'OpsMgr' }
        else {
            $cat = switch -Regex ($Provider) {
                $sqlProviderRx { 'SQL Server'; break }
                'FailoverClustering|ClusSvc|ClusterAwareUpdating' { 'Cluster'; break }
                'Hyper-V' { 'Hyper-V'; break }
                '^(Microsoft-Windows-Kernel-Power|Microsoft-Windows-Kernel-General|EventLog|User32|Microsoft-Windows-Kernel-Boot|Microsoft-Windows-WER-SystemErrorReporting|BugCheck|Microsoft-Windows-Power-Troubleshooter|Microsoft-Windows-Winlogon|Microsoft-Windows-Wininit)$' { 'Power / Boot'; break }
                '^(disk|Ntfs|Microsoft-Windows-Ntfs|storvsc|storahci|stornvme|StorPort|Microsoft-Windows-StorPort|volmgr|volsnap|mpio|msdsm|iScsiPrt|Microsoft-Windows-Disk|Microsoft-Windows-StorageSpaces.*|Microsoft-Windows-ReFS|ReFS|VSS|Microsoft-Windows-Storage.*|partmgr|Microsoft-Windows-Partition|LSI_.*|megasas.*|percsas.*|HpCISSs.*|smartpqi|ql2.*|elx.*|Microsoft-Windows-Kernel-IO|Microsoft-Windows-Volume.*)$' { 'Storage'; break }
                '^(Tcpip|Microsoft-Windows-Tcpip|NetBT|NETLOGON|Microsoft-Windows-DNS-Client|DnsApi|Microsoft-Windows-Time-Service|W32Time|Microsoft-Windows-NDIS|Microsoft-Windows-MsLbfoProvider|Microsoft-Windows-NetworkProfile|e1.express|ixgbe|i40e.*|bxnd.*|b57nd.*|ebdrv|mlx.*|vmxnet.*|netvsc|Microsoft-Windows-SMBClient|Microsoft-Windows-SMBServer|Srv|LsaSrv|Microsoft-Windows-Security-Kerberos|Kerberos|Microsoft-Windows-GroupPolicy|Userenv|Schannel|Microsoft-Windows-Iphlpsvc|Dhcp.*|Microsoft-Windows-Dhcp.*)$' { 'Network / AD / Auth'; break }
                '^Service Control Manager$' { 'Services'; break }
                '^(Microsoft-Windows-WindowsUpdateClient|Microsoft-Windows-Servicing|MsiInstaller|TrustedInstaller|Microsoft-Windows-RestartManager|Windows Server Update Services)$' { 'Updates / Installs'; break }
                '^(Application Error|Application Hang|Windows Error Reporting|\.NET Runtime|Microsoft-Windows-WER.*)$' { 'App Crashes'; break }
                '^(Microsoft-Windows-Resource-Exhaustion-Detector|Microsoft-Windows-Resource-Exhaustion-Resolver|Microsoft-Windows-MemoryDiagnostics.*|PerfNet|Perflib|Microsoft-Windows-Perflib|LoadPerf|WMI|Microsoft-Windows-WMI)$' { 'Resources / Perf'; break }
                '^(HealthService|Health Service.*|OpsMgr.*)' { 'OpsMgr'; break }
            }
            if (-not $cat) {
                if ($LogName -match 'FailoverClustering|ClusterAwareUpdating') { $cat = 'Cluster' }
                elseif ($LogName -match 'Hyper-V') { $cat = 'Hyper-V' }
                elseif ($LogName -eq 'System') { $cat = 'System (other)' }
                elseif ($LogName -eq 'Application') { $cat = 'Application (other)' }
                else { $cat = $LogName }
            }
        }
        $categoryCache[$key] = $cat
        return $cat
    }

    #---- Well-known event rules: tag text, timeline marker kind, minimum severity ------------
    $rules = @{}
    function Add-Rule([string]$Category, [string]$ProviderRx, [int[]]$Ids, [string]$Tag, [string]$Marker = '', [int]$Level = 0) {
        foreach ($i in $Ids) {
            $k = "$Category|$i"
            if (-not $rules.ContainsKey($k)) { $rules[$k] = New-Object System.Collections.Generic.List[object] }
            $rules[$k].Add(@{ Rx = $ProviderRx; Tag = $Tag; Marker = $Marker; Level = $Level })
        }
    }
    function Resolve-Rule([string]$Category, [int]$Id, [string]$Provider) {
        $list = $rules["$Category|$Id"]
        if ($list) { foreach ($r in $list) { if ($Provider -match $r.Rx) { return $r } } }
        return $null
    }

    $pb = 'Power / Boot'
    Add-Rule $pb '^EventLog$' 6005 'Boot (Event Log service started)' 'Boot'
    Add-Rule $pb '^EventLog$' 6006 'Clean shutdown (Event Log stopped)'
    Add-Rule $pb '^EventLog$' 6008 'Unexpected shutdown' 'Crash' 2
    Add-Rule $pb '^EventLog$' 6009 'OS version at boot'
    Add-Rule $pb 'Kernel-Power' 41 'Unexpected reboot (Kernel-Power 41)' 'Crash' 1
    Add-Rule $pb 'Kernel-Power' 109 'Kernel shutdown initiated'
    Add-Rule $pb '^User32$' 1074 'Planned restart / shutdown' 'Shutdown'
    Add-Rule $pb '^User32$' 1076 'Shutdown reason recorded'
    Add-Rule $pb 'Kernel-General' 12 'OS started'
    Add-Rule $pb 'Kernel-General' 13 'OS shutting down'
    Add-Rule $pb 'WER-SystemErrorReporting|BugCheck' 1001 'Bugcheck (BSOD)' 'Crash' 1

    $sv = 'Services'; $scm = '^Service Control Manager$'
    Add-Rule $sv $scm 7000 'Service failed to start'
    Add-Rule $sv $scm 7001 'Dependent service failed to start'
    Add-Rule $sv $scm 7009 'Service start timeout'
    Add-Rule $sv $scm 7011 'Service response timeout'
    Add-Rule $sv $scm 7022 'Service hung on start'
    Add-Rule $sv $scm @(7023, 7024) 'Service terminated with error'
    Add-Rule $sv $scm 7031 'Service crashed (will restart)' '' 2
    Add-Rule $sv $scm 7034 'Service crashed' '' 2
    Add-Rule $sv $scm 7036 'Service state change'
    Add-Rule $sv $scm 7040 'Service start type changed'
    Add-Rule $sv $scm 7045 'New service installed'

    $up = 'Updates / Installs'
    Add-Rule $up 'WindowsUpdateClient' 19 'Windows Update installed' 'Update'
    Add-Rule $up 'WindowsUpdateClient' 20 'Windows Update failed' '' 2
    Add-Rule $up 'WindowsUpdateClient' 43 'Windows Update install started'
    Add-Rule $up '^MsiInstaller$' @(1033, 11707) 'Product installed'
    Add-Rule $up '^MsiInstaller$' @(1034, 11724) 'Product removed'
    Add-Rule $up '^MsiInstaller$' 11708 'Product install failed'

    $ac = 'App Crashes'
    Add-Rule $ac '^Application Error$' 1000 'Application crash'
    Add-Rule $ac '^Application Hang$' 1002 'Application hang'
    Add-Rule $ac 'Windows Error Reporting' 1001 'WER fault report'
    Add-Rule $ac '\.NET Runtime' 1026 '.NET unhandled exception'

    $st = 'Storage'
    Add-Rule $st '^disk$' 7 'Bad block on disk' '' 2
    Add-Rule $st '^disk$' 11 'Disk controller error' '' 2
    Add-Rule $st '^disk$' 15 'Disk not ready'
    Add-Rule $st '^disk$' 51 'Paging I/O error'
    Add-Rule $st '^disk$' 52 'Disk failure predicted' '' 1
    Add-Rule $st '^disk$' 153 'Disk I/O retried'
    Add-Rule $st '.' 129 'Storage reset (I/O timeout)'
    Add-Rule $st 'Ntfs' 55 'File system corruption' '' 2
    Add-Rule $st 'Ntfs' 137 'NTFS transaction error'
    Add-Rule $st 'Ntfs' 140 'Failed to flush data (delayed write)' '' 2
    Add-Rule $st '.' @(50, 57) 'Delayed write failed' '' 2
    Add-Rule $st 'volsnap' @(25, 33, 36) 'Shadow copies deleted'
    Add-Rule $st 'mpio|msdsm' @(16, 17, 20, 32, 46) 'MPIO path event'
    Add-Rule $st 'iScsiPrt' @(1, 7, 20, 39, 129) 'iSCSI connection problem'

    $na = 'Network / AD / Auth'
    Add-Rule $na 'NETLOGON' 5719 'No domain controller available'
    Add-Rule $na 'NETLOGON' 5805 'Session setup failed'
    Add-Rule $na 'Time-Service|W32Time' @(36, 129, 134, 142) 'Time synchronisation problem'
    Add-Rule $na 'Tcpip' 4227 'TCP/IP port exhaustion' '' 2
    Add-Rule $na 'Tcpip' 4199 'IP address conflict' '' 2
    Add-Rule $na 'DNS-Client' 1014 'DNS name resolution timeout'
    Add-Rule $na 'Schannel' @(36870, 36871, 36874, 36887, 36888) 'TLS / Schannel error'
    Add-Rule $na 'LsaSrv' @(40960, 40961) 'Authentication failure (LSA)'
    Add-Rule $na 'Kerberos' 4 'Kerberos ticket problem (duplicate SPN?)'

    $rs = 'Resources / Perf'
    Add-Rule $rs 'Resource-Exhaustion-Detector' 2004 'Low virtual memory' '' 2
    Add-Rule $rs '^Srv$' @(2019, 2020) 'Kernel pool exhausted' '' 2

    $cl = 'Cluster'; $fc = 'FailoverClustering'
    Add-Rule $cl $fc 1069 'Cluster resource failed'
    Add-Rule $cl $fc 1135 'Node removed from cluster membership' 'Cluster' 1
    Add-Rule $cl $fc 1177 'Cluster quorum lost' 'Cluster' 1
    Add-Rule $cl $fc 1146 'Resource host (RHS) crashed'
    Add-Rule $cl $fc 1205 'Cluster role failed to come online'
    Add-Rule $cl $fc 1254 'Role exceeded failover threshold'
    Add-Rule $cl $fc 1230 'Resource call timed out (deadlock)'
    Add-Rule $cl $fc @(1126, 1127, 1129, 1130) 'Cluster network problem'
    Add-Rule $cl $fc 1196 'Cluster DNS registration failed'
    Add-Rule $cl $fc @(1557, 1558) 'Quorum disk / witness problem'
    Add-Rule $cl $fc 1561 'Cluster could not start - no quorum' 'Cluster' 1
    Add-Rule $cl $fc 1564 'File share witness unreachable'
    Add-Rule $cl $fc 1573 'Node could not form cluster (no quorum)'
    Add-Rule $cl $fc 5120 'CSV paused / no longer available' 'Cluster'
    Add-Rule $cl $fc 5121 'CSV in redirected access'
    Add-Rule $cl $fc 5142 'CSV no longer accessible'
    Add-Rule $cl $fc 1641 'Cluster role moved' 'Cluster'
    Add-Rule $cl $fc 1153 'Failover attempted' 'Cluster'
    Add-Rule $cl $fc 1201 'Cluster role online'
    Add-Rule $cl $fc 1204 'Cluster role offline'
    Add-Rule $cl $fc 1200 'Bringing cluster role online'
    Add-Rule $cl $fc 1203 'Taking cluster role offline'

    $sq = 'SQL Server'; $ms = '^(MSSQL|SQL Server)'
    Add-Rule $sq $ms 17126 'SQL Server ready for connections' 'SQL'
    Add-Rule $sq $ms 17147 'SQL Server stopping (system shutdown)' 'SQL'
    Add-Rule $sq $ms 17148 'SQL Server stopping (service control)' 'SQL'
    Add-Rule $sq $ms 17137 'Starting up database'
    Add-Rule $sq $ms 18456 'Login failed' '' 3
    Add-Rule $sq $ms 18452 'Login failed (untrusted domain)' '' 3
    Add-Rule $sq $ms @(17806, 17836) 'Login handshake / SSPI failure' '' 3
    Add-Rule $sq $ms 17809 'Max user connections reached' '' 2
    Add-Rule $sq $ms 833 'Slow I/O (> 15 seconds)' '' 3
    Add-Rule $sq $ms 823 'OS I/O error' '' 1
    Add-Rule $sq $ms 824 'Logical consistency I/O error (corruption)' '' 1
    Add-Rule $sq $ms 825 'Read retry required' '' 2
    Add-Rule $sq $ms 9002 'Transaction log full' '' 2
    Add-Rule $sq $ms 9001 'Transaction log not available' '' 2
    Add-Rule $sq $ms 1105 'Filegroup full' '' 2
    Add-Rule $sq $ms 701 'Insufficient system memory' '' 2
    Add-Rule $sq $ms 17883 'Non-yielding worker' '' 2
    Add-Rule $sq $ms @(17884, 17888) 'Deadlocked schedulers' '' 1
    Add-Rule $sq $ms 17890 'SQL memory paged out' '' 3
    Add-Rule $sq $ms 17053 'Operating system error' '' 2
    Add-Rule $sq $ms 3449 'SQL shutting down to recover' '' 1
    Add-Rule $sq $ms 3041 'Backup failed' '' 2
    Add-Rule $sq $ms 18210 'Backup device failure' '' 2
    Add-Rule $sq $ms @(5144, 5145) 'File autogrow cancelled / slow' '' 3
    Add-Rule $sq $ms 1205 'Deadlock' '' 3
    Add-Rule $sq $ms 1480 'AG database changing role' 'AG'
    Add-Rule $sq $ms 19406 'AG replica state changed' 'AG'
    Add-Rule $sq $ms 19407 'AG lease expired' 'AG' 2
    Add-Rule $sq $ms 35264 'AG data movement suspended' '' 3
    Add-Rule $sq $ms 35265 'AG data movement resumed'
    Add-Rule $sq '^(SQLAgent|SQLSERVERAGENT)' 208 'SQL Agent job failed' '' 2

    $se = 'Security'; $sa = 'Security-Auditing|Eventlog'
    Add-Rule $se $sa 1102 'Security audit log cleared' 'Security' 2
    Add-Rule $se $sa 4625 'Failed logon' '' 3
    Add-Rule $se $sa 4740 'Account locked out' '' 3
    Add-Rule $se $sa 4771 'Kerberos pre-authentication failed' '' 3
    Add-Rule $se $sa 4719 'Audit policy changed' '' 3

    # Informational events worth collecting regardless of level - scoped to their provider, as IDs are reused by other providers
    $systemKeyEvents = [ordered]@{
        'EventLog' = @(6005, 6006, 6008, 6009)
        'Microsoft-Windows-Kernel-Power' = @(41, 109)
        'User32' = @(1074, 1076)
        'Microsoft-Windows-Kernel-General' = @(12, 13)
        'Microsoft-Windows-WER-SystemErrorReporting|BugCheck' = @(1001)
        'Service Control Manager' = @(7036, 7040, 7045)
        'Microsoft-Windows-WindowsUpdateClient' = @(19, 43)
    }
    $appKeyEvents = [ordered]@{
        'MsiInstaller' = @(1033, 1034, 11707, 11724)
        'Windows Error Reporting' = @(1001)
    }
    $sqlKeyIds     = @(17126, 17147, 17148, 17137, 18456, 18452, 17806, 17836, 17809, 833, 823, 824, 825, 9002, 9001, 1105, 701,
                       17883, 17884, 17888, 17890, 17053, 3449, 3041, 18210, 5144, 5145, 1205, 1480, 19406, 19407, 35264, 35265, 208)
    $clusterKeyIds = @(1069, 1135, 1146, 1153, 1177, 1200, 1201, 1202, 1203, 1204, 1205, 1230, 1254, 1557, 1558, 1561, 1573,
                       1626, 1641, 1650, 1726, 1794, 5120, 5121, 5142)
    $securityIds   = @(1102, 4625, 4740, 4771, 4719)
    $opsMgrIds     = @(1102, 1103, 4502, 4506, 20000, 20020, 20022, 21016, 21034, 26004)

    #---- Event record conversion -------------------------------------------------------------
    function Add-EventRecords($Events) {
        $added = 0
        foreach ($e in $Events) {
            if ($null -eq $e) { continue }
            $k = "$($e.LogName)|$($e.RecordId)"
            if ($seen.ContainsKey($k)) { continue }
            $seen[$k] = $true
            $msg = $null
            try { $msg = $e.Message } catch { }
            if ([string]::IsNullOrWhiteSpace($msg)) {
                $msg = '(Message text unavailable - provider not registered on the collecting machine) ' + (($e.Properties | ForEach-Object { $_.Value }) -join ' | ')
            }
            if ($e.ProviderName -eq 'Service Control Manager' -and ($e.Id -eq 7036 -or $e.Id -eq 7040) -and $msg -notmatch $serviceInterestRx) { continue }
            $msg = $msg.Trim()
            if ($msg.Length -gt 8000) { $msg = $msg.Substring(0, 8000) + ' ...[truncated]' }

            $lvl = [int]$e.Level
            if ($lvl -lt 1 -or $lvl -gt 4) { $lvl = 4 }
            $lvlName = $levelNames[$lvl]
            if ($e.LogName -eq 'Security' -and $null -ne $e.Keywords -and (([long]$e.Keywords -band 0x10000000000000L) -ne 0)) { $lvl = 3; $lvlName = 'Audit Failure' }

            $cat = Get-EventCategory $e.LogName $e.ProviderName
            $tag = ''; $marker = ''
            $rule = Resolve-Rule $cat $e.Id $e.ProviderName
            if ($rule) {
                $tag = $rule.Tag; $marker = $rule.Marker
                if ($rule.Level -gt 0 -and $lvl -gt $rule.Level) { $lvl = $rule.Level; $lvlName = $levelNames[$lvl] }
            }
            $results.Add([pscustomobject]@{
                Time = $e.TimeCreated; Computer = $machine; Level = $lvlName; LevelNum = $lvl; Category = $cat
                Tag = $tag; Marker = $marker; Id = [int]$e.Id; Provider = [string]$e.ProviderName; LogName = [string]$e.LogName
                RecordId = [long]$e.RecordId; Source = 'Event Log'; Message = $msg
            })
            $added++
        }
        return $added
    }

    function Get-LogInfo([string]$LogName) {
        $p = @{ ListLog = $LogName; ErrorAction = 'Stop' }
        if (-not $isLocal) { $p.ComputerName = $Computer }
        try { return Get-WinEvent @p } catch { return $null }
    }

    function Split-Chunks($Items, [int]$Size) {
        $chunks = New-Object System.Collections.Generic.List[object]
        $arr = @($Items)
        for ($i = 0; $i -lt $arr.Count; $i += $Size) { $chunks.Add(@($arr[$i..([math]::Min($i + $Size, $arr.Count) - 1)])) }
        return , $chunks
    }

    # Runs XPath queries against one log. Levels and IDs are OR'ed; providers (if any) restrict both.
    function Invoke-LogQuery {
        param([string]$LogName, [string]$Label, [int[]]$Levels, [int[]]$Ids, [string[]]$Providers, $KeyEvents)
        if (-not $Label) { $Label = $LogName }
        Write-Step $Label
        $info = Get-LogInfo $LogName
        if (-not $info) { Write-RunLog "$Label : log not present - skipped"; return $false }
        if (-not $info.IsEnabled) { Write-RunLog "$Label : log is disabled - skipped"; return $true }

        $selectors = New-Object System.Collections.Generic.List[string]
        if ($Levels) { $selectors.Add('(' + (($Levels | ForEach-Object { "Level=$_" }) -join ' or ') + ')') }
        if ($Ids) { foreach ($c in (Split-Chunks $Ids 15)) { $selectors.Add('(' + (($c | ForEach-Object { "EventID=$_" }) -join ' or ') + ')') } }
        if ($KeyEvents) {
            # key = provider name(s) separated by '|', value = event IDs
            foreach ($k in $KeyEvents.Keys) {
                $names = ($k -split '\|') | ForEach-Object { "@Name='$_'" }
                $selectors.Add('(Provider[' + ($names -join ' or ') + '] and (' + (($KeyEvents[$k] | ForEach-Object { "EventID=$_" }) -join ' or ') + '))')
            }
        }
        $providerClauses = New-Object System.Collections.Generic.List[string]
        if ($Providers) {
            foreach ($c in (Split-Chunks $Providers 10)) {
                $names = $c | ForEach-Object { if ($_ -match "'") { "@Name=`"$_`"" } else { "@Name='$_'" } }
                $providerClauses.Add('Provider[' + ($names -join ' or ') + ']')
            }
        } else { $providerClauses.Add('') }

        $total = 0; $capped = $false
        foreach ($pc in $providerClauses) {
            foreach ($sel in $selectors) {
                $conds = @("TimeCreated[@SystemTime>='$startUtc' and @SystemTime<='$endUtc']", $sel)
                if ($pc) { $conds += $pc }
                $q = @{ LogName = $LogName; FilterXPath = ('*[System[' + ($conds -join ' and ') + ']]'); MaxEvents = $MaxEvents; ErrorAction = 'Stop' }
                if (-not $isLocal) { $q.ComputerName = $Computer }
                $found = @()
                try { $found = @(Get-WinEvent @q) }
                catch {
                    if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { Write-RunLog "$Label : query failed - $($_.Exception.Message)" }
                }
                if ($found.Count -ge $MaxEvents) { $capped = $true }
                $total += Add-EventRecords $found
            }
        }
        $note = if ($capped) { " (WARNING: hit MaxEventsPerQuery=$MaxEvents - older events in the window may be missing)" } else { '' }
        Write-RunLog "$Label : $total events$note"
        return $true
    }

    #---- SQL Server ERRORLOG / SQL Agent log files -------------------------------------------
    function ConvertTo-AccessPath([string]$Path) {
        if (-not $Path) { return $null }
        if ($isLocal -or $Path.StartsWith('\\')) { return $Path }
        if ($Path -match '^([A-Za-z]):\\(.*)$') { return "\\$Computer\$($Matches[1])`$\$($Matches[2])" }
        return $Path
    }

    function Get-SqlLogLocations {
        $found = New-Object System.Collections.Generic.List[object]
        try {
            if ($isLocal) { $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64) }
            else { $hive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $Computer, [Microsoft.Win32.RegistryView]::Registry64) }
        } catch { Write-RunLog "SQL log files: cannot open registry ($($_.Exception.Message)) - is the Remote Registry service running?"; return , $found }
        $root = 'SOFTWARE\Microsoft\Microsoft SQL Server'
        $openKey = { param($Path) try { $hive.OpenSubKey($Path) } catch { $null } }
        $names = & $openKey "$root\Instance Names\SQL"
        if (-not $names) { Write-RunLog 'SQL log files: no SQL Server instances registered'; $hive.Close(); return , $found }
        foreach ($inst in $names.GetValueNames()) {
            $id = [string]$names.GetValue($inst)
            $errDir = $null; $agentFile = $null
            $params = & $openKey "$root\$id\MSSQLServer\Parameters"
            if ($params) { foreach ($v in $params.GetValueNames()) { $val = [string]$params.GetValue($v); if ($val -like '-e*') { $errDir = Split-Path $val.Substring(2) } } }
            if (-not $errDir) {
                # Parameters key is often admin-only; fall back to the default <instance root>\Log folder
                $setup = & $openKey "$root\$id\Setup"
                if ($setup -and $setup.GetValue('SQLDataRoot')) { $errDir = Join-Path ([string]$setup.GetValue('SQLDataRoot')) 'Log' }
                if (-not $params) { Write-RunLog "SQL log files ($inst): startup parameters not readable (run as Administrator?) - assuming $errDir" }
            }
            $agent = & $openKey "$root\$id\SQLServerAgent"
            if ($agent) { $agentFile = [string]$agent.GetValue('ErrorLogFile') }
            if (-not $agentFile -and $errDir) { $agentFile = Join-Path $errDir 'SQLAGENT.OUT' }
            $found.Add([pscustomobject]@{ Instance = $inst; ErrorLogDir = (ConvertTo-AccessPath $errDir); AgentLogDir = (ConvertTo-AccessPath $(if ($agentFile) { Split-Path $agentFile })) })
        }
        $hive.Close()
        return , $found
    }

    function Read-LogLines([string]$Path) {
        $lines = New-Object System.Collections.Generic.List[string]
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::Default, $true)
        try { while ($null -ne ($line = $sr.ReadLine())) { $lines.Add($line) } } finally { $sr.Dispose() }
        return , $lines
    }

    $startStr = $Start.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
    $endStr   = $End.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
    $sqlLogExcludeRx = '(?i)(found 0 errors|0 errors and 0|without errors|no user action is required|This is an informational message|error log has been reinitialized|Logging SQL Server messages in file|Registry startup parameters|Error: 0,|CHECKDB .* finished without|Recovery completed|Setting database option|Configuration option|Login succeeded|successfully|Error reporting|Server process ID|Authentication mode|SQL Server is now ready)'
    $sqlLogSevereRx  = '(?i)(stack dump|Stack Signature|access violation|corrupt|non-yielding|deadlocked schedulers|severe error|assertion|latch timeout|exception .* address)'
    $sqlLogProblemRx = '(?i)\b(error|errors|fail|failed|failure|timed? ?out|timeout|insufficient|terminat\w*|unable|cannot|could not|exception|paged out|unloaded|denied|lease|suspended|not synchroniz\w*|disconnected|taking longer than 15 seconds)\b'

    function Import-SqlErrorLog([string]$Path, [string]$Instance, $EventLogKeys) {
        $lines = Read-LogLines $Path
        $entries = New-Object System.Collections.Generic.List[object]
        $cur = $null
        foreach ($line in $lines) {
            if ($line.Length -ge 23 -and $line[4] -eq '-' -and $line[10] -eq ' ' -and $line[19] -eq '.') {
                $ts19 = $line.Substring(0, 19)
                if ([string]::CompareOrdinal($ts19, $startStr) -lt 0 -or [string]::CompareOrdinal($ts19, $endStr) -gt 0) { $cur = $null; continue }
                if ($line -match '^(\S+ \S+)\s+(\S+)\s+(.*)$') {
                    $cur = @{ Time = $Matches[1]; Spid = $Matches[2]; Text = $Matches[3] }
                    $entries.Add($cur)
                }
            } elseif ($null -ne $cur -and $line.Trim()) { $cur.Text += "`n" + $line.TrimEnd() }
        }
        $provider = if ($Instance -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { "MSSQL`$$Instance" }
        $added = 0; $dupes = 0; $i = 0
        while ($i -lt $entries.Count) {
            $en = $entries[$i]; $i++
            $text = $en.Text; $errNum = 0; $sev = -1
            if ($text -match '^Error: (\d+), Severity: (\d+), State: (\d+)') {
                $errNum = [int]$Matches[1]; $sev = [int]$Matches[2]; $state = $Matches[3]
                if ($i -lt $entries.Count -and $entries[$i].Spid -eq $en.Spid -and $entries[$i].Time.Substring(0, 19) -eq $en.Time.Substring(0, 19)) {
                    $text = $entries[$i].Text + "  [Error $errNum, Severity $sev, State $state]"; $i++
                }
            }
            $time = [datetime]::ParseExact($en.Time, 'yyyy-MM-dd HH:mm:ss.ff', [Globalization.CultureInfo]::InvariantCulture)
            if ($errNum -gt 0 -and $EventLogKeys.ContainsKey("$errNum|$($time.ToString('yyyyMMddHHmmss'))")) { $dupes++; continue }

            if ($sev -ge 0) { $lvl = if ($sev -ge 20) { 1 } elseif ($sev -ge 17) { 2 } elseif ($sev -ge 11) { 3 } else { 4 } }
            elseif ($text -match $sqlLogExcludeRx) { $lvl = 4 }
            elseif ($text -match $sqlLogSevereRx) { $lvl = 2 }
            elseif ($text -match $sqlLogProblemRx) { $lvl = 3 }
            else { $lvl = 4 }
            if ($text -match '^(Stack Signature|\* \*{5,}|BEGIN STACK DUMP)') { $lvl = 1 }

            $tag = ''; $marker = ''
            if ($text -match '^SQL Server is starting at') { $tag = 'SQL Server starting'; $marker = 'SQL' }
            elseif ($text -match 'SQL Server is now ready for client connections') { $tag = 'SQL Server ready for connections'; $marker = 'SQL' }
            elseif ($text -match '^(SQL Server is terminating|SQL Server shutdown (has been initiated|due to)|Server shut down by)') { $tag = 'SQL Server stopping'; $marker = 'SQL'; $lvl = 4 }
            elseif ($text -match "The state of the local availability replica in availability group '([^']+)' has changed from '([^']+)' to '([^']+)'") { $tag = "AG $($Matches[1]): $($Matches[2]) -> $($Matches[3])"; $marker = 'AG' }
            elseif ($text -match 'is changing roles from') { $tag = 'AG database changing role'; $marker = 'AG' }
            elseif ($text -match 'appears to be non-yielding') { $tag = 'Non-yielding scheduler'; if ($lvl -gt 2) { $lvl = 2 } }
            elseif ($text -match 'I/O requests taking longer than 15 seconds') { $tag = 'Slow I/O (> 15 seconds)'; if ($lvl -gt 3) { $lvl = 3 } }
            elseif ($text -match 'A significant part of sql server process memory has been paged out') { $tag = 'SQL memory paged out'; if ($lvl -gt 3) { $lvl = 3 } }
            elseif ($errNum -gt 0) {
                $rule = Resolve-Rule 'SQL Server' $errNum $provider
                if ($rule) { $tag = $rule.Tag; $marker = $rule.Marker; if ($rule.Level -gt 0 -and $lvl -gt $rule.Level) { $lvl = $rule.Level } }
            }
            if ($lvl -eq 4 -and -not $marker -and -not $IncludeInfo) { continue }
            if ($text.Length -gt 8000) { $text = $text.Substring(0, 8000) + ' ...[truncated]' }
            $results.Add([pscustomobject]@{
                Time = $time; Computer = $machine; Level = $levelNames[$lvl]; LevelNum = $lvl; Category = 'SQL ERRORLOG'
                Tag = $tag; Marker = $marker; Id = $errNum; Provider = $provider; LogName = "ERRORLOG ($Instance) $(Split-Path $Path -Leaf)"
                RecordId = [long]0; Source = 'SQL ERRORLOG'; Message = "[$($en.Spid)] $text"
            })
            $added++
        }
        return @($added, $dupes)
    }

    function Import-SqlAgentLog([string]$Path, [string]$Instance) {
        $lines = Read-LogLines $Path
        $provider = if ($Instance -eq 'MSSQLSERVER') { 'SQLSERVERAGENT' } else { "SQLAgent`$$Instance" }
        $added = 0; $cur = $null
        foreach ($line in $lines) {
            if ($line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.) \[(\d+)\] (.*)$') {
                $cur = $null
                $ts = $Matches[1]
                if ([string]::CompareOrdinal($ts, $startStr) -lt 0 -or [string]::CompareOrdinal($ts, $endStr) -gt 0) { continue }
                $lvl = switch ($Matches[2]) { '!' { 2 } '?' { 3 } default { 4 } }
                if ($lvl -eq 4 -and -not $IncludeInfo) { continue }
                $cur = [pscustomobject]@{
                    Time = [datetime]::ParseExact($ts, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
                    Computer = $machine; Level = $levelNames[$lvl]; LevelNum = $lvl; Category = 'SQL Agent'; Tag = ''; Marker = ''
                    Id = [int]$Matches[3]; Provider = $provider; LogName = "SQL Agent log ($Instance) $(Split-Path $Path -Leaf)"
                    RecordId = [long]0; Source = 'SQL Agent log'; Message = $Matches[4]
                }
                $results.Add($cur); $added++
            } elseif ($null -ne $cur -and $line.Trim()) { $cur.Message += "`n" + $line.TrimEnd() }
        }
        return $added
    }

    function Import-SqlLogFiles {
        Write-Step 'SQL Server ERRORLOG / Agent log files'
        # SQL writes most errors to both the Application log and ERRORLOG - skip ERRORLOG copies of events we already have
        $eventLogKeys = @{}
        foreach ($r in $results) {
            if ($r.Category -eq 'SQL Server') { foreach ($d in -1, 0, 1) { $eventLogKeys["$($r.Id)|$($r.Time.AddSeconds($d).ToString('yyyyMMddHHmmss'))"] = $true } }
        }
        foreach ($loc in (Get-SqlLogLocations)) {
            if ($loc.ErrorLogDir -and (Test-Path -LiteralPath $loc.ErrorLogDir)) {
                $files = Get-ChildItem -LiteralPath $loc.ErrorLogDir -Filter 'ERRORLOG*' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^ERRORLOG(\.\d+)?$' -and $_.LastWriteTime -ge $Start } | Sort-Object LastWriteTime
                $n = 0; $d = 0
                foreach ($f in $files) {
                    try { $r = Import-SqlErrorLog $f.FullName $loc.Instance $eventLogKeys; $n += $r[0]; $d += $r[1] }
                    catch { Write-RunLog "ERRORLOG ($($loc.Instance)) $($f.Name): $($_.Exception.Message)" }
                }
                Write-RunLog "ERRORLOG ($($loc.Instance)): $n entries from $(@($files).Count) file(s), $d duplicates of Application-log events skipped"
            } else { Write-RunLog "ERRORLOG ($($loc.Instance)): folder '$($loc.ErrorLogDir)' not accessible (FCI passive node, permissions or admin share?)" }

            if ($loc.AgentLogDir -and (Test-Path -LiteralPath $loc.AgentLogDir)) {
                $files = Get-ChildItem -LiteralPath $loc.AgentLogDir -Filter 'SQLAGENT.*' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^SQLAGENT\.(OUT|\d+)$' -and $_.LastWriteTime -ge $Start } | Sort-Object LastWriteTime
                $n = 0
                foreach ($f in $files) {
                    try { $n += Import-SqlAgentLog $f.FullName $loc.Instance } catch { Write-RunLog "SQL Agent log ($($loc.Instance)) $($f.Name): $($_.Exception.Message)" }
                }
                Write-RunLog "SQL Agent log ($($loc.Instance)): $n entries from $(@($files).Count) file(s)"
            } elseif ($loc.AgentLogDir) { Write-RunLog "SQL Agent log ($($loc.Instance)): folder '$($loc.AgentLogDir)' not accessible" }
        }
    }

    #---- Run the selected sources ------------------------------------------------------------
    Write-RunLog ("Collecting {0:yyyy-MM-dd HH:mm:ss} -> {1:yyyy-MM-dd HH:mm:ss}; sources: {2}" -f $Start, $End, ($Sources -join ', '))
    if (-not $isLocal -and -not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-RunLog 'WARNING: host did not answer ping - trying anyway'
    }
    if ('System' -in $Sources) { [void](Invoke-LogQuery -LogName 'System' -Levels $problemLevels -KeyEvents $systemKeyEvents) }
    if ('Application' -in $Sources) { [void](Invoke-LogQuery -LogName 'Application' -Levels $problemLevels -KeyEvents $appKeyEvents) }
    if ('SQL' -in $Sources) {
        Write-Step 'SQL Server providers'
        $app = Get-LogInfo 'Application'
        $sqlProviders = @(if ($app) { $app.ProviderNames | Where-Object { $_ -match $sqlProviderRx } })
        if ($sqlProviders.Count -eq 0) { Write-RunLog 'SQL Server: no SQL providers registered in the Application log' }
        else { [void](Invoke-LogQuery -LogName 'Application' -Label "SQL Server events ($($sqlProviders.Count) providers)" -Levels $problemLevels -Ids $sqlKeyIds -Providers $sqlProviders) }
    }
    if ('SQLLogs' -in $Sources) { Import-SqlLogFiles }
    if ('Cluster' -in $Sources) {
        if (Invoke-LogQuery -LogName 'Microsoft-Windows-FailoverClustering/Operational' -Label 'Cluster Operational' -Levels $problemLevels -Ids $clusterKeyIds) {
            [void](Invoke-LogQuery -LogName 'System' -Label 'Cluster events in System log' -Levels @(1, 2, 3, 4) -Providers @('Microsoft-Windows-FailoverClustering'))
            [void](Invoke-LogQuery -LogName 'Microsoft-Windows-FailoverClustering-Manager/Admin' -Label 'Cluster Manager' -Levels $problemLevels)
            [void](Invoke-LogQuery -LogName 'Microsoft-Windows-FailoverClustering-CsvFs/Operational' -Label 'Cluster CSV' -Levels $problemLevels)
            [void](Invoke-LogQuery -LogName 'Microsoft-Windows-ClusterAwareUpdating/Admin' -Label 'Cluster-Aware Updating' -Levels @(1, 2, 3, 4))
            Write-RunLog 'Cluster: for deeper analysis also run Get-ClusterLog -TimeSpan <minutes> on a node'
        }
    }
    if ('HyperV' -in $Sources) {
        foreach ($l in 'Microsoft-Windows-Hyper-V-VMMS-Admin', 'Microsoft-Windows-Hyper-V-Worker-Admin', 'Microsoft-Windows-Hyper-V-High-Availability-Admin') {
            [void](Invoke-LogQuery -LogName $l -Levels $problemLevels)
        }
    }
    if ('Security' -in $Sources) { [void](Invoke-LogQuery -LogName 'Security' -Ids $securityIds) }
    if ('OpsMgr' -in $Sources) { [void](Invoke-LogQuery -LogName 'Operations Manager' -Levels @(1, 2) -Ids $opsMgrIds) }

    Write-RunLog "Done - $($results.Count) events"
    Write-Progress -Activity "Collecting from $machine" -Completed
    [pscustomobject]@{ Computer = $machine; Events = $results.ToArray(); Log = $runLog.ToArray() }
}
#endregion

#region ===================== CSV / HTML export =====================
$script:ExportColumns = 'Time', 'Computer', 'Level', 'Category', 'Tag', 'Id', 'Provider', 'LogName', 'Source', 'Message'

function Export-EventCsv($Rows, [string]$Path) {
    $Rows | Select-Object @{ n = 'Time'; e = { ([datetime]$_.Time).ToString('yyyy-MM-dd HH:mm:ss.fff') } }, Computer, Level, Category, Tag, Id, Provider, LogName, Source, Message |
        Export-Csv -Path $Path -NoTypeInformation -UseCulture -Encoding UTF8
}

#---- Session files: everything needed to review a collection on another machine ----
$script:SessionFormat = 'WinEventLogInvestigator.Session'
$script:SessionColumns = 'Time', 'Computer', 'Level', 'LevelNum', 'Category', 'Tag', 'Marker', 'Id', 'Provider', 'LogName', 'Source', 'RecordId', 'Message'

function ConvertTo-JsonText($Value) {
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [datetime]) { return ConvertTo-JsString $Value.ToString('yyyy-MM-ddTHH:mm:ss.fff', $inv) }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return [string]::Format($inv, '{0}', $Value) }
    if ($Value -is [string]) { return ConvertTo-JsString $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        return '{' + (($Value.Keys | ForEach-Object { (ConvertTo-JsString ([string]$_)) + ':' + (ConvertTo-JsonText $Value[$_]) }) -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) { return '[' + ((@($Value) | ForEach-Object { ConvertTo-JsonText $_ }) -join ',') + ']' }
    return ConvertTo-JsString ([string]$Value)
}

function Export-InvestigationSession {
    param($Rows, [string]$Path, $Collection, $View, [string[]]$RunLog)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $header = [ordered]@{
        format = $script:SessionFormat; version = 1
        exportedAt = (Get-Date); exportedFrom = $env:COMPUTERNAME; exportedBy = "$env:USERDOMAIN\$env:USERNAME"
        collection = $Collection; view = $View; runLog = @($RunLog); eventColumns = $script:SessionColumns
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{')
    foreach ($k in $header.Keys) { [void]$sb.Append((ConvertTo-JsString $k)).Append(':').Append((ConvertTo-JsonText $header[$k])).Append(",`n") }
    [void]$sb.Append('"events":[')
    $first = $true
    foreach ($r in $Rows) {
        if (-not $first) { [void]$sb.Append(",`n") }; $first = $false
        [void]$sb.Append('[').Append((ConvertTo-JsString ([datetime]$r.Time).ToString('yyyy-MM-ddTHH:mm:ss.fff', $inv))).Append(',')
        [void]$sb.Append((ConvertTo-JsString $r.Computer)).Append(',').Append((ConvertTo-JsString $r.Level)).Append(',').Append([int]$r.LevelNum).Append(',')
        [void]$sb.Append((ConvertTo-JsString $r.Category)).Append(',').Append((ConvertTo-JsString $r.Tag)).Append(',').Append((ConvertTo-JsString $r.Marker)).Append(',')
        [void]$sb.Append([int]$r.Id).Append(',').Append((ConvertTo-JsString $r.Provider)).Append(',').Append((ConvertTo-JsString $r.LogName)).Append(',')
        [void]$sb.Append((ConvertTo-JsString $r.Source)).Append(',').Append([long]$r.RecordId).Append(',').Append((ConvertTo-JsString ([string]$r.Message))).Append(']')
    }
    [void]$sb.Append("]}`n")
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-JsonValue($Object, [string]$Name, $Default = $null) {
    # JavaScriptSerializer (Windows PowerShell) returns Dictionary<string,object>, ConvertFrom-Json -AsHashtable (PowerShell 7) a Hashtable
    if ($Object -is [System.Collections.IDictionary] -and $Object.Keys -contains $Name -and $null -ne $Object[$Name]) { return $Object[$Name] }
    return $Default
}

# Session times are stored as the source server's local wall-clock time ('yyyy-MM-ddTHH:mm:ss.fff').
# PowerShell 7's ConvertFrom-Json already turns them into DateTime values; Windows PowerShell leaves strings.
function ConvertFrom-SessionDate($Value) {
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [datetime]) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Unspecified) }
    return [datetime]::ParseExact([string]$Value, [string[]]@('yyyy-MM-ddTHH:mm:ss.fff', 'yyyy-MM-ddTHH:mm:ss', 'o'), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None)
}

function Read-InvestigationSession([string]$Path) {
    $text = [System.IO.File]::ReadAllText($Path)
    if ($PSVersionTable.PSEdition -eq 'Core') { $doc = ConvertFrom-Json -InputObject $text -AsHashtable -Depth 20 }
    else {
        Add-Type -AssemblyName System.Web.Extensions
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue; $ser.RecursionLimit = 100
        $doc = $ser.DeserializeObject($text)
    }
    if ((Get-JsonValue $doc 'format') -ne $script:SessionFormat) { throw "'$Path' is not a $script:SessionFormat file." }
    $cols = @(Get-JsonValue $doc 'eventColumns' @())
    $ix = @{}; for ($i = 0; $i -lt $cols.Count; $i++) { $ix[[string]$cols[$i]] = $i }
    $missing = @($script:SessionColumns | Where-Object { -not $ix.ContainsKey($_) })
    if ($missing) { throw "'$Path' is missing event columns: $($missing -join ', ')" }
    $iT = $ix.Time; $iC = $ix.Computer; $iL = $ix.Level; $iN = $ix.LevelNum; $iCat = $ix.Category; $iTag = $ix.Tag; $iMk = $ix.Marker
    $iId = $ix.Id; $iP = $ix.Provider; $iLog = $ix.LogName; $iSrc = $ix.Source; $iRec = $ix.RecordId; $iMsg = $ix.Message
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $events = New-Object System.Collections.Generic.List[object]
    foreach ($a in @(Get-JsonValue $doc 'events' @())) {
        $events.Add([pscustomobject]@{
            Time = $(if ($a[$iT] -is [string]) { [datetime]::ParseExact($a[$iT], 'yyyy-MM-ddTHH:mm:ss.fff', $inv) } else { ConvertFrom-SessionDate $a[$iT] }); Computer = [string]$a[$iC]; Level = [string]$a[$iL]
            LevelNum = [int]$a[$iN]; Category = [string]$a[$iCat]; Tag = [string]$a[$iTag]; Marker = [string]$a[$iMk]; Id = [int]$a[$iId]
            Provider = [string]$a[$iP]; LogName = [string]$a[$iLog]; Source = [string]$a[$iSrc]; RecordId = [long]$a[$iRec]; Message = [string]$a[$iMsg]
        })
    }
    return @{ Path = $Path; Document = $doc; Events = $events }
}

function ConvertTo-JsString([string]$s) {
    if ($null -eq $s) { return '""' }
    $s = $s.Replace('\', '\\').Replace('"', '\"').Replace("`r", '').Replace("`n", '\n').Replace("`t", '\t').Replace('</', '<\/')
    return '"' + [regex]::Replace($s, '[\x00-\x1f]', '') + '"'
}

function New-HtmlReport {
    param($Rows, [string]$Path, [datetime]$Start, [datetime]$End, [string[]]$Computers, [string[]]$RunLog, [int]$MaxRows = 50000)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $list = @($Rows | Sort-Object { [datetime]$_.Time })
    if ($list.Count -gt $MaxRows) { $list = $list[($list.Count - $MaxRows)..($list.Count - 1)] }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"meta":{"start":').Append((ConvertTo-JsString $Start.ToString('yyyy-MM-ddTHH:mm:ss', $inv)))
    [void]$sb.Append(',"end":').Append((ConvertTo-JsString $End.ToString('yyyy-MM-ddTHH:mm:ss', $inv)))
    [void]$sb.Append(',"generated":').Append((ConvertTo-JsString (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', $inv)))
    [void]$sb.Append(',"computers":[').Append((($Computers | ForEach-Object { ConvertTo-JsString $_ }) -join ',')).Append(']},"ev":[')
    $first = $true
    foreach ($r in $list) {
        if (-not $first) { [void]$sb.Append(',') }; $first = $false
        $msg = [string]$r.Message; if ($msg.Length -gt 4000) { $msg = $msg.Substring(0, 4000) + ' ...' }
        [void]$sb.Append('[').Append((ConvertTo-JsString ([datetime]$r.Time).ToString('yyyy-MM-ddTHH:mm:ss.fff', $inv))).Append(',')
        [void]$sb.Append((ConvertTo-JsString $r.Computer)).Append(',').Append([int]$r.LevelNum).Append(',').Append((ConvertTo-JsString $r.Level)).Append(',')
        [void]$sb.Append((ConvertTo-JsString $r.Category)).Append(',').Append((ConvertTo-JsString $r.Tag)).Append(',').Append((ConvertTo-JsString $r.Marker)).Append(',')
        [void]$sb.Append([int]$r.Id).Append(',').Append((ConvertTo-JsString $r.Provider)).Append(',').Append((ConvertTo-JsString $r.LogName)).Append(',')
        [void]$sb.Append((ConvertTo-JsString $msg)).Append(']')
    }
    [void]$sb.Append('],"log":[').Append((($RunLog | ForEach-Object { ConvertTo-JsString $_ }) -join ',')).Append(']}')
    $title = 'Event Log Investigation - ' + ($Computers -join ', ')
    $html = $script:HtmlTemplate.Replace('__TITLE__', [System.Net.WebUtility]::HtmlEncode($title)).Replace('__DATA__', $sb.ToString())
    [System.IO.File]::WriteAllText($Path, $html, (New-Object System.Text.UTF8Encoding($false)))
}

$script:HtmlTemplate = @'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#1c1c1f;--panel:#26262b;--panel2:#303036;--fg:#e4e4e7;--muted:#9a9aa3;--grid:#3a3a41;--accent:#2f8cff;--c1:#e0457b;--c2:#f26b3a;--c3:#e8a317;--c4:#5b9fe3}
@media (prefers-color-scheme: light){:root{--bg:#f5f5f7;--panel:#fff;--panel2:#eef0f3;--fg:#1d1d1f;--muted:#6b6b74;--grid:#dcdce3;--accent:#0060df;--c3:#c98a00}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.45 "Segoe UI",system-ui,sans-serif}
header{padding:16px 20px 4px}h1{font-size:18px;margin:0 0 2px}.sub{color:var(--muted)}
.kpis{display:flex;gap:10px;flex-wrap:wrap;padding:10px 20px}
.kpi{background:var(--panel);border-radius:8px;padding:8px 14px;min-width:110px;border-left:4px solid var(--grid)}
.kpi b{display:block;font-size:20px;font-variant-numeric:tabular-nums}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;padding:8px 20px;position:sticky;top:0;background:var(--bg);z-index:3;border-bottom:1px solid var(--grid)}
.bar label{display:flex;gap:4px;align-items:center}
input,select,button{font:inherit;color:var(--fg);background:var(--panel);border:1px solid var(--grid);border-radius:6px;padding:4px 8px}
button{cursor:pointer}button:hover{border-color:var(--accent)}#q{min-width:220px}
.card{background:var(--panel);margin:12px 20px;border-radius:8px;padding:10px 12px}
.card h2{font-size:14px;margin:0 0 6px;display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}
.hint{color:var(--muted);font-size:12px;font-weight:normal}
#tl{width:100%;display:block;user-select:none;cursor:crosshair}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:4px 6px;border-bottom:1px solid var(--grid);vertical-align:top}
th{position:sticky;top:0;background:var(--panel2);white-space:nowrap;z-index:1}td.n{text-align:right;font-variant-numeric:tabular-nums}
td.msg{max-width:0;width:45%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}td.t{white-space:nowrap;font-variant-numeric:tabular-nums}
tbody tr.ev:hover,tbody tr.grp:hover{background:var(--panel2);cursor:pointer}
tr.detail pre{white-space:pre-wrap;word-break:break-word;margin:4px 0;font:12px/1.45 Consolas,monospace}
.l1{color:var(--c1)}.l2{color:var(--c2)}.l3{color:var(--c3)}.l4{color:var(--c4)}.lv{font-weight:600}
.scroll{max-height:70vh;overflow:auto}pre#log{white-space:pre-wrap;font:12px Consolas,monospace;color:var(--muted)}
svg text{fill:var(--muted);font:11px "Segoe UI",system-ui,sans-serif}
@media (max-width:700px){header,.kpis,.bar{padding-left:12px;padding-right:12px}.card{margin:10px 12px}#q{min-width:0;flex:1}}
</style></head><body>
<header><h1 id="title"></h1><div class="sub" id="sub"></div></header>
<div class="kpis" id="kpis"></div>
<div class="bar">
<label><input type="checkbox" data-l="1" checked><span class="l1 lv">Critical</span></label>
<label><input type="checkbox" data-l="2" checked><span class="l2 lv">Error</span></label>
<label><input type="checkbox" data-l="3" checked><span class="l3 lv">Warning</span></label>
<label><input type="checkbox" data-l="4" checked><span class="l4 lv">Info</span></label>
<select id="cat"></select><select id="comp"></select>
<label>Lanes <select id="lane"><option value="cat">Category</option><option value="c">Computer</option><option value="p">Provider</option></select></label>
<input id="q" type="search" placeholder="Search message, provider, tag, ID">
<button id="back">Zoom out</button><button id="reset">Reset</button><span class="hint" id="win"></span>
</div>
<div class="card"><h2>Timeline <span class="hint">Drag to zoom &middot; click a bar or dot to drill in &middot; right-click to zoom out &middot; dashed lines = reboots, SQL restarts, failovers</span></h2><svg id="tl"></svg></div>
<div class="card"><h2>Top issues <span class="hint">click a row to filter to it</span></h2><div class="scroll" style="max-height:40vh"><table id="top"></table></div></div>
<div class="card"><h2>Events <span class="hint" id="cnt"></span></h2><div class="scroll"><table id="evt"></table></div></div>
<div class="card"><details><summary>Collection log</summary><pre id="log"></pre></details></div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
const D=JSON.parse(document.getElementById('data').textContent);
const LV={1:'Critical',2:'Error',3:'Warning',4:'Information'};
const MK={Boot:'#9aa0a6',Shutdown:'#7d8288',Crash:'#ff4040',SQL:'#14b8a6',AG:'#38bdf8',Cluster:'#a78bfa',Security:'#fb923c',Update:'#65a30d'};
const css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const E=D.ev.map((r,i)=>({i,ts:r[0],t:Date.parse(r[0]),c:r[1],l:r[2],ln:r[3],cat:r[4],tag:r[5],mk:r[6],id:r[7],p:r[8],log:r[9],m:r[10],s:(r[10]+' '+r[8]+' '+r[5]+' '+r[7]+' '+r[1]).toLowerCase()}));
const full=[Date.parse(D.meta.start),Date.parse(D.meta.end)];
const S={lv:{1:1,2:1,3:1,4:1},cat:'',c:'',q:'',lane:'cat',w0:full[0],w1:full[1],stack:[],open:new Set()};
const STEPS=[10,30,60,120,300,600,900,1800,3600,7200,10800,21600,43200,86400,172800,604800];
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const p2=n=>String(n).padStart(2,'0');
const MON=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function fmt(t,mode){const d=new Date(t);const hm=p2(d.getHours())+':'+p2(d.getMinutes());
 if(mode==='d')return p2(d.getDate())+' '+MON[d.getMonth()];if(mode==='hm')return hm;if(mode==='hms')return hm+':'+p2(d.getSeconds());
 if(mode==='dhm')return p2(d.getDate())+' '+MON[d.getMonth()]+' '+hm;return d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate())+' '+hm+':'+p2(d.getSeconds());}
function laneOf(e){return S.lane==='c'?e.c:S.lane==='p'?e.p:e.cat;}
function base(){const q=S.q.toLowerCase();return E.filter(e=>S.lv[e.l]&&(!S.cat||e.cat===S.cat)&&(!S.c||e.c===S.c)&&(!q||e.s.includes(q)));}
const off=t=>-new Date(t).getTimezoneOffset()*60000;
function alignDown(t,B){const o=off(t);return Math.floor((t+o)/B)*B-o;}
function alignUp(t,B){const o=off(t);return Math.ceil((t+o)/B)*B-o;}

$('title').textContent=document.title;
$('sub').textContent='Window '+fmt(full[0])+' \u2192 '+fmt(full[1])+' \u00b7 generated '+D.meta.generated+' \u00b7 '+E.length.toLocaleString()+' events';
$('log').textContent=D.log.join('\n');
function fillSel(id,label,vals){const s=$(id);s.innerHTML='<option value="">'+label+'</option>'+[...new Set(vals)].sort().map(v=>'<option>'+esc(v)+'</option>').join('');}
fillSel('cat','All categories',E.map(e=>e.cat));fillSel('comp','All computers',E.map(e=>e.c));
document.querySelectorAll('[data-l]').forEach(cb=>cb.onchange=()=>{S.lv[cb.dataset.l]=cb.checked?1:0;render();});
$('cat').onchange=e=>{S.cat=e.target.value;render();};$('comp').onchange=e=>{S.c=e.target.value;render();};
$('lane').onchange=e=>{S.lane=e.target.value;render();};
let qt;$('q').oninput=e=>{clearTimeout(qt);qt=setTimeout(()=>{S.q=e.target.value.trim();render();},200);};
function zoom(a,b){S.stack.push([S.w0,S.w1]);S.w0=a;S.w1=b;render();}
function back(){if(S.stack.length){[S.w0,S.w1]=S.stack.pop();render();}}
$('back').onclick=back;$('reset').onclick=()=>{S.stack=[];S.w0=full[0];S.w1=full[1];render();};

let G=null;
function drawTimeline(rows){
 const svg=$('tl');const W=Math.max(320,svg.clientWidth||900);const narrow=W<600;
 const span=(S.w1-S.w0)/1000;const bs=STEPS.find(s=>span/s<=(narrow?60:120))||604800;const B=bs*1000;
 const a0=alignDown(S.w0,B),a1=Math.max(alignUp(S.w1,B),a0+B);const n=Math.round((a1-a0)/B);
 const L=narrow?90:170,R=12,T=14,H=narrow?120:170,laneH=narrow?18:20;
 const cnt=[0,1,2,3,4].map(()=>new Array(n).fill(0));const cells=new Map();const laneN=new Map();const marks=[];
 for(const e of rows){const b=Math.floor((e.t-a0)/B);if(b<0||b>=n)continue;cnt[e.l][b]++;
  const ln=laneOf(e);laneN.set(ln,(laneN.get(ln)||0)+1);const k=ln+'\u0001'+b;let c=cells.get(k);
  if(!c){c={ln,b,n:0,w:4,k:[0,0,0,0,0],top:new Map()};cells.set(k,c);}c.n++;c.k[e.l]++;if(e.l<c.w)c.w=e.l;
  const lab=e.p+' '+e.id+(e.tag?' ('+e.tag+')':'');c.top.set(lab,(c.top.get(lab)||0)+1);}
 for(const e of E){if(e.mk&&e.t>=S.w0&&e.t<S.w1&&(!S.cat||e.cat===S.cat)&&(!S.c||e.c===S.c))marks.push(e);}
 let lanes=[...laneN.entries()].sort((x,y)=>y[1]-x[1]);if(lanes.length>30){const keep=new Set(lanes.slice(0,29).map(x=>x[0]));
  for(const c of [...cells.values()])if(!keep.has(c.ln)){cells.delete(c.ln+'\u0001'+c.b);const k='(other)\u0001'+c.b;let o=cells.get(k);
   if(!o){o={ln:'(other)',b:c.b,n:0,w:4,k:[0,0,0,0,0],top:new Map()};cells.set(k,o);}o.n+=c.n;o.w=Math.min(o.w,c.w);for(let i=1;i<5;i++)o.k[i]+=c.k[i];}
  lanes=lanes.slice(0,29).concat([['(other)',0]]);}
 const laneNames=lanes.map(x=>x[0]).sort((x,y)=>x==='(other)'?1:y==='(other)'?-1:x.localeCompare(y));const li=new Map(laneNames.map((x,i)=>[x,i]));
 const laneTop=T+H+26,Ht=laneTop+Math.max(1,laneNames.length)*laneH+8;
 const X=t=>L+(t-a0)/(a1-a0)*(W-L-R);const bw=(W-L-R)/n;
 let mx=1;for(let b=0;b<n;b++){let s=0;for(let l=1;l<5;l++)s+=cnt[l][b];if(s>mx)mx=s;}
 const nice=v=>{const p=Math.pow(10,Math.floor(Math.log10(v)));const f=v/p;return (f<=1?1:f<=2?2:f<=5?5:10)*p;};const ymax=Math.max(4,nice(mx));
 const Y=v=>T+H-v/ymax*H;const col={1:css('--c1'),2:css('--c2'),3:css('--c3'),4:css('--c4')};const grid=css('--grid');
 let s='';
 for(let i=0;i<=4;i++){const v=ymax*i/4,y=Y(v);s+=`<line x1="${L}" x2="${W-R}" y1="${y}" y2="${y}" stroke="${grid}"/><text x="${L-6}" y="${y+4}" text-anchor="end">${Math.round(v)}</text>`;}
 for(let b=0;b<n;b++){let acc=0;const x=X(a0+b*B)+Math.max(0.5,bw*0.06),w=Math.max(1,bw*0.88);
  for(const l of [1,2,3,4]){const v=cnt[l][b];if(!v)continue;const y0=Y(acc),y1=Y(acc+v);acc+=v;
   s+=`<rect x="${x}" y="${y1}" width="${w}" height="${Math.max(0.5,y0-y1)}" fill="${col[l]}"><title>${fmt(a0+b*B,'dhm')} \u2013 ${fmt(a0+(b+1)*B,'hm')}\n${LV[l]}: ${v}</title></rect>`;}}
 const tickTarget=Math.max(2,Math.floor((W-L-R)/(narrow?80:110)));const ts=STEPS.find(x=>span/x<=tickTarget&&x>=bs)||604800;
 const tf=ts>=86400?'d':span>86400?'dhm':ts<60?'hms':'hm';
 for(let t=alignUp(a0,ts*1000);t<=a1;t+=ts*1000){const x=X(t);s+=`<line x1="${x}" x2="${x}" y1="${T}" y2="${Ht-6}" stroke="${grid}" stroke-dasharray="2 4"/><text x="${x}" y="${T+H+16}" text-anchor="middle">${fmt(t,tf)}</text>`;}
 s+=`<line x1="${L}" x2="${W-R}" y1="${T+H}" y2="${T+H}" stroke="${css('--muted')}"/>`;
 laneNames.forEach((ln,i)=>{const y=laneTop+i*laneH;if(i%2===0)s+=`<rect x="${L}" y="${y}" width="${W-L-R}" height="${laneH}" fill="${css('--panel2')}" opacity="0.6"/>`;
  const lab=ln.length>(narrow?12:26)?ln.slice(0,narrow?11:25)+'\u2026':ln;s+=`<text x="${L-6}" y="${y+laneH/2+4}" text-anchor="end"><title>${esc(ln)}</title>${esc(lab)}</text>`;});
 for(const c of cells.values()){const i=li.get(c.ln);if(i==null)continue;const cx=X(a0+(c.b+0.5)*B),cy=laneTop+i*laneH+laneH/2;const r=Math.min(laneH/2-1,2.5+2.2*Math.log10(c.n+1)*1.6);
  const top=[...c.top.entries()].sort((x,y)=>y[1]-x[1]).slice(0,3).map(x=>x[1]+'\u00d7 '+x[0]).join('\n');
  s+=`<circle cx="${cx}" cy="${cy}" r="${r}" fill="${col[c.w]}" fill-opacity="0.85"><title>${esc(c.ln)} \u00b7 ${fmt(a0+c.b*B,'dhm')}\n${c.n} events (${c.k[1]} critical, ${c.k[2]} error, ${c.k[3]} warning, ${c.k[4]} info)\n${esc(top)}</title></circle>`;}
 marks.sort((x,y)=>x.t-y.t);const last=new Map();const gap=Math.max(300000,B);
 for(const m of marks){const k=m.c+'|'+m.mk;if(last.has(k)&&m.t-last.get(k)<gap)continue;last.set(k,m.t);const x=X(m.t),c=MK[m.mk]||'#888';
  s+=`<g><line x1="${x}" x2="${x}" y1="${T-4}" y2="${Ht-6}" stroke="${c}" stroke-width="1.6" stroke-dasharray="5 3"/><path d="M${x-5},${T-12}h10l-5,7z" fill="${c}"/><title>${fmt(m.t)} \u00b7 ${esc(m.c)}\n${esc(m.tag||m.mk)}</title></g>`;}
 s+=`<rect id="brush" x="0" y="${T}" width="0" height="${Ht-T-6}" fill="${css('--accent')}" opacity="0.18" pointer-events="none"/>`;
 svg.setAttribute('viewBox',`0 0 ${W} ${Ht}`);svg.setAttribute('height',Ht);svg.innerHTML=s;
 G={a0,a1,B,n,L,R,W,T,H,laneTop,laneH,laneNames,X,tot:Array.from({length:n},(_,b)=>cnt[1][b]+cnt[2][b]+cnt[3][b]+cnt[4][b])};
}
const svg=$('tl');let drag=null;
function px(ev){const r=svg.getBoundingClientRect();return{x:(ev.clientX-r.left)*G.W/r.width,y:(ev.clientY-r.top)*G.W/r.width};}
const tAt=x=>G.a0+(Math.min(Math.max(x,G.L),G.W-G.R)-G.L)/(G.W-G.L-G.R)*(G.a1-G.a0);
svg.addEventListener('mousedown',ev=>{if(ev.button!==0||!G)return;const p=px(ev);if(p.x<G.L)return;drag={x0:p.x,x1:p.x,y:p.y};ev.preventDefault();});
window.addEventListener('mousemove',ev=>{if(!drag)return;drag.x1=px(ev).x;const b=$('brush');if(b){b.setAttribute('x',Math.min(drag.x0,drag.x1));b.setAttribute('width',Math.abs(drag.x1-drag.x0));}});
window.addEventListener('mouseup',()=>{if(!drag)return;const d=drag;drag=null;
 if(Math.abs(d.x1-d.x0)>5){const a=tAt(Math.min(d.x0,d.x1)),b=tAt(Math.max(d.x0,d.x1));zoom(a,b);return;}
 let b=Math.floor((tAt(d.x0)-G.a0)/G.B);if(b<0||b>=G.n)return;
 if(!G.tot[b]){if(G.tot[b-1])b--;else if(G.tot[b+1])b++;}
 if(d.y>=G.laneTop){const i=Math.floor((d.y-G.laneTop)/G.laneH);const ln=G.laneNames[i];
  if(ln&&ln!=='(other)'){if(S.lane==='cat'){S.cat=ln;$('cat').value=ln;}else if(S.lane==='c'){S.c=ln;$('comp').value=ln;}else{S.q=ln;$('q').value=ln;}}}
 zoom(G.a0+b*G.B,G.a0+(b+1)*G.B);});
svg.addEventListener('contextmenu',ev=>{ev.preventDefault();back();});
window.addEventListener('resize',()=>{clearTimeout(window.__rt);window.__rt=setTimeout(render,150);});

function drawTop(rows){const g=new Map();
 for(const e of rows){const k=e.cat+'\u0001'+e.p+'\u0001'+e.id+(e.id===0?'\u0001'+e.tag:'');let o=g.get(k);if(!o){o={cat:e.cat,p:e.p,id:e.id,n:0,w:4,f:e.t,la:e.t,tag:e.tag,cs:new Set(),m:e.m};g.set(k,o);}
  o.n++;if(e.l<o.w)o.w=e.l;if(e.t<o.f)o.f=e.t;if(e.t>o.la)o.la=e.t;o.cs.add(e.c);}
 const list=[...g.values()].sort((a,b)=>a.w-b.w||b.n-a.n).slice(0,200);
 $('top').innerHTML='<thead><tr><th>Count</th><th>Level</th><th>Category</th><th>Provider</th><th>ID</th><th>Description</th><th>First</th><th>Last</th><th>Hosts</th><th>Sample message</th></tr></thead><tbody>'+
  list.map((o,i)=>`<tr class="grp" data-g="${i}"><td class="n">${o.n}</td><td class="lv l${o.w}">${LV[o.w]}</td><td>${esc(o.cat)}</td><td>${esc(o.p)}</td><td class="n">${o.id}</td><td>${esc(o.tag)}</td><td class="t">${fmt(o.f,'dhm')}</td><td class="t">${fmt(o.la,'dhm')}</td><td class="n">${o.cs.size}</td><td class="msg" title="${esc(o.m.slice(0,600))}">${esc(o.m.slice(0,300))}</td></tr>`).join('')+'</tbody>';
 $('top').onclick=ev=>{const tr=ev.target.closest('tr.grp');if(!tr)return;const o=list[+tr.dataset.g];S.cat=o.cat;$('cat').value=o.cat;S.q=String(o.id);$('q').value=S.q;render();};
}
function drawTable(rows){const MAX=2000;const show=rows.length>MAX?rows.slice(rows.length-MAX):rows;
 $('cnt').textContent=rows.length.toLocaleString()+' events in window'+(rows.length>MAX?' \u2014 showing the latest '+MAX+'; zoom or filter to narrow down':'');
 let h='<thead><tr><th>Time</th><th>Computer</th><th>Level</th><th>Category</th><th>Description</th><th>ID</th><th>Provider</th><th>Message</th></tr></thead><tbody>';
 for(const e of show){h+=`<tr class="ev" data-i="${e.i}"><td class="t">${esc(e.ts.replace('T',' '))}</td><td>${esc(e.c)}</td><td class="lv l${e.l}">${esc(e.ln)}</td><td>${esc(e.cat)}</td><td>${esc(e.tag)}</td><td class="n">${e.id}</td><td>${esc(e.p)}</td><td class="msg">${esc(e.m.slice(0,300))}</td></tr>`;
  if(S.open.has(e.i))h+=`<tr class="detail"><td colspan="8"><pre>${esc(e.log)}\n\n${esc(e.m)}</pre></td></tr>`;}
 $('evt').innerHTML=h+'</tbody>';
 $('evt').onclick=ev=>{const tr=ev.target.closest('tr.ev');if(!tr)return;const i=+tr.dataset.i;if(S.open.has(i))S.open.delete(i);else S.open.add(i);drawTable(rows);};
}
function kpis(rows){const k=[0,0,0,0,0];rows.forEach(e=>k[e.l]++);const mk=rows.filter(e=>e.mk).length;
 const t=(lab,v,c)=>`<div class="kpi" style="border-left-color:${c}">${lab}<b>${v.toLocaleString()}</b></div>`;
 $('kpis').innerHTML=t('Critical',k[1],css('--c1'))+t('Error',k[2],css('--c2'))+t('Warning',k[3],css('--c3'))+t('Information',k[4],css('--c4'))+t('Key events',mk,'#a78bfa')+t('Computers',new Set(rows.map(e=>e.c)).size,css('--grid'));}
function render(){const rows=base().filter(e=>e.t>=S.w0&&e.t<S.w1);drawTimeline(rows);drawTop(rows);drawTable(rows);kpis(rows);
 $('win').textContent=fmt(S.w0)+' \u2192 '+fmt(S.w1);}
render();
})();
</script></body></html>
'@
#endregion

#region ===================== Headless mode =====================
function Get-SessionFileName([string[]]$Computers) {
    $names = ($Computers | Select-Object -First 3) -join '_'
    if ($Computers.Count -gt 3) { $names += "_and_$($Computers.Count - 3)_more" }
    return ('EventLogSession_{0}_{1}.json' -f ($names -replace '[^\w\.-]', '_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

if ($NoGui) {
    $allEvents = New-Object System.Collections.Generic.List[object]
    $allLog = New-Object System.Collections.Generic.List[string]
    if ($SessionPath) {
        # Convert saved session(s) to CSV / HTML (or objects) without collecting anything
        $starts = @(); $ends = @(); $comps = @()
        foreach ($p in $SessionPath) {
            $sess = Read-InvestigationSession $p
            $col = Get-JsonValue $sess.Document 'collection'
            $starts += ConvertFrom-SessionDate (Get-JsonValue $col 'start')
            $ends += ConvertFrom-SessionDate (Get-JsonValue $col 'end')
            $comps += @(Get-JsonValue $col 'computers' @())
            $allEvents.AddRange([object[]]$sess.Events)
            foreach ($l in @(Get-JsonValue $sess.Document 'runLog' @())) { $allLog.Add([string]$l) }
        }
        $StartTime = ($starts | Measure-Object -Minimum).Minimum; $EndTime = ($ends | Measure-Object -Maximum).Maximum
        $ComputerName = @($comps | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    } else {
        foreach ($c in $ComputerName) {
            $r = & $Collector $c $StartTime $EndTime $Sources $MaxEventsPerQuery ([bool]$IncludeInformation)
            if ($r) { $allEvents.AddRange([object[]]$r.Events); $allLog.AddRange([string[]]$r.Log) }
        }
    }
    $sorted = @($allEvents | Sort-Object Time)
    if ($OutputPath) {
        if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $base = Join-Path $OutputPath ([IO.Path]::GetFileNameWithoutExtension((Get-SessionFileName $ComputerName)))
        $written = @()
        if (-not $SessionPath) {
            $collection = [ordered]@{
                start = $StartTime; end = $EndTime; computers = $ComputerName; sources = $Sources; includeInformation = [bool]$IncludeInformation
                maxEventsPerQuery = $MaxEventsPerQuery; collectedAt = (Get-Date); collectedOn = $env:COMPUTERNAME
                utcOffsetMinutes = [int][TimeZoneInfo]::Local.GetUtcOffset($StartTime).TotalMinutes
            }
            Export-InvestigationSession -Rows $sorted -Path "$base.json" -Collection $collection -View $null -RunLog $allLog
            $written += "$base.json"
        }
        Export-EventCsv $sorted "$base.csv"
        New-HtmlReport -Rows $sorted -Path "$base.html" -Start $StartTime -End $EndTime -Computers $ComputerName -RunLog $allLog
        $allLog | Set-Content -Path "$base.log" -Encoding UTF8
        $written += "$base.csv", "$base.html", "$base.log"
        $allLog | ForEach-Object { Write-Host $_ }
        Write-Host "`n$($sorted.Count) events written to:"
        $written | ForEach-Object { Write-Host "  $_" }
    } else {
        $allLog | ForEach-Object { Write-Host $_ }
        $sorted
    }
    return
}
#endregion

#region ===================== GUI =====================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms.DataVisualization
[System.Windows.Forms.Application]::EnableVisualStyles()

# Dark renderer for menus, toolbars and the status bar
if (-not ('WELI.DarkRenderer' -as [type])) {
    Add-Type -ReferencedAssemblies System.Windows.Forms, System.Drawing -TypeDefinition @'
using System.Drawing;
using System.Windows.Forms;
namespace WELI {
    public class DarkColors : ProfessionalColorTable {
        static readonly Color Bg = Color.FromArgb(45, 45, 48), Bg2 = Color.FromArgb(37, 37, 40), Hover = Color.FromArgb(62, 62, 66);
        static readonly Color Border = Color.FromArgb(70, 70, 74), Accent = Color.FromArgb(0, 122, 204), Checked = Color.FromArgb(0, 84, 140);
        public override Color ToolStripGradientBegin { get { return Bg; } }
        public override Color ToolStripGradientMiddle { get { return Bg; } }
        public override Color ToolStripGradientEnd { get { return Bg; } }
        public override Color ToolStripBorder { get { return Bg; } }
        public override Color ToolStripDropDownBackground { get { return Bg2; } }
        public override Color ToolStripContentPanelGradientBegin { get { return Bg; } }
        public override Color ToolStripContentPanelGradientEnd { get { return Bg; } }
        public override Color MenuStripGradientBegin { get { return Bg; } }
        public override Color MenuStripGradientEnd { get { return Bg; } }
        public override Color StatusStripGradientBegin { get { return Bg2; } }
        public override Color StatusStripGradientEnd { get { return Bg2; } }
        public override Color ImageMarginGradientBegin { get { return Bg2; } }
        public override Color ImageMarginGradientMiddle { get { return Bg2; } }
        public override Color ImageMarginGradientEnd { get { return Bg2; } }
        public override Color MenuBorder { get { return Border; } }
        public override Color MenuItemBorder { get { return Border; } }
        public override Color MenuItemSelected { get { return Hover; } }
        public override Color MenuItemSelectedGradientBegin { get { return Hover; } }
        public override Color MenuItemSelectedGradientEnd { get { return Hover; } }
        public override Color MenuItemPressedGradientBegin { get { return Bg2; } }
        public override Color MenuItemPressedGradientMiddle { get { return Bg2; } }
        public override Color MenuItemPressedGradientEnd { get { return Bg2; } }
        public override Color ButtonSelectedHighlight { get { return Hover; } }
        public override Color ButtonSelectedGradientBegin { get { return Hover; } }
        public override Color ButtonSelectedGradientMiddle { get { return Hover; } }
        public override Color ButtonSelectedGradientEnd { get { return Hover; } }
        public override Color ButtonSelectedBorder { get { return Border; } }
        public override Color ButtonPressedGradientBegin { get { return Accent; } }
        public override Color ButtonPressedGradientMiddle { get { return Accent; } }
        public override Color ButtonPressedGradientEnd { get { return Accent; } }
        public override Color ButtonPressedBorder { get { return Accent; } }
        public override Color ButtonCheckedGradientBegin { get { return Checked; } }
        public override Color ButtonCheckedGradientMiddle { get { return Checked; } }
        public override Color ButtonCheckedGradientEnd { get { return Checked; } }
        public override Color ButtonCheckedHighlight { get { return Checked; } }
        public override Color ButtonCheckedHighlightBorder { get { return Accent; } }
        public override Color CheckBackground { get { return Checked; } }
        public override Color CheckSelectedBackground { get { return Accent; } }
        public override Color CheckPressedBackground { get { return Accent; } }
        public override Color SeparatorDark { get { return Border; } }
        public override Color SeparatorLight { get { return Bg; } }
        public override Color GripDark { get { return Border; } }
        public override Color GripLight { get { return Bg; } }
        public override Color OverflowButtonGradientBegin { get { return Bg; } }
        public override Color OverflowButtonGradientMiddle { get { return Bg; } }
        public override Color OverflowButtonGradientEnd { get { return Bg; } }
    }
    public class DarkRenderer : ToolStripProfessionalRenderer {
        public DarkRenderer() : base(new DarkColors()) { RoundedEdges = false; }
        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e) {
            e.TextColor = e.Item.Enabled ? e.Item.ForeColor : Color.FromArgb(115, 115, 120);
            base.OnRenderItemText(e);
        }
        protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e) {
            e.ArrowColor = e.Item == null || e.Item.Enabled ? Color.FromArgb(210, 210, 210) : Color.FromArgb(115, 115, 120);
            base.OnRenderArrow(e);
        }
        protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e) {
            Rectangle r = new Rectangle(e.ImageRectangle.X - 2, e.ImageRectangle.Y - 2, e.ImageRectangle.Width + 4, e.ImageRectangle.Height + 4);
            using (SolidBrush b = new SolidBrush(Color.FromArgb(0, 84, 140))) { e.Graphics.FillRectangle(b, r); }
            using (Pen p = new Pen(Color.White, 2)) {
                e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                e.Graphics.DrawLines(p, new Point[] { new Point(r.Left + 4, r.Top + r.Height / 2), new Point(r.Left + r.Width / 2 - 1, r.Bottom - 5), new Point(r.Right - 4, r.Top + 4) });
            }
        }
    }
}
'@
}

$theme = @{
    FormBackground          = [System.Drawing.Color]::FromArgb(45, 45, 48)
    PanelBackground         = [System.Drawing.Color]::FromArgb(37, 37, 40)
    ControlBackground       = [System.Drawing.Color]::FromArgb(60, 60, 63)
    ControlForeground       = [System.Drawing.Color]::FromArgb(220, 220, 220)
    MutedForeground         = [System.Drawing.Color]::FromArgb(150, 150, 155)
    GridBackground          = [System.Drawing.Color]::FromArgb(42, 42, 45)
    GridForeground          = [System.Drawing.Color]::FromArgb(215, 215, 215)
    GridLines               = [System.Drawing.Color]::FromArgb(58, 58, 62)
    ChartLines              = [System.Drawing.Color]::FromArgb(72, 72, 76)
    GridHeaderBackground    = [System.Drawing.Color]::FromArgb(52, 52, 56)
    GridAltCellBackground   = [System.Drawing.Color]::FromArgb(47, 47, 50)
    GridSelectionBackground = [System.Drawing.Color]::FromArgb(0, 84, 140)
    AccentColor             = [System.Drawing.Color]::FromArgb(0, 122, 204)
}
$levelColors = @{
    1 = [System.Drawing.Color]::FromArgb(224, 69, 123)   # Critical
    2 = [System.Drawing.Color]::FromArgb(242, 107, 58)   # Error
    3 = [System.Drawing.Color]::FromArgb(232, 163, 23)   # Warning
    4 = [System.Drawing.Color]::FromArgb(91, 159, 227)   # Information
}
$levelNames = @{ 1 = 'Critical'; 2 = 'Error'; 3 = 'Warning'; 4 = 'Information' }
$markerColors = @{
    Boot = [System.Drawing.Color]::FromArgb(200, 200, 205); Shutdown = [System.Drawing.Color]::FromArgb(140, 140, 145)
    Crash = [System.Drawing.Color]::FromArgb(255, 64, 64); SQL = [System.Drawing.Color]::FromArgb(20, 184, 166)
    AG = [System.Drawing.Color]::FromArgb(56, 189, 248); Cluster = [System.Drawing.Color]::FromArgb(167, 139, 250)
    Security = [System.Drawing.Color]::FromArgb(251, 146, 60); Update = [System.Drawing.Color]::FromArgb(101, 163, 13)
}
$timeFrames = @(
    [PSCustomObject]@{ Name = 'Last 1 hour'; Hours = 1 }, [PSCustomObject]@{ Name = 'Last 6 hours'; Hours = 6 },
    [PSCustomObject]@{ Name = 'Last 12 hours'; Hours = 12 }, [PSCustomObject]@{ Name = 'Last 24 hours'; Hours = 24 },
    [PSCustomObject]@{ Name = 'Last 48 hours'; Hours = 48 }, [PSCustomObject]@{ Name = 'Last 3 days'; Hours = 72 },
    [PSCustomObject]@{ Name = 'Last 7 days'; Hours = 168 }, [PSCustomObject]@{ Name = 'Last 14 days'; Hours = 336 },
    [PSCustomObject]@{ Name = 'Last 30 days'; Hours = 720 }, [PSCustomObject]@{ Name = 'Custom range'; Hours = 0 }
)
$sourceDefs = @(
    @{ Key = 'System'; Text = 'System log'; Tip = 'Critical / Error / Warning plus boots, shutdowns, BSODs, patching and SQL / cluster service changes.' },
    @{ Key = 'Application'; Text = 'Application log'; Tip = 'Critical / Error / Warning plus installs and crash reports.' },
    @{ Key = 'SQL'; Text = 'SQL Server events'; Tip = 'Every SQL provider in the Application log incl. restarts, AG role changes, login failures, slow I/O, corruption...' },
    @{ Key = 'SQLLogs'; Text = 'SQL ERRORLOG + Agent log'; Tip = 'Parses ERRORLOG / SQLAGENT.OUT for every instance (remote: Remote Registry + admin shares).' },
    @{ Key = 'Cluster'; Text = 'Failover Cluster'; Tip = 'FailoverClustering Operational, Manager, CSV and Cluster-Aware Updating logs plus cluster events in the System log.' },
    @{ Key = 'HyperV'; Text = 'Hyper-V'; Tip = 'Hyper-V VMMS, Worker and High-Availability admin logs.' },
    @{ Key = 'Security'; Text = 'Security audit'; Tip = 'Failed logons, lockouts, Kerberos failures, audit log cleared.' },
    @{ Key = 'OpsMgr'; Text = 'Operations Manager (SCOM)'; Tip = 'SCOM agent errors.' }
)
$script:BucketSteps = 10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800

# --- State ---
$script:Jobs = @()
$script:RunLog = @()
$script:Computers = $ComputerName
$script:CollectStart = $null; $script:CollectEnd = $null; $script:CollectedAt = $null; $script:CollectedOn = $null
$script:CollectSources = $Sources; $script:CollectIncludeInfo = [bool]$IncludeInformation; $script:CollectMax = $MaxEventsPerQuery
$script:UtcOffsetMinutes = $null
$script:SessionFiles = @()
$script:ViewStart = $null; $script:ViewEnd = $null
$script:ZoomStack = New-Object System.Collections.Stack
$script:SuspendFilter = $false
$script:SettingRange = $false
$script:ChartDownX = 0
$script:LaneNames = @()
$script:LaneCount = 1

$script:Table = New-Object System.Data.DataTable 'Events'
foreach ($c in @(@('Key', [int]), @('Time', [datetime]), @('Computer', [string]), @('Level', [string]), @('LevelNum', [int]), @('Category', [string]),
        @('Tag', [string]), @('Marker', [string]), @('Id', [int]), @('Provider', [string]), @('LogName', [string]), @('Source', [string]),
        @('RecordId', [long]), @('Summary', [string]), @('Message', [string]))) { [void]$script:Table.Columns.Add($c[0], $c[1]) }
$script:View = New-Object System.Data.DataView($script:Table)
$script:View.Sort = 'Time ASC'

$script:SummaryTable = New-Object System.Data.DataTable 'Summary'
foreach ($c in @(@('Count', [int]), @('Level', [string]), @('LevelNum', [int]), @('Category', [string]), @('Provider', [string]), @('Id', [int]),
        @('Tag', [string]), @('First', [datetime]), @('Last', [datetime]), @('Computers', [int]), @('Sample', [string]))) { [void]$script:SummaryTable.Columns.Add($c[0], $c[1]) }
$script:SummaryView = New-Object System.Data.DataView($script:SummaryTable)
$script:SummaryView.Sort = 'LevelNum ASC, Count DESC'

# --- Control helpers ---
$renderer = New-Object WELI.DarkRenderer
$uiFont = New-Object System.Drawing.Font('Segoe UI', 9)
$uiFontBold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

function New-ToolStrip {
    $t = New-Object System.Windows.Forms.ToolStrip
    $t.Renderer = $renderer; $t.GripStyle = [System.Windows.Forms.ToolStripGripStyle]::Hidden
    $t.BackColor = $theme.FormBackground; $t.ForeColor = $theme.ControlForeground; $t.Font = $uiFont
    $t.Padding = New-Object System.Windows.Forms.Padding(6, 4, 6, 4)
    $t
}
function New-TsLabel([string]$Text, [switch]$Muted) {
    $l = New-Object System.Windows.Forms.ToolStripLabel $Text
    $l.ForeColor = if ($Muted) { $theme.MutedForeground } else { $theme.ControlForeground }
    $l.Margin = New-Object System.Windows.Forms.Padding(6, 1, 2, 2)
    $l
}
function New-TsButton([string]$Text, [string]$Tip = $null) {
    $b = New-Object System.Windows.Forms.ToolStripButton $Text
    $b.ForeColor = $theme.ControlForeground; $b.DisplayStyle = [System.Windows.Forms.ToolStripItemDisplayStyle]::Text
    $b.Padding = New-Object System.Windows.Forms.Padding(6, 2, 6, 2)
    if ($Tip) { $b.ToolTipText = $Tip }
    $b
}
function New-TsTextBox([int]$Width, [string]$Tip = $null) {
    $t = New-Object System.Windows.Forms.ToolStripTextBox
    $t.AutoSize = $false; $t.Width = $Width
    $t.BackColor = $theme.ControlBackground; $t.ForeColor = $theme.ControlForeground; $t.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    if ($Tip) { $t.ToolTipText = $Tip }
    $t
}
# ToolStripComboBox ignores BackColor, so host a flat ComboBox instead. The ToolStrip host is kept in .Tag.
function New-TsComboBox([int]$Width, [object[]]$Items, [string]$Tip = $null) {
    $c = New-Object System.Windows.Forms.ComboBox
    $c.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; $c.Width = $Width
    $c.BackColor = $theme.ControlBackground; $c.ForeColor = $theme.ControlForeground; $c.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    foreach ($i in $Items) { [void]$c.Items.Add($i) }
    $h = New-Object System.Windows.Forms.ToolStripControlHost $c
    $h.Margin = New-Object System.Windows.Forms.Padding(2, 1, 2, 1)
    if ($Tip) { $h.ToolTipText = $Tip }
    $c.Tag = $h
    $c
}
function New-MenuItem([string]$Text, $Shortcut = $null, [string]$ShortcutText = $null) {
    $m = New-Object System.Windows.Forms.ToolStripMenuItem $Text
    $m.ForeColor = $theme.ControlForeground
    if ($Shortcut) { $m.ShortcutKeys = $Shortcut }
    if ($ShortcutText) { $m.ShortcutKeyDisplayString = $ShortcutText }
    $m
}
function Set-DoubleBuffered($Control) {
    $Control.GetType().GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]'NonPublic,Instance').SetValue($Control, $true, $null)
}
function Set-GridStyle($Grid) {
    $Grid.Dock = [System.Windows.Forms.DockStyle]::Fill
    $Grid.ReadOnly = $true; $Grid.AllowUserToAddRows = $false; $Grid.AllowUserToDeleteRows = $false; $Grid.AllowUserToResizeRows = $false
    $Grid.RowHeadersVisible = $false; $Grid.AutoGenerateColumns = $false
    $Grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $Grid.ClipboardCopyMode = [System.Windows.Forms.DataGridViewClipboardCopyMode]::EnableAlwaysIncludeHeaderText
    $Grid.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $Grid.CellBorderStyle = [System.Windows.Forms.DataGridViewCellBorderStyle]::SingleHorizontal
    $Grid.ColumnHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::None
    $Grid.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::DisableResizing
    $Grid.ColumnHeadersHeight = 30; $Grid.RowTemplate.Height = 24
    $Grid.BackgroundColor = $theme.GridBackground; $Grid.ForeColor = $theme.GridForeground; $Grid.GridColor = $theme.GridLines
    $Grid.DefaultCellStyle.BackColor = $theme.GridBackground; $Grid.DefaultCellStyle.ForeColor = $theme.GridForeground
    $Grid.DefaultCellStyle.SelectionBackColor = $theme.GridSelectionBackground; $Grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $Grid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(4, 0, 4, 0)
    $Grid.AlternatingRowsDefaultCellStyle.BackColor = $theme.GridAltCellBackground
    $Grid.ColumnHeadersDefaultCellStyle.BackColor = $theme.GridHeaderBackground; $Grid.ColumnHeadersDefaultCellStyle.ForeColor = $theme.MutedForeground
    $Grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $theme.GridHeaderBackground
    $Grid.ColumnHeadersDefaultCellStyle.Font = $uiFontBold
    $Grid.ColumnHeadersDefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(4, 0, 4, 0)
    $Grid.EnableHeadersVisualStyles = $false
    Set-DoubleBuffered $Grid
}
function Add-GridColumn($Grid, [string]$Prop, [string]$Header, [int]$Width, [string]$Format = $null, [switch]$Fill) {
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.DataPropertyName = $Prop; $col.Name = $Prop; $col.HeaderText = $Header; $col.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::Automatic
    if ($Format) { $col.DefaultCellStyle.Format = $Format }
    if ($Fill) { $col.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill; $col.MinimumWidth = 250 } else { $col.Width = $Width }
    [void]$Grid.Columns.Add($col)
}
function New-LogTextBox {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Multiline = $true; $t.ReadOnly = $true; $t.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    $t.Dock = [System.Windows.Forms.DockStyle]::Fill; $t.Font = New-Object System.Drawing.Font('Consolas', 9.5)
    $t.BackColor = $theme.PanelBackground; $t.ForeColor = $theme.ControlForeground; $t.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $t
}

# --- Form ---
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = 'Windows Event Log Investigator'
$mainForm.Size = New-Object System.Drawing.Size(1440, 920)
$mainForm.MinimumSize = New-Object System.Drawing.Size(1000, 640)
$mainForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$mainForm.BackColor = $theme.FormBackground
$mainForm.ForeColor = $theme.ControlForeground
$mainForm.Font = $uiFont
$mainForm.KeyPreview = $true
$mainForm.AllowDrop = $true

# Menu
$menu = New-Object System.Windows.Forms.MenuStrip
$menu.Renderer = $renderer; $menu.BackColor = $theme.FormBackground; $menu.ForeColor = $theme.ControlForeground; $menu.Font = $uiFont
$mnuFile = New-MenuItem '&File'
$miOpen = New-MenuItem '&Open session...' ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::O)
$miAdd = New-MenuItem '&Add session (merge)...'
$miAdd.ToolTipText = 'Add more session files to what is loaded, e.g. one exported from each cluster node.'
$miSave = New-MenuItem '&Save session...' ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::S)
$miCsv = New-MenuItem 'Export displayed events to &CSV...' ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::E)
$miExcel = New-MenuItem 'Open displayed events in &Excel'
$miHtml = New-MenuItem 'Save &HTML report...' ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::H)
$miExit = New-MenuItem 'E&xit'
[void]$mnuFile.DropDownItems.AddRange(@($miOpen, $miAdd, $miSave, (New-Object System.Windows.Forms.ToolStripSeparator), $miCsv, $miExcel, $miHtml,
        (New-Object System.Windows.Forms.ToolStripSeparator), $miExit))
$mnuView = New-MenuItem '&View'
$miCollect = New-MenuItem '&Collect now' ([System.Windows.Forms.Keys]::F5)
$miFind = New-MenuItem '&Search events' ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::F)
$miZoomOut = New-MenuItem '&Zoom out' ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::OemMinus) 'Ctrl+-'
$miResetZoom = New-MenuItem '&Reset zoom' ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::D0) 'Ctrl+0'
$miClearFilters = New-MenuItem 'C&lear filters' ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Shift -bor [System.Windows.Forms.Keys]::X) 'Ctrl+Shift+X'
$miShowCollect = New-MenuItem 'Collection &bar'; $miShowCollect.CheckOnClick = $true; $miShowCollect.Checked = $true
$miShowDetail = New-MenuItem '&Details pane'; $miShowDetail.CheckOnClick = $true; $miShowDetail.Checked = $true
[void]$mnuView.DropDownItems.AddRange(@($miCollect, $miFind, (New-Object System.Windows.Forms.ToolStripSeparator), $miZoomOut, $miResetZoom, $miClearFilters,
        (New-Object System.Windows.Forms.ToolStripSeparator), $miShowCollect, $miShowDetail))
$mnuHelp = New-MenuItem '&Help'
$miTips = New-MenuItem '&How to use' ([System.Windows.Forms.Keys]::F1)
[void]$mnuHelp.DropDownItems.Add($miTips)
[void]$menu.Items.AddRange(@($mnuFile, $mnuView, $mnuHelp))

# Collection bar: where / when / what
$tsCollect = New-ToolStrip
$txtComputers = New-TsTextBox 240 'Servers to collect from, comma separated (e.g. every node of a cluster).'
$txtComputers.Text = $ComputerName -join ', '
$btnClusterNodes = New-TsButton '+ Cluster nodes' 'Add every node of the cluster that the first computer belongs to.'
$cmbRange = New-TsComboBox 125 ($timeFrames | ForEach-Object { $_.Name })
$dtpFrom = New-Object System.Windows.Forms.DateTimePicker
$dtpTo = New-Object System.Windows.Forms.DateTimePicker
foreach ($d in $dtpFrom, $dtpTo) {
    $d.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom; $d.CustomFormat = 'yyyy-MM-dd HH:mm:ss'; $d.Width = 150
    $d.MinDate = (Get-Date).AddYears(-20); $d.MaxDate = (Get-Date).AddYears(1)
}
$hostFrom = New-Object System.Windows.Forms.ToolStripControlHost $dtpFrom
$hostTo = New-Object System.Windows.Forms.ToolStripControlHost $dtpTo
$ddSources = New-Object System.Windows.Forms.ToolStripDropDownButton 'Sources'
$ddSources.ForeColor = $theme.ControlForeground
$ddSources.DropDown.BackColor = $theme.PanelBackground
$sourceItems = @{}
foreach ($def in $sourceDefs) {
    $mi = New-MenuItem $def.Text
    $mi.CheckOnClick = $true; $mi.Checked = ($def.Key -in $Sources); $mi.ToolTipText = $def.Tip; $mi.Tag = $def.Key
    $sourceItems[$def.Key] = $mi
    [void]$ddSources.DropDownItems.Add($mi)
}
$miIncludeInfo = New-MenuItem 'Also collect ALL Information events (noisy)'
$miIncludeInfo.CheckOnClick = $true; $miIncludeInfo.Checked = [bool]$IncludeInformation
$miIncludeInfo.ToolTipText = 'Key informational events (reboots, failovers, SQL restarts, patching) are always collected.'
$lblMax = New-TsLabel 'Max events per log query:' -Muted
$cmbMax = New-Object System.Windows.Forms.ToolStripComboBox
$cmbMax.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown; $cmbMax.BackColor = $theme.ControlBackground; $cmbMax.ForeColor = $theme.ControlForeground
foreach ($v in 1000, 5000, 20000, 100000) { [void]$cmbMax.Items.Add([string]$v) }
$cmbMax.Text = [string]$MaxEventsPerQuery
[void]$ddSources.DropDownItems.AddRange(@((New-Object System.Windows.Forms.ToolStripSeparator), $miIncludeInfo, (New-Object System.Windows.Forms.ToolStripSeparator), $lblMax, $cmbMax))
$ddSources.DropDown.Add_Closing({ param($s, $e) if ($e.CloseReason -eq [System.Windows.Forms.ToolStripDropDownCloseReason]::ItemClicked) { $e.Cancel = $true } })
$btnCollect = New-TsButton ("$([char]0x25B6)  Collect") 'Collect events from the computers above (F5).'
$btnCollect.BackColor = $theme.AccentColor; $btnCollect.ForeColor = [System.Drawing.Color]::White; $btnCollect.Font = $uiFontBold
$btnCancel = New-TsButton 'Cancel'; $btnCancel.Enabled = $false
[void]$tsCollect.Items.AddRange(@((New-TsLabel 'Computers'), $txtComputers, $btnClusterNodes, (New-Object System.Windows.Forms.ToolStripSeparator),
        (New-TsLabel 'Range'), $cmbRange.Tag, (New-TsLabel 'From' -Muted), $hostFrom, (New-TsLabel 'To' -Muted), $hostTo,
        (New-Object System.Windows.Forms.ToolStripSeparator), $ddSources, (New-Object System.Windows.Forms.ToolStripSeparator), $btnCollect, $btnCancel))

# Filter bar: what is displayed
$tsFilter = New-ToolStrip
$tsFilter.BackColor = $theme.PanelBackground
$bullet = [char]0x25CF
$chkCrit = New-TsButton "$bullet Critical"; $chkErr = New-TsButton "$bullet Error"; $chkWarn = New-TsButton "$bullet Warning"; $chkInfo = New-TsButton "$bullet Info"
$i = 1
foreach ($b in $chkCrit, $chkErr, $chkWarn, $chkInfo) { $b.CheckOnClick = $true; $b.Checked = $true; $b.ForeColor = $levelColors[$i]; $b.ToolTipText = "Show / hide $($levelNames[$i]) events"; $i++ }
$cmbCategory = New-TsComboBox 165 @('All categories')
$cmbComputer = New-TsComboBox 140 @('All computers')
$cmbLanes = New-TsComboBox 195 @('Lanes: Category', 'Lanes: Computer', 'Lanes: Computer + Category', 'Lanes: Provider') 'What the swim lanes under the timeline are grouped by.'
$txtIds = New-TsTextBox 110 "Event IDs, comma/space separated. E.g. '1069 1135' or '-7036' to exclude."
$txtSearch = New-TsTextBox 210 'Search message, provider, description, computer and category (Ctrl+F).'
$btnClearFilter = New-TsButton 'Clear' 'Clear all filters (Ctrl+Shift+X)'
$btnResetZoom = New-TsButton 'Reset zoom' 'Show the whole collected range (Ctrl+0)'
$btnZoomOut = New-TsButton 'Zoom out' 'Back to the previous zoom level (Ctrl+- or right-click the chart)'
foreach ($b in $btnResetZoom, $btnZoomOut) { $b.Alignment = [System.Windows.Forms.ToolStripItemAlignment]::Right }
[void]$tsFilter.Items.AddRange(@($chkCrit, $chkErr, $chkWarn, $chkInfo, (New-Object System.Windows.Forms.ToolStripSeparator),
        $cmbCategory.Tag, $cmbComputer.Tag, $cmbLanes.Tag, (New-Object System.Windows.Forms.ToolStripSeparator),
        (New-TsLabel 'IDs' -Muted), $txtIds, (New-TsLabel 'Search' -Muted), $txtSearch, $btnClearFilter, $btnResetZoom, $btnZoomOut))
$cmbCategory.SelectedIndex = 0; $cmbComputer.SelectedIndex = 0; $cmbLanes.SelectedIndex = 0

# --- Timeline chart ---
$chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
$chart.Dock = [System.Windows.Forms.DockStyle]::Fill
$chart.BackColor = $theme.GridBackground
$chart.AntiAliasing = [System.Windows.Forms.DataVisualization.Charting.AntiAliasingStyles]::All
$caCounts = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea 'Counts'
$caLanes = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea 'Lanes'
foreach ($ca in $caCounts, $caLanes) {
    $ca.BackColor = $theme.GridBackground
    foreach ($ax in $ca.AxisX, $ca.AxisY) {
        $ax.LineColor = $theme.ChartLines; $ax.MajorGrid.LineColor = $theme.ChartLines; $ax.MajorTickMark.LineColor = $theme.ChartLines
        $ax.LabelStyle.ForeColor = $theme.ControlForeground; $ax.LabelStyle.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
    }
    $ca.AxisX.IntervalAutoMode = [System.Windows.Forms.DataVisualization.Charting.IntervalAutoMode]::VariableCount
    $ca.AxisX.MajorGrid.LineDashStyle = [System.Windows.Forms.DataVisualization.Charting.ChartDashStyle]::Dot
    $ca.Position.Auto = $false; $ca.Position.X = 0; $ca.Position.Width = 99
}
$caCounts.Position.Y = 13; $caCounts.Position.Height = 44
$caLanes.Position.Y = 57; $caLanes.Position.Height = 43
$caCounts.AxisX.LabelStyle.Enabled = $false
$caCounts.AxisY.Minimum = 0
$caCounts.AxisY.LabelStyle.Format = 'N0'
$caCounts.CursorX.IsUserSelectionEnabled = $true
$caCounts.CursorX.IntervalType = [System.Windows.Forms.DataVisualization.Charting.DateTimeIntervalType]::Seconds
$caCounts.CursorX.Interval = 1
$caCounts.CursorX.SelectionColor = [System.Drawing.Color]::FromArgb(90, 0, 122, 204)
$caCounts.CursorX.LineColor = $theme.AccentColor
$caCounts.AxisX.ScaleView.Zoomable = $false
$caLanes.AxisY.MajorGrid.Enabled = $false
$caLanes.AxisY.MajorTickMark.Enabled = $false
$caLanes.AlignWithChartArea = 'Counts'
$caLanes.AlignmentOrientation = [System.Windows.Forms.DataVisualization.Charting.AreaAlignmentOrientations]::Vertical
$caLanes.AlignmentStyle = [System.Windows.Forms.DataVisualization.Charting.AreaAlignmentStyles]::PlotPosition
$chart.ChartAreas.Add($caCounts); $chart.ChartAreas.Add($caLanes)

$legend = New-Object System.Windows.Forms.DataVisualization.Charting.Legend 'Legend'
$legend.Docking = [System.Windows.Forms.DataVisualization.Charting.Docking]::Top
$legend.Alignment = [System.Drawing.StringAlignment]::Far
$legend.BackColor = [System.Drawing.Color]::Transparent; $legend.ForeColor = $theme.ControlForeground
$legend.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
$legend.IsDockedInsideChartArea = $false
$chart.Legends.Add($legend)
$chartTitle = New-Object System.Windows.Forms.DataVisualization.Charting.Title
$chartTitle.ForeColor = $theme.ControlForeground; $chartTitle.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$chartTitle.Alignment = [System.Drawing.ContentAlignment]::TopLeft; $chartTitle.Docking = [System.Windows.Forms.DataVisualization.Charting.Docking]::Top
$chart.Titles.Add($chartTitle)
$emptyTitle = 'No events loaded.  Pick computers, a range and sources above and click Collect (F5) - or File > Open session to review an exported collection (you can also drag a .json file here).'
$chartTitle.Text = $emptyTitle

foreach ($lv in 1, 2, 3, 4) {
    $s = New-Object System.Windows.Forms.DataVisualization.Charting.Series "L$lv"
    $s.ChartArea = 'Counts'; $s.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::StackedColumn
    $s.Color = $levelColors[$lv]; $s.XValueType = [System.Windows.Forms.DataVisualization.Charting.ChartValueType]::DateTime
    $s.LegendText = $levelNames[$lv]; $s['PointWidth'] = '0.85'; $s.Legend = 'Legend'
    $chart.Series.Add($s)
}
foreach ($lv in 4, 3, 2, 1) {
    $s = New-Object System.Windows.Forms.DataVisualization.Charting.Series "S$lv"
    $s.ChartArea = 'Lanes'; $s.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Point
    $s.Color = [System.Drawing.Color]::FromArgb(220, $levelColors[$lv]); $s.MarkerStyle = [System.Windows.Forms.DataVisualization.Charting.MarkerStyle]::Circle
    $s.XValueType = [System.Windows.Forms.DataVisualization.Charting.ChartValueType]::DateTime; $s.IsVisibleInLegend = $false
    $chart.Series.Add($s)
}
$chartTips = New-Object System.Windows.Forms.ToolTip
$chartTips.SetToolTip($chart, 'Drag to zoom  |  click a bar to drill into it  |  click a dot to drill in and filter to that lane  |  right-click to zoom out')

# --- Grids, details and log ---
$dgvEvents = New-Object System.Windows.Forms.DataGridView
Set-GridStyle $dgvEvents
$dgvEvents.MultiSelect = $true
Add-GridColumn $dgvEvents 'Time' 'Time' 160 'yyyy-MM-dd HH:mm:ss.fff'
Add-GridColumn $dgvEvents 'Computer' 'Computer' 110
Add-GridColumn $dgvEvents 'Level' 'Level' 80
Add-GridColumn $dgvEvents 'Category' 'Category' 130
Add-GridColumn $dgvEvents 'Tag' 'Description' 210
Add-GridColumn $dgvEvents 'Id' 'Event ID' 70
Add-GridColumn $dgvEvents 'Provider' 'Provider' 180
Add-GridColumn $dgvEvents 'Summary' 'Message' 400 -Fill
$dgvEvents.DataSource = $script:View

$dgvSummary = New-Object System.Windows.Forms.DataGridView
Set-GridStyle $dgvSummary
$dgvSummary.MultiSelect = $false
Add-GridColumn $dgvSummary 'Count' 'Count' 65
Add-GridColumn $dgvSummary 'Level' 'Worst level' 90
Add-GridColumn $dgvSummary 'Category' 'Category' 130
Add-GridColumn $dgvSummary 'Provider' 'Provider' 180
Add-GridColumn $dgvSummary 'Id' 'Event ID' 70
Add-GridColumn $dgvSummary 'Tag' 'Description' 210
Add-GridColumn $dgvSummary 'First' 'First seen' 140 'yyyy-MM-dd HH:mm:ss'
Add-GridColumn $dgvSummary 'Last' 'Last seen' 140 'yyyy-MM-dd HH:mm:ss'
Add-GridColumn $dgvSummary 'Computers' 'Hosts' 55
Add-GridColumn $dgvSummary 'Sample' 'Sample message' 400 -Fill
$dgvSummary.DataSource = $script:SummaryView

$txtDetail = New-LogTextBox
$txtDetail.WordWrap = $true; $txtDetail.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$txtDetail.Text = 'Select an event to see its full details.'
$txtRunLog = New-LogTextBox
$txtRunLog.WordWrap = $false

$splitEvents = New-Object System.Windows.Forms.SplitContainer
$splitEvents.Dock = [System.Windows.Forms.DockStyle]::Fill; $splitEvents.Orientation = [System.Windows.Forms.Orientation]::Horizontal
$splitEvents.BackColor = $theme.FormBackground; $splitEvents.SplitterWidth = 5
$splitEvents.Panel1.Controls.Add($dgvEvents)
$pnlDetail = New-Object System.Windows.Forms.Panel
$pnlDetail.Dock = [System.Windows.Forms.DockStyle]::Fill; $pnlDetail.Padding = New-Object System.Windows.Forms.Padding(10, 8, 6, 4); $pnlDetail.BackColor = $theme.PanelBackground
$pnlDetail.Controls.Add($txtDetail)
$splitEvents.Panel2.Controls.Add($pnlDetail)

# Dark "tabs": a toolbar of toggle buttons over a content panel
$tsTabs = New-ToolStrip
$tsTabs.Padding = New-Object System.Windows.Forms.Padding(4, 2, 6, 0)
$tabEvents = New-TsButton 'Events'
$tabSummary = New-TsButton 'Top issues'
$tabLog = New-TsButton 'Collection log'
$lblSession = New-TsLabel '' -Muted
$lblSession.Alignment = [System.Windows.Forms.ToolStripItemAlignment]::Right
[void]$tsTabs.Items.AddRange(@($tabEvents, $tabSummary, $tabLog, $lblSession))
$pnlContent = New-Object System.Windows.Forms.Panel
$pnlContent.Dock = [System.Windows.Forms.DockStyle]::Fill; $pnlContent.BackColor = $theme.GridBackground
$pnlLog = New-Object System.Windows.Forms.Panel
$pnlLog.Dock = [System.Windows.Forms.DockStyle]::Fill; $pnlLog.Padding = New-Object System.Windows.Forms.Padding(10, 8, 6, 4); $pnlLog.BackColor = $theme.PanelBackground
$pnlLog.Controls.Add($txtRunLog)
$pnlContent.Controls.AddRange(@($splitEvents, $dgvSummary, $pnlLog))
$tabPages = @{ Events = @($tabEvents, $splitEvents); Summary = @($tabSummary, $dgvSummary); Log = @($tabLog, $pnlLog) }

$splitMain = New-Object System.Windows.Forms.SplitContainer
$splitMain.Dock = [System.Windows.Forms.DockStyle]::Fill; $splitMain.Orientation = [System.Windows.Forms.Orientation]::Horizontal
$splitMain.BackColor = $theme.FormBackground; $splitMain.SplitterWidth = 6
$splitMain.Panel1.Controls.Add($chart)
$splitMain.Panel2.Controls.Add($pnlContent)
$splitMain.Panel2.Controls.Add($tsTabs)

$ctxMenu = New-Object System.Windows.Forms.ContextMenuStrip
$ctxMenu.Renderer = $renderer
$miCopy = New-MenuItem 'Copy selected rows' ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::C)
$miSelectAll = New-MenuItem 'Select all'
$miOnlyId = New-MenuItem 'Show only this Event ID'
$miExcludeId = New-MenuItem 'Exclude this Event ID'
$miAround = New-MenuItem 'Zoom timeline to +/- 15 minutes around this event'
$miExport = New-MenuItem 'Export displayed events to CSV...'
$ctxMenu.Items.AddRange(@($miCopy, $miSelectAll, (New-Object System.Windows.Forms.ToolStripSeparator), $miOnlyId, $miExcludeId, $miAround, (New-Object System.Windows.Forms.ToolStripSeparator), $miExport))
$dgvEvents.ContextMenuStrip = $ctxMenu

# Status bar: message | level counts | progress
$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusBar.Renderer = $renderer; $statusBar.SizingGrip = $false; $statusBar.Font = $uiFont
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel 'Ready.'
$statusLabel.ForeColor = $theme.ControlForeground; $statusLabel.Spring = $true; $statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$countLabels = @{}
foreach ($lv in 1..4) {
    $l = New-Object System.Windows.Forms.ToolStripStatusLabel ''
    $l.ForeColor = $levelColors[$lv]; $l.Margin = New-Object System.Windows.Forms.Padding(10, 3, 0, 2)
    $countLabels[$lv] = $l
}
$progress = New-Object System.Windows.Forms.ToolStripProgressBar
$progress.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee; $progress.Visible = $false; $progress.Width = 140
[void]$statusBar.Items.AddRange(@($statusLabel, $countLabels[1], $countLabels[2], $countLabels[3], $countLabels[4], $progress))

# Fill control first, then top bars (last added docks first = top-most)
$mainForm.Controls.Add($splitMain)
$mainForm.Controls.Add($tsFilter)
$mainForm.Controls.Add($tsCollect)
$mainForm.Controls.Add($menu)
$mainForm.Controls.Add($statusBar)
$mainForm.MainMenuStrip = $menu

$pollTimer = New-Object System.Windows.Forms.Timer; $pollTimer.Interval = 500
$filterTimer = New-Object System.Windows.Forms.Timer; $filterTimer.Interval = 350

#---- Functions ----
function Update-StatusBar([string]$Text, [switch]$ErrorState) {
    $statusLabel.Text = $Text
    $statusLabel.ForeColor = if ($ErrorState) { [System.Drawing.Color]::OrangeRed } else { $theme.ControlForeground }
    $statusBar.Refresh()
}

function Show-Tab([string]$Name) {
    foreach ($k in $tabPages.Keys) {
        $on = ($k -eq $Name)
        $tabPages[$k][0].Checked = $on
        $tabPages[$k][0].Font = if ($on) { $uiFontBold } else { $uiFont }
        $tabPages[$k][1].Visible = $on
    }
    $script:CurrentTab = $Name
}

function Get-SelectedSources { @($sourceDefs | Where-Object { $sourceItems[$_.Key].Checked } | ForEach-Object { $_.Key }) }
function Update-SourcesButton {
    $n = @(Get-SelectedSources).Count
    $ddSources.Text = "Sources ($n of $($sourceDefs.Count))" + $(if ($miIncludeInfo.Checked) { ' + all info' } else { '' })
}

function Set-RangeFromPreset {
    $tf = $timeFrames[$cmbRange.SelectedIndex]
    if ($tf.Hours -le 0) { return }
    $script:SettingRange = $true
    $now = Get-Date
    $dtpTo.Value = $now; $dtpFrom.Value = $now.AddHours(-$tf.Hours)
    $script:SettingRange = $false
}
function Set-CustomRange([datetime]$From, [datetime]$To) {
    $script:SettingRange = $true
    $cmbRange.SelectedIndex = $timeFrames.Count - 1
    if ($From -lt $dtpFrom.MinDate) { $From = $dtpFrom.MinDate }
    if ($To -gt $dtpTo.MaxDate) { $dtpTo.MaxDate = $To.AddYears(1); $dtpFrom.MaxDate = $dtpTo.MaxDate }
    $dtpFrom.Value = $From; $dtpTo.Value = $To
    $script:SettingRange = $false
}

function ConvertTo-FilterLiteral([string]$s) { $s -replace "'", "''" }
function ConvertTo-LikeLiteral([string]$s) { (ConvertTo-FilterLiteral $s) -replace '([\[\]\*%])', '[$1]' }
function ConvertTo-DateLiteral([datetime]$d) { '#' + $d.ToString('MM/dd/yyyy HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + '#' }

function Get-RowFilter([switch]$NoTime) {
    $parts = New-Object System.Collections.Generic.List[string]
    $levels = @()
    if ($chkCrit.Checked) { $levels += 1 }; if ($chkErr.Checked) { $levels += 2 }; if ($chkWarn.Checked) { $levels += 3 }; if ($chkInfo.Checked) { $levels += 4 }
    if ($levels.Count -eq 0) { $parts.Add('LevelNum = -1') } elseif ($levels.Count -lt 4) { $parts.Add("LevelNum IN ($($levels -join ','))") }
    if ($cmbCategory.SelectedIndex -gt 0) { $parts.Add("Category = '$(ConvertTo-FilterLiteral $cmbCategory.SelectedItem)'") }
    if ($cmbComputer.SelectedIndex -gt 0) { $parts.Add("Computer = '$(ConvertTo-FilterLiteral $cmbComputer.SelectedItem)'") }
    $inc = @(); $exc = @()
    foreach ($tok in ($txtIds.Text -split '[,;\s]+' | Where-Object { $_ })) {
        if ($tok -match '^-(\d+)$') { $exc += [int]$Matches[1] } elseif ($tok -match '^\d+$') { $inc += [int]$tok }
    }
    if ($inc.Count) { $parts.Add("Id IN ($($inc -join ','))") }
    if ($exc.Count) { $parts.Add("Id NOT IN ($($exc -join ','))") }
    $q = $txtSearch.Text.Trim()
    if ($q) { $l = ConvertTo-LikeLiteral $q; $parts.Add("(Message LIKE '%$l%' OR Provider LIKE '%$l%' OR Tag LIKE '%$l%' OR Computer LIKE '%$l%' OR Category LIKE '%$l%')") }
    if (-not $NoTime -and $script:ViewStart) {
        $parts.Add("Time >= $(ConvertTo-DateLiteral $script:ViewStart) AND Time < $(ConvertTo-DateLiteral $script:ViewEnd)")
    }
    return ($parts -join ' AND ')
}

function Get-LaneKey($Row) {
    switch ($cmbLanes.SelectedIndex) {
        1 { return [string]$Row['Computer'] }
        2 { return "$($Row['Computer']) | $($Row['Category'])" }
        3 { return [string]$Row['Provider'] }
        default { return [string]$Row['Category'] }
    }
}

function Format-Span([timespan]$ts) {
    if ($ts.TotalDays -ge 1) { return '{0:N1} days' -f $ts.TotalDays }
    if ($ts.TotalHours -ge 1) { return '{0:N1} hours' -f $ts.TotalHours }
    if ($ts.TotalMinutes -ge 1) { return '{0:N0} minutes' -f $ts.TotalMinutes }
    return '{0:N0} seconds' -f $ts.TotalSeconds
}

# Lay out the two chart areas: a fixed pixel band for title + legend, lanes get more room when there are many of them
function Set-ChartLayout {
    $h = [math]::Max(200, $chart.Height)
    $topPct = [math]::Min(30, [math]::Ceiling(58 * 100 / $h))
    $lanePct = [math]::Min(62, [math]::Max(28, 10 + 4 * $script:LaneCount))
    $lanePct = [math]::Min($lanePct, 100 - $topPct - 20)
    $caCounts.Position.Y = $topPct; $caCounts.Position.Height = 100 - $topPct - $lanePct
    $caLanes.Position.Y = 100 - $lanePct; $caLanes.Position.Height = $lanePct
}

# Single pass over the visible rows: builds the stacked counts, swim-lane dots, markers and the Top issues summary.
function Update-Visuals {
    foreach ($s in $chart.Series) { $s.Points.Clear() }
    $caCounts.AxisX.StripLines.Clear(); $caLanes.AxisX.StripLines.Clear(); $caLanes.AxisY.CustomLabels.Clear(); $legend.CustomItems.Clear()
    $script:SummaryTable.Rows.Clear()
    foreach ($lv in 1..4) { $countLabels[$lv].Text = '' }
    if (-not $script:ViewStart) { $chartTitle.Text = $emptyTitle; return }

    $bucketSec = $script:BucketSteps | Where-Object { ($script:ViewEnd - $script:ViewStart).TotalSeconds / $_ -le 120 } | Select-Object -First 1
    if (-not $bucketSec) { $bucketSec = 604800 }
    $bt = [long]$bucketSec * 10000000L
    $t0 = $script:ViewStart.Ticks; $t1 = $script:ViewEnd.Ticks
    $cs = New-Object DateTime ($t0 - ($t0 % $bt))
    $rem = $t1 % $bt; if ($rem -ne 0) { $t1 += $bt - $rem }
    $ce = New-Object DateTime $t1
    $n = [int][math]::Max(1, [math]::Round(($ce.Ticks - $cs.Ticks) / $bt))
    $script:ChartStart = $cs; $script:BucketTicks = $bt; $script:BucketCount = $n

    $cnt = @{}; foreach ($lv in 1..4) { $cnt[$lv] = New-Object 'int[]' $n }
    $levelTotals = New-Object 'int[]' 5
    $cells = @{}; $laneCounts = @{}; $groups = @{}
    $markers = New-Object System.Collections.Generic.List[object]
    $total = 0
    foreach ($drv in $script:View) {
        $r = $drv.Row
        $t = [datetime]$r['Time']
        $b = [int][math]::Floor(($t.Ticks - $cs.Ticks) / $bt)
        if ($b -lt 0 -or $b -ge $n) { continue }
        $lv = [int]$r['LevelNum']
        $cnt[$lv][$b]++
        $levelTotals[$lv]++
        $total++
        $lane = Get-LaneKey $r
        $laneCounts[$lane] = 1 + [int]$laneCounts[$lane]
        $ck = "$b|$lane"
        $cell = $cells[$ck]
        if (-not $cell) { $cell = @{ B = $b; Lane = $lane; N = 0; Worst = 4; C = (New-Object 'int[]' 5); Top = @{} }; $cells[$ck] = $cell }
        $cell.N++; $cell.C[$lv]++; if ($lv -lt $cell.Worst) { $cell.Worst = $lv }
        $tag = [string]$r['Tag']
        $label = "$($r['Provider']) $($r['Id'])" + $(if ($tag) { " ($tag)" } else { '' })
        $cell.Top[$label] = 1 + [int]$cell.Top[$label]

        # Log-file entries without an error number (Id 0) are grouped by their description instead
        $gk = "$($r['Category'])|$($r['Provider'])|$($r['Id'])" + $(if ([int]$r['Id'] -eq 0) { "|$tag" } else { '' })
        $g = $groups[$gk]
        if (-not $g) { $g = @{ Count = 0; Worst = 4; Cat = $r['Category']; Prov = $r['Provider']; Id = $r['Id']; Tag = $tag; First = $t; Last = $t; Comp = @{}; Sample = $r['Summary'] }; $groups[$gk] = $g }
        $g.Count++; if ($lv -lt $g.Worst) { $g.Worst = $lv }; if ($t -lt $g.First) { $g.First = $t }; if ($t -gt $g.Last) { $g.Last = $t }; $g.Comp[[string]$r['Computer']] = 1

        $mk = [string]$r['Marker']
        if ($mk) { $markers.Add(@{ Time = $t; Kind = $mk; Computer = [string]$r['Computer']; Tag = $tag }) }
    }
    foreach ($lv in 1..4) { $countLabels[$lv].Text = '{0} {1:N0} {2}' -f $bullet, $levelTotals[$lv], $levelNames[$lv] }

    # Stacked counts
    foreach ($lv in 1..4) {
        $s = $chart.Series["L$lv"]
        $s.Enabled = ($lv -ne 4 -or $chkInfo.Checked)
        $arr = $cnt[$lv]
        for ($b = 0; $b -lt $n; $b++) {
            $bs = $cs.AddTicks($b * $bt)
            $idx = $s.Points.AddXY($bs.AddTicks([long]($bt / 2)).ToOADate(), $arr[$b])
            if ($arr[$b] -gt 0) { $s.Points[$idx].ToolTip = '{0:dd MMM HH:mm:ss} - {1:HH:mm:ss}{2}{3}: {4:N0}' -f $bs, $bs.AddTicks($bt), "`n", $levelNames[$lv], $arr[$b] }
        }
    }

    # Swim lanes (max 30, the rest grouped as "(other)")
    $laneList = @($laneCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { $_.Key })
    if ($laneList.Count -gt 30) {
        $keep = @{}; $laneList[0..28] | ForEach-Object { $keep[$_] = $true }
        foreach ($k in @($cells.Keys)) {
            $c = $cells[$k]
            if ($keep.ContainsKey($c.Lane)) { continue }
            $cells.Remove($k)
            $ok = "$($c.B)|(other)"; $o = $cells[$ok]
            if (-not $o) { $o = @{ B = $c.B; Lane = '(other)'; N = 0; Worst = 4; C = (New-Object 'int[]' 5); Top = @{} }; $cells[$ok] = $o }
            $o.N += $c.N; if ($c.Worst -lt $o.Worst) { $o.Worst = $c.Worst }; for ($i = 1; $i -le 4; $i++) { $o.C[$i] += $c.C[$i] }
            foreach ($tk in $c.Top.Keys) { $o.Top[$tk] = $c.Top[$tk] + [int]$o.Top[$tk] }
        }
        $laneList = @($laneList[0..28]) + '(other)'
    }
    $laneList = @($laneList | Where-Object { $_ -ne '(other)' } | Sort-Object) + @($laneList | Where-Object { $_ -eq '(other)' })
    $script:LaneNames = $laneList
    $nl = [math]::Max(1, $laneList.Count)
    $laneIndex = @{}; for ($i = 0; $i -lt $laneList.Count; $i++) { $laneIndex[$laneList[$i]] = $nl - 1 - $i }
    foreach ($c in $cells.Values) {
        $y = $laneIndex[$c.Lane]
        if ($null -eq $y) { continue }
        $s = $chart.Series["S$($c.Worst)"]
        $idx = $s.Points.AddXY($cs.AddTicks([long]($c.B * $bt + $bt / 2)).ToOADate(), $y)
        $p = $s.Points[$idx]
        $p.MarkerSize = [int][math]::Min(20, 6 + 4 * [math]::Log10($c.N))
        $top = ($c.Top.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Value) x $($_.Key)" }) -join "`n"
        $p.ToolTip = ("{0}  {1:dd MMM HH:mm}`n{2:N0} events ({3} critical, {4} error, {5} warning, {6} info)`n{7}" -f $c.Lane, $cs.AddTicks($c.B * $bt), $c.N, $c.C[1], $c.C[2], $c.C[3], $c.C[4], $top).Replace('#', '')
        $p.Tag = "$($c.B)|$($c.Lane)"
    }
    for ($i = 0; $i -lt $laneList.Count; $i++) {
        $y = $nl - 1 - $i; $name = $laneList[$i]
        if ($name.Length -gt 34) { $name = $name.Substring(0, 33) + '...' }
        [void]$caLanes.AxisY.CustomLabels.Add($y - 0.5, $y + 0.5, $name)
    }
    $caLanes.AxisY.Minimum = -0.5; $caLanes.AxisY.Maximum = $nl - 0.5; $caLanes.AxisY.Interval = 1

    $script:LaneCount = $nl
    Set-ChartLayout

    foreach ($ca in $caCounts, $caLanes) { $ca.AxisX.Minimum = $cs.ToOADate(); $ca.AxisX.Maximum = $ce.ToOADate() }
    $span = $ce - $cs
    $caLanes.AxisX.LabelStyle.Format = if ($bucketSec -ge 86400) { 'dd MMM' } elseif ($span.TotalHours -gt 24) { 'dd MMM HH:mm' } elseif ($bucketSec -lt 60) { 'HH:mm:ss' } else { 'HH:mm' }

    # Markers: reboots, SQL restarts, failovers... (de-duplicated per computer + kind; hover for details)
    $gap = [math]::Max(300, $bucketSec)
    $last = @{}; $shown = New-Object System.Collections.Generic.List[object]
    foreach ($m in ($markers | Sort-Object { $_.Time })) {
        $k = "$($m.Computer)|$($m.Kind)"
        if ($last.ContainsKey($k) -and ($m.Time - $last[$k]).TotalSeconds -lt $gap) { continue }
        $last[$k] = $m.Time; $shown.Add($m)
    }
    $kindsShown = @{}
    foreach ($m in $shown) {
        $color = $markerColors[$m.Kind]; if (-not $color) { $color = [System.Drawing.Color]::Gray }
        $kindsShown[$m.Kind] = $color
        foreach ($ca in $caCounts, $caLanes) {
            $sl = New-Object System.Windows.Forms.DataVisualization.Charting.StripLine
            $sl.IntervalOffset = $m.Time.ToOADate(); $sl.StripWidth = 0
            $sl.BorderColor = $color; $sl.BorderWidth = 2; $sl.BorderDashStyle = [System.Windows.Forms.DataVisualization.Charting.ChartDashStyle]::Dash
            $sl.ToolTip = ('{0:yyyy-MM-dd HH:mm:ss}  {1}  {2}' -f $m.Time, $m.Computer, $(if ($m.Tag) { $m.Tag } else { $m.Kind })).Replace('#', '')
            $ca.AxisX.StripLines.Add($sl)
        }
    }
    foreach ($k in $kindsShown.Keys) {
        $li = New-Object System.Windows.Forms.DataVisualization.Charting.LegendItem
        $li.Name = $k; $li.ImageStyle = [System.Windows.Forms.DataVisualization.Charting.LegendImageStyle]::Line
        $li.Color = $kindsShown[$k]; $li.BorderWidth = 2; $li.BorderDashStyle = [System.Windows.Forms.DataVisualization.Charting.ChartDashStyle]::Dash
        $legend.CustomItems.Add($li)
    }

    $chartTitle.Text = ('{0:N0} events   {1:ddd dd MMM HH:mm} - {2:ddd dd MMM HH:mm}  ({3}, {4} per bar){5}' -f
        $total, $script:ViewStart, $script:ViewEnd, (Format-Span ($script:ViewEnd - $script:ViewStart)), (Format-Span ([timespan]::FromSeconds($bucketSec))),
        $(if ($script:ZoomStack.Count) { '   [zoomed - right-click or Ctrl+- to zoom out]' } else { '' }))

    # Top issues
    $script:SummaryTable.BeginLoadData()
    foreach ($g in $groups.Values) {
        [void]$script:SummaryTable.LoadDataRow([object[]]@($g.Count, $levelNames[$g.Worst], $g.Worst, $g.Cat, $g.Prov, $g.Id, $g.Tag, $g.First, $g.Last, $g.Comp.Count, $g.Sample), $true)
    }
    $script:SummaryTable.EndLoadData()
}

function Update-View {
    if ($script:SuspendFilter) { return }
    try {
        $mainForm.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $script:View.RowFilter = Get-RowFilter
        Update-Visuals
        if ($script:Table.Rows.Count -gt 0) { Update-StatusBar ('Showing {0:N0} of {1:N0} events' -f $script:View.Count, $script:Table.Rows.Count) }
        $tabSummary.Text = "Top issues ($($script:SummaryTable.Rows.Count))"
        $tabEvents.Text = 'Events ({0:N0})' -f $script:View.Count
    } catch {
        Update-StatusBar "Filter error: $($_.Exception.Message)" -ErrorState
    } finally { $mainForm.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Set-ViewWindow([datetime]$From, [datetime]$To, [switch]$NoPush) {
    if ($To -le $From) { return }
    if (-not $NoPush -and $script:ViewStart) { $script:ZoomStack.Push(@($script:ViewStart, $script:ViewEnd)) }
    $script:ViewStart = $From; $script:ViewEnd = $To
    Update-View
}
function Undo-Zoom {
    if ($script:ZoomStack.Count -gt 0) { $w = $script:ZoomStack.Pop(); Set-ViewWindow $w[0] $w[1] -NoPush }
}
function Reset-Zoom {
    if (-not $script:CollectStart) { return }
    $script:ZoomStack.Clear()
    Set-ViewWindow $script:CollectStart $script:CollectEnd -NoPush
}
function Set-ZoomToBucket([int]$Bucket) {
    $from = $script:ChartStart.AddTicks([long]$Bucket * $script:BucketTicks)
    $to = $from.AddTicks($script:BucketTicks)
    if ($to -gt $script:ViewEnd -and $from -lt $script:ViewEnd) { $to = $script:ViewEnd }
    if ($from -lt $script:ViewStart -and $to -gt $script:ViewStart) { $from = $script:ViewStart }
    if ($from -eq $script:ViewStart -and $to -eq $script:ViewEnd) { return }
    Set-ViewWindow $from $to
}

function Set-ComboItems($Combo, [string]$AllText, [string[]]$Items) {
    $current = $Combo.SelectedItem
    $Combo.Items.Clear(); [void]$Combo.Items.Add($AllText)
    foreach ($i in $Items) { [void]$Combo.Items.Add($i) }
    $idx = if ($current) { $Combo.Items.IndexOf($current) } else { 0 }
    $Combo.SelectedIndex = [math]::Max(0, $idx)
}
function Select-ComboItem($Combo, [string]$Value) {
    $i = if ($Value) { $Combo.Items.IndexOf($Value) } else { 0 }
    if ($i -ge 0) { $Combo.SelectedIndex = $i }
}

function Set-CollectingState([bool]$Busy) {
    foreach ($c in $btnCollect, $txtComputers, $btnClusterNodes, $cmbRange, $hostFrom, $hostTo, $ddSources, $miOpen, $miAdd, $miSave, $miCollect) { $c.Enabled = -not $Busy }
    $btnCancel.Enabled = $Busy
    $progress.Visible = $Busy
}

function Get-DistinctValues([string]$Column) {
    @($script:Table.DefaultView.ToTable($true, $Column).Rows | ForEach-Object { [string]$_[0] } | Where-Object { $_ } | Sort-Object)
}

function Import-CollectedEvents($Events, [switch]$Append) {
    $script:SuspendFilter = $true
    $script:Table.BeginLoadData()
    $seenKeys = @{}
    if ($Append) {
        foreach ($r in $script:Table.Rows) { $seenKeys["$($r['Computer'])|$($r['LogName'])|$($r['RecordId'])|$(([datetime]$r['Time']).Ticks)|$($r['Id'])"] = $true }
    } else { $script:Table.Rows.Clear() }
    $key = $script:Table.Rows.Count
    $skipped = 0
    foreach ($e in $Events) {
        $time = [datetime]$e.Time
        if ($Append) {
            $k = "$($e.Computer)|$($e.LogName)|$($e.RecordId)|$($time.Ticks)|$($e.Id)"
            if ($seenKeys.ContainsKey($k)) { $skipped++; continue }
            $seenKeys[$k] = $true
        }
        $msg = [string]$e.Message
        $summary = $msg -replace '\s+', ' '
        if ($summary.Length -gt 400) { $summary = $summary.Substring(0, 400) + '...' }
        [void]$script:Table.LoadDataRow([object[]]@($key, $time, [string]$e.Computer, [string]$e.Level, [int]$e.LevelNum, [string]$e.Category,
                [string]$e.Tag, [string]$e.Marker, [int]$e.Id, [string]$e.Provider, [string]$e.LogName, [string]$e.Source, [long]$e.RecordId, $summary, $msg), $true)
        $key++
    }
    $script:Table.EndLoadData()
    Set-ComboItems $cmbCategory 'All categories' (Get-DistinctValues 'Category')
    Set-ComboItems $cmbComputer 'All computers' (Get-DistinctValues 'Computer')
    $script:SuspendFilter = $false
    $script:ZoomStack.Clear()
    $script:ViewStart = $script:CollectStart; $script:ViewEnd = $script:CollectEnd
    Update-View
    return $skipped
}

function Set-RunLog([string[]]$Lines) {
    $script:RunLog = @($Lines)
    $txtRunLog.Lines = $script:RunLog
    $problems = @($script:RunLog | Where-Object { $_ -match 'WARNING|ERROR|failed|not accessible|cannot|not readable' })
    $tabLog.Text = if ($problems.Count) { "Collection log ($($problems.Count) warnings)" } else { 'Collection log' }
    $tabLog.ForeColor = if ($problems.Count) { $levelColors[3] } else { $theme.ControlForeground }
}

function Get-DisplayedRows([switch]$IgnoreZoom) {
    $filter = Get-RowFilter -NoTime:$IgnoreZoom
    return , $script:Table.Select($filter, 'Time ASC')
}

function Show-Error([string]$Title, [string]$Text) {
    Update-StatusBar $Text -ErrorState
    [void][System.Windows.Forms.MessageBox]::Show($mainForm, $Text, $Title, 'OK', 'Error')
}

function Update-SessionBanner {
    if ($script:SessionFiles.Count) {
        $names = ($script:SessionFiles | ForEach-Object { Split-Path $_ -Leaf }) -join ', '
        $lblSession.Text = "Reviewing saved session: $names"
        $lblSession.ToolTipText = ($script:SessionFiles -join "`n")
        $mainForm.Text = "Windows Event Log Investigator - $names"
    } else {
        $lblSession.Text = if ($script:CollectedAt) { 'Live collection {0:yyyy-MM-dd HH:mm} from {1}' -f $script:CollectedAt, ($script:Computers -join ', ') } else { '' }
        $lblSession.ToolTipText = ''
        $mainForm.Text = 'Windows Event Log Investigator'
    }
}

#---- Sessions ----
function Get-ViewState {
    $levels = @(); if ($chkCrit.Checked) { $levels += 1 }; if ($chkErr.Checked) { $levels += 2 }; if ($chkWarn.Checked) { $levels += 3 }; if ($chkInfo.Checked) { $levels += 4 }
    [ordered]@{
        viewStart = $script:ViewStart; viewEnd = $script:ViewEnd; levels = $levels
        category = $(if ($cmbCategory.SelectedIndex -gt 0) { [string]$cmbCategory.SelectedItem } else { '' })
        computer = $(if ($cmbComputer.SelectedIndex -gt 0) { [string]$cmbComputer.SelectedItem } else { '' })
        lanes = [string]$cmbLanes.SelectedItem; eventIds = $txtIds.Text; search = $txtSearch.Text; tab = $script:CurrentTab
    }
}

function Restore-ViewState($View) {
    if (-not ($View -is [System.Collections.IDictionary])) { return }
    $script:SuspendFilter = $true
    $levels = @(Get-JsonValue $View 'levels' @(1, 2, 3, 4) | ForEach-Object { [int]$_ })
    $chkCrit.Checked = 1 -in $levels; $chkErr.Checked = 2 -in $levels; $chkWarn.Checked = 3 -in $levels; $chkInfo.Checked = 4 -in $levels
    Select-ComboItem $cmbCategory (Get-JsonValue $View 'category' '')
    Select-ComboItem $cmbComputer (Get-JsonValue $View 'computer' '')
    $lanes = Get-JsonValue $View 'lanes' ''; if ($lanes) { Select-ComboItem $cmbLanes $lanes }
    $txtIds.Text = Get-JsonValue $View 'eventIds' ''
    $txtSearch.Text = Get-JsonValue $View 'search' ''
    $filterTimer.Stop()
    $script:SuspendFilter = $false
    $vs = ConvertFrom-SessionDate (Get-JsonValue $View 'viewStart'); $ve = ConvertFrom-SessionDate (Get-JsonValue $View 'viewEnd')
    if ($vs -and $ve -and $ve -gt $vs -and ($vs -ne $script:CollectStart -or $ve -ne $script:CollectEnd)) {
        $script:ZoomStack.Clear(); $script:ZoomStack.Push(@($script:CollectStart, $script:CollectEnd))
        $script:ViewStart = $vs; $script:ViewEnd = $ve
    }
    Update-View
    $tab = Get-JsonValue $View 'tab' ''; if ($tab -and $tabPages.ContainsKey($tab)) { Show-Tab $tab }
}

function Open-SessionFiles([string[]]$Paths, [switch]$Append) {
    if (-not $Paths) { return }
    if ($script:Jobs.Count) { Show-Error 'Open session' 'Wait for the current collection to finish (or cancel it) first.'; return }
    $mainForm.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $loaded = @()
        foreach ($p in $Paths) { Update-StatusBar "Reading $(Split-Path $p -Leaf)..."; $loaded += Read-InvestigationSession $p }
        $events = New-Object System.Collections.Generic.List[object]
        $log = New-Object System.Collections.Generic.List[string]
        if ($Append) { foreach ($l in $script:RunLog) { $log.Add($l) } }
        $starts = @(); $ends = @(); $comps = @(); $srcs = @(); $offsets = @()
        if ($Append -and $script:CollectStart) { $starts += $script:CollectStart; $ends += $script:CollectEnd; $comps += $script:Computers; $srcs += $script:CollectSources }
        foreach ($s in $loaded) {
            $doc = $s.Document; $col = Get-JsonValue $doc 'collection'
            $starts += ConvertFrom-SessionDate (Get-JsonValue $col 'start'); $ends += ConvertFrom-SessionDate (Get-JsonValue $col 'end')
            $comps += @(Get-JsonValue $col 'computers' @() | ForEach-Object { [string]$_ })
            $srcs += @(Get-JsonValue $col 'sources' @() | ForEach-Object { [string]$_ })
            $off = Get-JsonValue $col 'utcOffsetMinutes'; if ($null -ne $off) { $offsets += [int]$off }
            $log.Add(('==== Session {0}: exported {1} from {2} by {3} ====' -f (Split-Path $s.Path -Leaf), (ConvertFrom-SessionDate (Get-JsonValue $doc 'exportedAt')),
                    (Get-JsonValue $doc 'exportedFrom' '?'), (Get-JsonValue $doc 'exportedBy' '?')))
            foreach ($l in @(Get-JsonValue $doc 'runLog' @())) { $log.Add([string]$l) }
            $events.AddRange([object[]]$s.Events)
        }
        $script:CollectStart = ($starts | Measure-Object -Minimum).Minimum
        $script:CollectEnd = ($ends | Measure-Object -Maximum).Maximum
        $script:Computers = @($comps | Sort-Object -Unique)
        $script:CollectSources = @($srcs | Sort-Object -Unique)
        $first = Get-JsonValue $loaded[0].Document 'collection'
        $script:CollectedAt = ConvertFrom-SessionDate (Get-JsonValue $first 'collectedAt')
        $script:CollectedOn = Get-JsonValue $first 'collectedOn'
        $script:CollectIncludeInfo = [bool](Get-JsonValue $first 'includeInformation' $false)
        $script:CollectMax = [int](Get-JsonValue $first 'maxEventsPerQuery' $MaxEventsPerQuery)
        $script:UtcOffsetMinutes = if ($offsets) { $offsets[0] } else { $null }
        $previous = @(if ($Append) { $script:SessionFiles })
        $script:SessionFiles = @($previous + @($Paths) | Select-Object -Unique)

        # Reflect the loaded collection in the collection bar so it can be re-run against the servers if they are reachable
        $txtComputers.Text = $script:Computers -join ', '
        Set-CustomRange $script:CollectStart $script:CollectEnd
        foreach ($def in $sourceDefs) { $sourceItems[$def.Key].Checked = ($def.Key -in $script:CollectSources) }
        $miIncludeInfo.Checked = $script:CollectIncludeInfo; $cmbMax.Text = [string]$script:CollectMax
        Update-SourcesButton

        Set-RunLog $log.ToArray()
        $skipped = Import-CollectedEvents $events -Append:$Append
        if (-not $Append -and $loaded.Count -eq 1) { Restore-ViewState (Get-JsonValue $loaded[0].Document 'view') }
        Update-SessionBanner
        $msg = 'Loaded {0:N0} events from {1} session file(s)' -f ($events.Count - $skipped), $loaded.Count
        if ($skipped) { $msg += " ($skipped duplicates skipped)" }
        $localOffset = [int][TimeZoneInfo]::Local.GetUtcOffset($script:CollectStart).TotalMinutes
        if ($null -ne $script:UtcOffsetMinutes -and $script:UtcOffsetMinutes -ne $localOffset) {
            $msg += '  |  times are the source server''s local time (UTC{0}{1:hh\:mm})' -f $(if ($script:UtcOffsetMinutes -lt 0) { '-' } else { '+' }), [timespan]::FromMinutes([math]::Abs($script:UtcOffsetMinutes))
        }
        Update-StatusBar $msg
    } catch {
        Show-Error 'Open session' "Could not open session: $($_.Exception.Message)"
    } finally { $mainForm.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Save-SessionFile {
    if ($script:Table.Rows.Count -eq 0 -and -not $script:RunLog) { Update-StatusBar 'Nothing to save yet - collect or open some events first.'; return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'Event Log Investigator session (*.json)|*.json'; $dlg.Title = 'Save session (all events, collection log, filters and zoom)'
    $dlg.FileName = Get-SessionFileName $script:Computers
    if ($dlg.ShowDialog($mainForm) -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $mainForm.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $collection = [ordered]@{
            start = $script:CollectStart; end = $script:CollectEnd; computers = $script:Computers; sources = $script:CollectSources
            includeInformation = $script:CollectIncludeInfo; maxEventsPerQuery = $script:CollectMax
            collectedAt = $script:CollectedAt; collectedOn = $script:CollectedOn
            utcOffsetMinutes = $(if ($null -ne $script:UtcOffsetMinutes) { $script:UtcOffsetMinutes } elseif ($script:CollectStart) { [int][TimeZoneInfo]::Local.GetUtcOffset($script:CollectStart).TotalMinutes } else { $null })
        }
        Export-InvestigationSession -Rows $script:Table.Select('', 'Time ASC') -Path $dlg.FileName -Collection $collection -View (Get-ViewState) -RunLog $script:RunLog
        $size = (Get-Item $dlg.FileName).Length / 1MB
        Update-StatusBar ('Session saved: {0} ({1:N0} events, {2:N1} MB)' -f $dlg.FileName, $script:Table.Rows.Count, $size)
    } catch { Show-Error 'Save session' "Could not save session: $($_.Exception.Message)" }
    finally { $mainForm.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Select-SessionFiles([string]$Title) {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'Event Log Investigator session (*.json)|*.json|All files (*.*)|*.*'; $dlg.Multiselect = $true; $dlg.Title = $Title
    if ($dlg.ShowDialog($mainForm) -eq [System.Windows.Forms.DialogResult]::OK) { return , $dlg.FileNames }
    return $null
}

#---- Exports ----
function Save-DisplayedCsv {
    $rows = Get-DisplayedRows
    if ($rows.Count -eq 0) { Update-StatusBar 'No data to export.'; return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'; $dlg.Title = 'Export displayed events'
    $dlg.FileName = "EventLogInvestigation_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog($mainForm) -eq [System.Windows.Forms.DialogResult]::OK) {
        try { Export-EventCsv $rows $dlg.FileName; Update-StatusBar "$($rows.Count) events exported to $($dlg.FileName)" }
        catch { Show-Error 'Export' "Error exporting data: $($_.Exception.Message)" }
    }
}
function Open-DisplayedInExcel {
    $rows = Get-DisplayedRows
    if ($rows.Count -eq 0) { Update-StatusBar 'No data to export.'; return }
    $path = Join-Path $env:TEMP "EventLogInvestigation_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    try { Export-EventCsv $rows $path; Invoke-Item $path; Update-StatusBar "Opened $path" }
    catch { Show-Error 'Export' "Error exporting or opening data: $($_.Exception.Message)" }
}
function Save-HtmlReport {
    if ($script:Table.Rows.Count -eq 0) { Update-StatusBar 'Collect or open some events first.'; return }
    $rows = Get-DisplayedRows -IgnoreZoom
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'HTML report (*.html)|*.html'; $dlg.Title = 'Save interactive HTML report'
    $dlg.FileName = "EventLogInvestigation_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    if ($dlg.ShowDialog($mainForm) -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $mainForm.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            New-HtmlReport -Rows $rows -Path $dlg.FileName -Start $script:CollectStart -End $script:CollectEnd -Computers $script:Computers -RunLog $script:RunLog
            Update-StatusBar "HTML report saved to $($dlg.FileName)"
            Invoke-Item $dlg.FileName
        } catch { Show-Error 'HTML report' "Error creating report: $($_.Exception.Message)" }
        finally { $mainForm.Cursor = [System.Windows.Forms.Cursors]::Default }
    }
}

#---- Collection ----
function Start-Collection {
    if (-not $btnCollect.Enabled) { return }
    $computers = @($txtComputers.Text -split '[,;\s]+' | Where-Object { $_ } | Select-Object -Unique)
    if (-not $computers) { $computers = @($env:COMPUTERNAME); $txtComputers.Text = $env:COMPUTERNAME }
    if ($timeFrames[$cmbRange.SelectedIndex].Hours -gt 0) { Set-RangeFromPreset }
    $from = $dtpFrom.Value; $to = $dtpTo.Value
    if ($from -ge $to) { Show-Error 'Time range' "'From' must be earlier than 'To'."; return }
    $srcs = Get-SelectedSources
    if (-not $srcs) { Show-Error 'Sources' 'Select at least one source to collect (Sources drop-down).'; return }
    $max = 0; if (-not [int]::TryParse($cmbMax.Text, [ref]$max) -or $max -lt 100) { $max = 5000; $cmbMax.Text = '5000' }

    $script:CollectStart = $from; $script:CollectEnd = $to; $script:Computers = $computers
    $script:CollectSources = $srcs; $script:CollectIncludeInfo = $miIncludeInfo.Checked; $script:CollectMax = $max
    $script:CollectedAt = Get-Date; $script:CollectedOn = $env:COMPUTERNAME
    $script:UtcOffsetMinutes = [int][TimeZoneInfo]::Local.GetUtcOffset($from).TotalMinutes
    $script:SessionFiles = @()
    Set-RunLog @()
    Set-CollectingState $true
    $script:Jobs = @(foreach ($c in $computers) {
        Start-Job -Name "EventLog_$c" -ScriptBlock $Collector -ArgumentList $c, $from, $to, $srcs, $max, $miIncludeInfo.Checked
    })
    Update-StatusBar "Collecting from $($computers -join ', ')..."
    $pollTimer.Start()
}

function Show-Tips {
    $tips = @"
COLLECT
  Enter one or more computers (or '+ Cluster nodes'), pick a range and the sources, then Collect (F5).
  Every computer is collected in parallel. The Collection log tab shows what was queried and any problems.

TIMELINE
  Bars: events per time bucket by level.  Lanes: where they came from (Lanes: Category / Computer / Provider).
  Dashed lines: reboots, crashes, SQL restarts, failovers, AG changes, patching - hover for details.
  Drag to zoom  |  click a bar to drill in  |  click a dot to drill in and filter to that lane  |  right-click / Ctrl+- to zoom out  |  Ctrl+0 to reset.

FILTER
  Level toggles, category, computer, Event IDs ('1069 1135', '-7036' to exclude) and Search (Ctrl+F).
  Top issues groups events by provider + ID - double-click one to see those events.
  Right-click an event to filter / exclude its ID or zoom to +/- 15 minutes around it.

SHARE
  File > Save session (Ctrl+S) writes everything - all events with full messages, the collection log,
  the settings and your current filters / zoom - to one .json file.
  File > Open session (Ctrl+O), drag and drop, or -SessionPath opens it on any machine, no server access needed.
  File > Add session merges more files (e.g. one per cluster node).
  Collect on a server without the GUI:  .\WinEventLogInvestigator.ps1 -NoGui -OutputPath C:\Temp\RCA
  Also: CSV (Ctrl+E), Excel, and a self-contained interactive HTML report (Ctrl+H).
"@
    [void][System.Windows.Forms.MessageBox]::Show($mainForm, $tips, 'How to use', 'OK', 'Information')
}

#---- Event handlers ----
$miOpen.Add_Click({ $f = Select-SessionFiles 'Open session file(s)'; if ($f) { Open-SessionFiles $f } })
$miAdd.Add_Click({ $f = Select-SessionFiles 'Add session file(s) to the current view'; if ($f) { Open-SessionFiles $f -Append:($script:Table.Rows.Count -gt 0) } })
$miSave.Add_Click({ Save-SessionFile })
$miCsv.Add_Click({ Save-DisplayedCsv })
$miExport.Add_Click({ Save-DisplayedCsv })
$miExcel.Add_Click({ Open-DisplayedInExcel })
$miHtml.Add_Click({ Save-HtmlReport })
$miExit.Add_Click({ $mainForm.Close() })
$miCollect.Add_Click({ Start-Collection })
$miFind.Add_Click({ $txtSearch.Focus(); $txtSearch.SelectAll() })
$miZoomOut.Add_Click({ Undo-Zoom })
$miResetZoom.Add_Click({ Reset-Zoom })
$miShowCollect.Add_CheckedChanged({ $tsCollect.Visible = $miShowCollect.Checked })
$miShowDetail.Add_CheckedChanged({ $splitEvents.Panel2Collapsed = -not $miShowDetail.Checked })
$miTips.Add_Click({ Show-Tips })
$tabEvents.Add_Click({ Show-Tab 'Events' })
$tabSummary.Add_Click({ Show-Tab 'Summary' })
$tabLog.Add_Click({ Show-Tab 'Log' })
foreach ($mi in $sourceItems.Values) { $mi.Add_CheckedChanged({ Update-SourcesButton }) }
$miIncludeInfo.Add_CheckedChanged({ Update-SourcesButton })

$mainForm.Add_DragEnter({
    param($s, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy }
})
$mainForm.Add_DragDrop({
    param($s, $e)
    $files = @($e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop) | Where-Object { $_ -like '*.json' })
    if ($files) { Open-SessionFiles $files -Append:([System.Windows.Forms.Control]::ModifierKeys -band [System.Windows.Forms.Keys]::Shift) }
})
foreach ($c in $chart, $dgvEvents, $dgvSummary) {
    $c.AllowDrop = $true
    $c.Add_DragEnter({ param($s, $e) if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy } })
    $c.Add_DragDrop({ param($s, $e) $files = @($e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop) | Where-Object { $_ -like '*.json' }); if ($files) { Open-SessionFiles $files } })
}

$cmbRange.Add_SelectedIndexChanged({ if (-not $script:SettingRange) { Set-RangeFromPreset } })
$dtpFrom.Add_ValueChanged({ if (-not $script:SettingRange) { $script:SettingRange = $true; $cmbRange.SelectedIndex = $timeFrames.Count - 1; $script:SettingRange = $false } })
$dtpTo.Add_ValueChanged({ if (-not $script:SettingRange) { $script:SettingRange = $true; $cmbRange.SelectedIndex = $timeFrames.Count - 1; $script:SettingRange = $false } })

$btnClusterNodes.Add_Click({
    $first = @($txtComputers.Text -split '[,;\s]+' | Where-Object { $_ }) | Select-Object -First 1
    $isLocal = (-not $first) -or $first -ieq $env:COMPUTERNAME -or $first -in @('.', 'localhost')
    $nodes = $null
    Update-StatusBar 'Looking up cluster nodes...'
    try {
        $p = @{ Namespace = 'root/MSCluster'; ClassName = 'MSCluster_Node'; ErrorAction = 'Stop' }
        if (-not $isLocal) { $p.ComputerName = $first }
        $nodes = @(Get-CimInstance @p | ForEach-Object { $_.Name })
    } catch {
        try {
            Import-Module FailoverClusters -ErrorAction Stop
            $p = @{ ErrorAction = 'Stop' }; if (-not $isLocal) { $p.Cluster = $first }
            $nodes = @(Get-ClusterNode @p | ForEach-Object { $_.Name })
        } catch { }
    }
    if ($nodes -and $nodes.Count) {
        $all = @($txtComputers.Text -split '[,;\s]+' | Where-Object { $_ }) + $nodes | Sort-Object -Unique
        $txtComputers.Text = $all -join ', '
        Update-StatusBar "Cluster nodes: $($nodes -join ', ')"
    } else {
        Show-Error 'Cluster nodes' "Could not find cluster nodes for '$first'. It may not be a cluster node, or WMI / FailoverClusters access was denied."
    }
})

$btnCollect.Add_Click({ Start-Collection })

$btnCancel.Add_Click({
    $pollTimer.Stop()
    foreach ($j in $script:Jobs) { try { Stop-Job $j; Remove-Job $j -Force } catch { } }
    $script:Jobs = @()
    Set-CollectingState $false
    Update-StatusBar 'Collection cancelled.' -ErrorState
})

$pollTimer.Add_Tick({
    $running = @($script:Jobs | Where-Object { $_.State -in 'Running', 'NotStarted' })
    if ($running.Count -gt 0) {
        $parts = foreach ($j in $running) {
            $status = 'starting...'
            $prog = $j.ChildJobs[0].Progress
            if ($prog -and $prog.Count -gt 0) { $status = $prog[$prog.Count - 1].StatusDescription }
            "$($j.Name -replace '^EventLog_', ''): $status"
        }
        Update-StatusBar ("Collecting ({0} of {1} computers still running)  -  {2}" -f $running.Count, $script:Jobs.Count, ($parts -join '  |  '))
        return
    }
    $pollTimer.Stop()
    $events = New-Object System.Collections.Generic.List[object]
    $log = New-Object System.Collections.Generic.List[string]
    foreach ($j in $script:Jobs) {
        $name = $j.Name -replace '^EventLog_', ''
        if ($j.State -eq 'Completed') {
            $out = @(Receive-Job $j -ErrorAction SilentlyContinue -ErrorVariable jobErrors)
            $res = $out | Where-Object { $_ -and $_.PSObject.Properties['Events'] } | Select-Object -Last 1
            if ($res) {
                if ($res.Events) { foreach ($e in $res.Events) { $events.Add($e) } }
                if ($res.Log) { foreach ($l in $res.Log) { $log.Add([string]$l) } }
            } else { $log.Add("[$name] no result returned") }
            foreach ($err in $jobErrors) { $log.Add("[$name] ERROR: $err") }
        } else {
            $reason = if ($j.JobStateInfo.Reason) { $j.JobStateInfo.Reason.Message } else { $j.State }
            $log.Add("[$name] collection $($j.State): $reason")
        }
        Remove-Job $j -Force
    }
    $script:Jobs = @()
    Set-RunLog $log.ToArray()
    Set-CollectingState $false
    [void](Import-CollectedEvents ($events | Sort-Object { [datetime]$_.Time }))
    Update-SessionBanner
    if ($events.Count -eq 0) { Update-StatusBar 'No events found for the selected range and sources - see the Collection log tab.' }
    else { Update-StatusBar ('Collected {0:N0} events from {1}. File > Save session (Ctrl+S) to review them on another machine.' -f $events.Count, ($script:Computers -join ', ')) }
})

# Chart interaction
$chart.Add_Resize({ Set-ChartLayout })
$chart.Add_MouseDown({ param($s, $e) $script:ChartDownX = $e.X })
$chart.Add_SelectionRangeChanged({
    param($s, $e)
    $pos = $chart.PointToClient([System.Windows.Forms.Control]::MousePosition)
    $e.ChartArea.CursorX.SetSelectionPosition([double]::NaN, [double]::NaN)
    if ([math]::Abs($pos.X - $script:ChartDownX) -le 4) { return }   # a click, handled by MouseClick
    if ([double]::IsNaN($e.NewSelectionStart) -or [double]::IsNaN($e.NewSelectionEnd) -or -not $script:ViewStart) { return }
    $a = [DateTime]::FromOADate([math]::Min($e.NewSelectionStart, $e.NewSelectionEnd))
    $b = [DateTime]::FromOADate([math]::Max($e.NewSelectionStart, $e.NewSelectionEnd))
    if (($b - $a).TotalSeconds -ge 5) { Set-ViewWindow $a $b }
})
$chart.Add_MouseClick({
    param($s, $e)
    if (-not $script:ViewStart) { return }
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) { Undo-Zoom; return }
    if ([math]::Abs($e.X - $script:ChartDownX) -gt 4) { return }
    $hit = $chart.HitTest($e.X, $e.Y)
    if ($hit.ChartElementType -eq [System.Windows.Forms.DataVisualization.Charting.ChartElementType]::DataPoint -and $hit.Series.Name -like 'S*') {
        $parts = ([string]$hit.Series.Points[$hit.PointIndex].Tag) -split '\|', 2
        $lane = $parts[1]
        $script:SuspendFilter = $true
        switch ($cmbLanes.SelectedIndex) {
            0 { Select-ComboItem $cmbCategory $lane }
            1 { Select-ComboItem $cmbComputer $lane }
            2 { $cp = $lane -split ' \| ', 2; Select-ComboItem $cmbComputer $cp[0]; Select-ComboItem $cmbCategory $cp[1] }
            3 { $txtSearch.Text = $lane; $filterTimer.Stop() }
        }
        $script:SuspendFilter = $false
        Set-ZoomToBucket ([int]$parts[0])
        return
    }
    if ($hit.ChartArea -and $hit.ChartArea.Name -eq 'Counts' -and $hit.ChartElementType -in @('DataPoint', 'PlottingArea', 'Gridlines', 'StripLines')) {
        $v = $caCounts.AxisX.PixelPositionToValue($e.X)
        $b = [int][math]::Floor(([DateTime]::FromOADate($v).Ticks - $script:ChartStart.Ticks) / $script:BucketTicks)
        if ($b -ge 0 -and $b -lt $script:BucketCount) { Set-ZoomToBucket $b }
    }
})

# Filters
foreach ($c in $chkCrit, $chkErr, $chkWarn, $chkInfo) { $c.Add_CheckedChanged({ Update-View }) }
foreach ($c in $cmbCategory, $cmbComputer, $cmbLanes) { $c.Add_SelectedIndexChanged({ Update-View }) }
foreach ($t in $txtIds, $txtSearch) { $t.Add_TextChanged({ $filterTimer.Stop(); $filterTimer.Start() }) }
$txtSearch.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) { $txtSearch.Text = '' } })
$filterTimer.Add_Tick({ $filterTimer.Stop(); Update-View })
$clearFilters = {
    $script:SuspendFilter = $true
    $txtIds.Text = ''; $txtSearch.Text = ''; $cmbCategory.SelectedIndex = 0; $cmbComputer.SelectedIndex = 0
    foreach ($c in $chkCrit, $chkErr, $chkWarn, $chkInfo) { $c.Checked = $true }
    $script:SuspendFilter = $false
    $filterTimer.Stop()
    Update-View
}
$btnClearFilter.Add_Click($clearFilters)
$miClearFilters.Add_Click($clearFilters)
$btnZoomOut.Add_Click({ Undo-Zoom })
$btnResetZoom.Add_Click({ Reset-Zoom })

# Grids
$dgvEvents.Add_SelectionChanged({
    $row = if ($dgvEvents.SelectedRows.Count) { $dgvEvents.SelectedRows[0] } else { $dgvEvents.CurrentRow }
    if (-not $row -or -not $row.DataBoundItem) { return }
    $r = $row.DataBoundItem.Row
    $txtDetail.Text = (("{0:yyyy-MM-dd HH:mm:ss.fff}   {1}   {2}`r`n{3}  |  {4}  |  Event ID {5}`r`n{6}  ({7})`r`n" -f
        $r['Time'], $r['Computer'], $r['Level'], $r['Category'], $r['Provider'], $r['Id'], $(if ($r['Tag']) { $r['Tag'] } else { '-' }), $r['LogName']) +
        "`r`n" + ([string]$r['Message'] -replace '(?<!\r)\n', "`r`n"))
})
$dgvEvents.Add_CellFormatting({
    param($s, $e)
    $name = $dgvEvents.Columns[$e.ColumnIndex].Name
    if ($name -eq 'Level') {
        switch ([string]$e.Value) { 'Critical' { $e.CellStyle.ForeColor = $levelColors[1] } 'Error' { $e.CellStyle.ForeColor = $levelColors[2] }
            'Warning' { $e.CellStyle.ForeColor = $levelColors[3] } 'Audit Failure' { $e.CellStyle.ForeColor = $levelColors[3] } }
    } elseif ($name -eq 'Tag' -and $e.Value) {
        $mk = [string]$dgvEvents.Rows[$e.RowIndex].DataBoundItem['Marker']
        if ($mk -and $markerColors[$mk]) { $e.CellStyle.ForeColor = $markerColors[$mk] }
    }
})
$dgvSummary.Add_CellFormatting({
    param($s, $e)
    if ($dgvSummary.Columns[$e.ColumnIndex].Name -eq 'Level') {
        switch ([string]$e.Value) { 'Critical' { $e.CellStyle.ForeColor = $levelColors[1] } 'Error' { $e.CellStyle.ForeColor = $levelColors[2] } 'Warning' { $e.CellStyle.ForeColor = $levelColors[3] } }
    }
})
$dgvSummary.Add_CellDoubleClick({
    param($s, $e)
    if ($e.RowIndex -lt 0) { return }
    $r = $dgvSummary.Rows[$e.RowIndex].DataBoundItem.Row
    $script:SuspendFilter = $true
    Select-ComboItem $cmbCategory ([string]$r['Category'])
    $txtIds.Text = [string]$r['Id']
    $script:SuspendFilter = $false
    $filterTimer.Stop()
    Update-View
    Show-Tab 'Events'
})
$dgvEvents.Add_CellMouseDown({
    param($s, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right -and $e.RowIndex -ge 0 -and -not $dgvEvents.Rows[$e.RowIndex].Selected) {
        $dgvEvents.ClearSelection(); $dgvEvents.Rows[$e.RowIndex].Selected = $true; $dgvEvents.CurrentCell = $dgvEvents.Rows[$e.RowIndex].Cells[0]
    }
})
$miCopy.Add_Click({ $content = $dgvEvents.GetClipboardContent(); if ($content) { [System.Windows.Forms.Clipboard]::SetDataObject($content); Update-StatusBar 'Selected rows copied to clipboard.' } })
$miSelectAll.Add_Click({ $dgvEvents.SelectAll() })
$miOnlyId.Add_Click({ if ($dgvEvents.CurrentRow) { $txtIds.Text = [string]$dgvEvents.CurrentRow.DataBoundItem['Id'] } })
$miExcludeId.Add_Click({ if ($dgvEvents.CurrentRow) { $txtIds.Text = (($txtIds.Text.Trim() + ' -' + $dgvEvents.CurrentRow.DataBoundItem['Id']).Trim()) } })
$miAround.Add_Click({
    if ($dgvEvents.CurrentRow) { $t = [datetime]$dgvEvents.CurrentRow.DataBoundItem['Time']; Set-ViewWindow $t.AddMinutes(-15) $t.AddMinutes(15) }
})

$mainForm.Add_Shown({
    $splitMain.SplitterDistance = [int]($splitMain.Height * 0.46)
    $splitEvents.SplitterDistance = [int]($splitEvents.Height * 0.70)
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Update-StatusBar 'Not running as Administrator - the Security log and SQL ERRORLOG files may be inaccessible when collecting.' -ErrorState }
    if ($SessionPath) { Open-SessionFiles $SessionPath }
    elseif ($AutoRun) { Start-Collection }
})
$mainForm.Add_FormClosing({
    $pollTimer.Stop(); $filterTimer.Stop()
    foreach ($j in $script:Jobs) { try { Stop-Job $j; Remove-Job $j -Force } catch { } }
})

# Initial state
Show-Tab 'Events'
Update-SourcesButton
Set-RunLog @()
if ($PSBoundParameters.ContainsKey('StartTime') -or $PSBoundParameters.ContainsKey('EndTime')) {
    Set-CustomRange $StartTime $EndTime
} else {
    $preset = [array]::IndexOf(@($timeFrames | ForEach-Object { $_.Hours }), $Hours)
    if ($preset -ge 0) { $cmbRange.SelectedIndex = $preset } else { Set-CustomRange $StartTime $EndTime }
}

[void]$mainForm.ShowDialog()
$mainForm.Dispose()
#endregion
