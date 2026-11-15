<#
    ServiceChecker.ps1
    ------------------
    Screenshare helper. Checks the Windows services and settings that record
    activity (Prefetch, DPS, PcaSvc, Event Log, BAM and so on), shows which are
    stopped, disabled, restarted since boot or frozen, and can turn them back on.

    - It saves a report of the state it found BEFORE it changes anything, so the
      evidence of a disabled service is kept for the ban log.
    - Fixing only ever sets a service back to its normal Windows start type and
      starts it. It never stops, disables or removes a service. The only other
      things it can change are the Prefetch switch, the MiniNt key and the policy
      values in $PolicyList, which it puts back to the Windows default.
    - Windows PowerShell 5.1, WinForms only, no external modules.
    - Compile with:  Invoke-ps2exe .\ServiceChecker.ps1 .\ServiceChecker.exe -noConsole -requireAdmin

    Run it straight from GitHub without downloading anything (admin CMD or PowerShell):
      powershell -ExecutionPolicy Bypass -Command "iex (irm https://raw.githubusercontent.com/aaa1243/service-checker/main/ServiceChecker.ps1)"
    Same, but as text in the console instead of a window:
      powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm https://raw.githubusercontent.com/aaa1243/service-checker/main/ServiceChecker.ps1))) -NoGui"

    Command line (for testing, runs without the window):
      powershell -File ServiceChecker.ps1 -NoGui [-Fix] [-Json out.json] [-OutDir C:\SSTools\ServiceChecker]
#>
param(
    [switch]$NoGui,
    [switch]$Fix,
    [string]$Json = '',
    [string]$OutDir = 'C:\SSTools\ServiceChecker'
)

$ErrorActionPreference = 'Continue'

# =============================================================================
#  WHAT GETS CHECKED  (edit this list to add or remove services)
# -----------------------------------------------------------------------------
#  Name     : service name (the short one, as in "sc query <name>"). A name ending in _* matches
#             per-user services such as CDPUserSvc_1a2b3c.
#  What     : what it records, shown in the window
#  Start    : normal start type, used when fixing: Automatic, Manual or System (drivers)
#  MustRun  : $true if it normally runs the whole session
#  Core     : $true if screensharing depends on it. Others are shown as a note only.
# =============================================================================
$ServiceList = @(
    @{ Name = 'SysMain';   What = 'Writes Prefetch files';                        Start = 'Automatic'; MustRun = $true;  Core = $true  }
    @{ Name = 'DPS';       What = 'Keeps program names and times in memory';      Start = 'Automatic'; MustRun = $true;  Core = $true  }
    @{ Name = 'PcaSvc';    What = 'Records program launches (PCA)';               Start = 'Automatic'; MustRun = $true;  Core = $true  }
    @{ Name = 'EventLog';  What = 'Writes the Windows event logs';                Start = 'Automatic'; MustRun = $true;  Core = $true  }
    @{ Name = 'Schedule';  What = 'Task Scheduler';                               Start = 'Automatic'; MustRun = $true;  Core = $true  }
    @{ Name = 'bam';       What = 'BAM driver, records what each user ran';       Start = 'System';    MustRun = $true;  Core = $true  }
    @{ Name = 'Dnscache';  What = 'DNS Client, keeps the DNS cache';              Start = 'Automatic'; MustRun = $true;  Core = $true  }
    @{ Name = 'PlugPlay';  What = 'Plug and Play, device and USB tracking';       Start = 'Manual';    MustRun = $true;  Core = $true  }
    @{ Name = 'Appinfo';   What = 'Admin prompts, logs programs run as admin';    Start = 'Manual';    MustRun = $false; Core = $true  }
    @{ Name = 'DcomLaunch';What = 'DCOM launcher, starts COM programs';           Start = 'Automatic'; MustRun = $true;  Core = $true  }
    @{ Name = 'BFE';       What = 'Base Filtering Engine, firewall and network rules'; Start = 'Automatic'; MustRun = $true; Core = $true }
    @{ Name = 'DiagTrack'; What = 'Telemetry, extra program activity traces';     Start = 'Automatic'; MustRun = $true;  Core = $false }
    @{ Name = 'DusmSvc';   What = 'Data Usage, feeds the SRUM usage database';    Start = 'Automatic'; MustRun = $true;  Core = $false }
    @{ Name = 'WSearch';   What = 'Windows Search index';                         Start = 'Automatic'; MustRun = $false; Core = $false }
    @{ Name = 'CDPSvc';    What = 'Connected Devices Platform, activity history'; Start = 'Automatic'; MustRun = $false; Core = $false }
    @{ Name = 'CDPUserSvc_*'; What = 'Per-user part of the activity history';      Start = 'Automatic'; MustRun = $false; Core = $false }
    @{ Name = 'SSDPSRV';   What = 'SSDP Discovery, finds devices on the network'; Start = 'Manual';    MustRun = $false; Core = $false }
)

# Minutes after boot that a service process may start and still count as "started at boot".
$RestartGraceMinutes = 10

# Values that switch tracking or tools off. Fixing removes the value, which puts Windows back to its default
# (or sets it to 1 when Fix = 'set1').
#  BadWhen : 'nonzero' or 'zero', the value that means it is switched off
#  Machine / User : look under HKLM and/or under every loaded user hive
$PolicyList = @(
    @{ Name = 'DisablePCA'; Display = 'DisablePCA policy'; What = 'Turns the Compatibility Assistant off'
       Key = 'SOFTWARE\Policies\Microsoft\Windows\AppCompat'; Value = 'DisablePCA'; BadWhen = 'nonzero'; Machine = $true; User = $true; Core = $true; Level = 'bad'
       Detail = 'PcaSvc stops recording program launches while this is set.' }
    @{ Name = 'DisableCMD'; Display = 'DisableCMD policy'; What = 'Blocks Command Prompt'
       Key = 'Software\Policies\Microsoft\Windows\System'; Value = 'DisableCMD'; BadWhen = 'nonzero'; Machine = $true; User = $true; Core = $true; Level = 'bad'
       Detail = 'Command Prompt is blocked, which gets in the way of a screenshare.' }
    @{ Name = 'ScriptBlockLogging'; Display = 'PowerShell script logging'; What = 'Policy that turns PowerShell logging off'
       Key = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Value = 'EnableScriptBlockLogging'; BadWhen = 'zero'; Machine = $true; User = $true; Core = $true; Level = 'warn'
       Detail = 'Someone set the policy to 0 on purpose. The default is simply not set.' }
    @{ Name = 'Start_TrackDocs'; Display = 'Recent files and jump lists'; What = 'Setting that stops Windows tracking opened files'
       Key = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Value = 'Start_TrackDocs'; BadWhen = 'zero'; Machine = $false; User = $true; Core = $true; Level = 'warn'; Fix = 'set1'
       Detail = 'Recent items and jump lists are not being recorded. This is also a normal privacy switch in Windows Settings.' }
    @{ Name = 'EnableActivityFeed'; Display = 'Activity history'; What = 'Policy that turns the activity timeline off'
       Key = 'SOFTWARE\Policies\Microsoft\Windows\System'; Value = 'EnableActivityFeed'; BadWhen = 'zero'; Machine = $true; User = $false; Core = $false; Level = 'note'
       Detail = 'The Activities cache stops recording. Privacy tools set this too.' }
)

# =============================================================================
#  CHECK LOGIC  (no window code in this part)
# =============================================================================
function Test-IsAdmin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-BootTime {
    try { return (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime }
    catch { return (Get-Date).AddMilliseconds(-[Environment]::TickCount) }
}

function Format-Time($t) {
    if ($null -eq $t) { return '' }
    return ([datetime]$t).ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-StartTypeName([string]$Mode, [string]$Name) {
    # Win32_Service / Win32_SystemDriver StartMode -> the words services.msc uses
    $out = $Mode
    if ($Mode -eq 'Auto') {
        $out = 'Automatic'
        try {
            $d = Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $Name) -Name DelayedAutostart -ErrorAction Stop
            if ($d.DelayedAutostart -eq 1) { $out = 'Automatic (Delayed)' }
        } catch { }
    }
    return $out
}

function Get-SuspendedThreads([int]$ProcessId) {
    # Returns "suspended/total" counts for a process, or $null if it cannot be read.
    try {
        $p = [System.Diagnostics.Process]::GetProcessById($ProcessId)
        $total = 0; $susp = 0
        foreach ($t in $p.Threads) {
            $total++
            try {
                if ($t.ThreadState -eq [System.Diagnostics.ThreadState]::Wait -and
                    $t.WaitReason -eq [System.Diagnostics.ThreadWaitReason]::Suspended) { $susp++ }
            } catch { }
        }
        return @{ Total = $total; Suspended = $susp }
    } catch { return $null }
}

function Get-ServiceRow($Def, $Boot) {
    $row = [ordered]@{
        Name        = $Def.Name
        Display     = $Def.Name
        What        = $Def.What
        Kind        = 'service'
        Core        = [bool]$Def.Core
        State       = 'Not found'
        StartType   = ''
        Normal      = $Def.Start
        ProcessId   = 0
        Started     = ''
        Result      = 'MISSING'
        Level       = 'bad'      # ok, note, warn, bad
        Detail      = ''
        Fixable     = $false
    }
    $svc = $null
    try { $svc = Get-CimInstance Win32_Service -Filter ("Name='" + $Def.Name + "'") -ErrorAction Stop } catch { }
    if ($null -eq $svc) {
        try { $svc = Get-CimInstance Win32_SystemDriver -Filter ("Name='" + $Def.Name + "'") -ErrorAction Stop } catch { }
        if ($null -ne $svc) { $row.Kind = 'driver' }
    }
    if ($null -eq $svc) {
        if ($Def.Core) { $row.Detail = 'Windows has this by default. It is missing from this PC.' }
        else { $row.Level = 'note'; $row.Detail = 'Not on this PC. Some Windows editions do not have it.' }
        return [pscustomobject]$row
    }
    $row.Display   = [string]$svc.DisplayName
    $row.State     = [string]$svc.State
    $row.StartType = Get-StartTypeName ([string]$svc.StartMode) $Def.Name
    if ($row.Kind -eq 'service') { $row.ProcessId = [int]$svc.ProcessId }

    $running  = ($row.State -eq 'Running')
    $disabled = ($svc.StartMode -eq 'Disabled')

    if ($running -and $row.ProcessId -gt 4) {
        try {
            $proc = [System.Diagnostics.Process]::GetProcessById($row.ProcessId)
            $row.Started = Format-Time $proc.StartTime
            $late = ($proc.StartTime - $Boot).TotalMinutes
        } catch { $late = 0 }
    } else { $late = 0 }

    if ($disabled) {
        $row.Result = 'DISABLED'; $row.Fixable = $true
        $row.Detail = 'Start type is Disabled. Windows does not disable this by itself.'
        if ($running) { $row.Detail += ' It is still running now, so it was disabled this session and will not start after a reboot.' }
    }
    elseif (-not $running -and $Def.MustRun) {
        $row.Result = 'STOPPED'; $row.Fixable = $true
        $row.Detail = 'It normally runs the whole session and it is not running now.'
    }
    elseif (-not $running) {
        $row.Result = 'OK'; $row.Level = 'ok'
        $row.Detail = 'Not running, which is normal. It starts only when needed.'
    }
    else {
        $row.Result = 'OK'; $row.Level = 'ok'
        $threads = $null
        if ($row.ProcessId -gt 4) { $threads = Get-SuspendedThreads $row.ProcessId }
        if ($null -ne $threads -and $threads.Total -gt 0 -and $threads.Suspended -eq $threads.Total) {
            $row.Result = 'FROZEN'; $row.Level = 'bad'
            $row.Detail = ("Every thread of its process is suspended ({0} of {1}). It shows as running but records nothing. Restart the service or the PC to clear it." -f $threads.Suspended, $threads.Total)
        }
        elseif ($null -ne $threads -and $threads.Suspended -gt 0) {
            $row.Result = 'THREADS SUSPENDED'; $row.Level = 'warn'
            $row.Detail = ("{0} of {1} threads of its process are suspended." -f $threads.Suspended, $threads.Total)
        }
        elseif ($late -gt $RestartGraceMinutes -and $Def.MustRun) {
            $row.Result = 'RESTARTED'; $row.Level = 'warn'
            $row.Detail = ("Its process started {0:N0} minutes after boot, so it was stopped or restarted this session. Anything it held in memory before that is gone." -f $late)
        }
    }
    if ($row.Result -ne 'OK' -and $row.Level -eq 'bad' -and -not $Def.Core) {
        $row.Level  = 'note'
        $row.Detail += ' Privacy and debloat tools often turn this one off, so it is a note and not a ban reason.'
    }
    return [pscustomobject]$row
}

function Get-SettingRows {
    $rows = @()
    # 1. Prefetch switch
    $r = [ordered]@{ Name = 'EnablePrefetcher'; Display = 'Prefetch setting'; What = 'Registry switch that turns Prefetch on'
                     Kind = 'setting'; Core = $true; State = ''; StartType = ''; Normal = '3'; ProcessId = 0; Started = ''
                     Result = 'OK'; Level = 'ok'; Detail = ''; Fixable = $false }
    try {
        $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -ErrorAction Stop).EnablePrefetcher
        $r.State = "Value $v"
        if ($v -ne 3) {
            $r.Result = 'CHANGED'; $r.Level = 'bad'; $r.Fixable = $true
            $r.Detail = "EnablePrefetcher is $v. The normal value is 3. At 0 Windows records no program runs."
        }
    } catch {
        $r.State = 'Missing'; $r.Result = 'MISSING'; $r.Level = 'bad'; $r.Fixable = $true
        $r.Detail = 'The EnablePrefetcher value is gone.'
    }
    $rows += [pscustomobject]$r

    # 2. MiniNt key (stops event logging)
    $r = [ordered]@{ Name = 'MiniNt'; Display = 'MiniNt key'; What = 'A key that makes Windows stop writing event logs'
                     Kind = 'setting'; Core = $true; State = 'Not present'; StartType = ''; Normal = 'Not present'; ProcessId = 0; Started = ''
                     Result = 'OK'; Level = 'ok'; Detail = ''; Fixable = $false }
    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNt') {
        $r.State = 'Present'; $r.Result = 'PRESENT'; $r.Level = 'bad'; $r.Fixable = $true
        $r.Detail = 'This key does not exist on a normal install. Fixing removes it. Event logging comes back after a reboot.'
    }
    $rows += [pscustomobject]$r

    # 3. Policies that switch tracking or tools off
    foreach ($pol in $PolicyList) {
        $r = [ordered]@{ Name = $pol.Name; Display = $pol.Display; What = $pol.What
                         Kind = 'setting'; Core = [bool]$pol.Core; State = 'Not set'; StartType = ''; Normal = 'Not set'; ProcessId = 0; Started = ''
                         Result = 'OK'; Level = 'ok'; Detail = ''; Fixable = $false }
        $found = @()
        foreach ($p in (Get-PolicyPaths $pol)) {
            try {
                $v = (Get-ItemProperty -Path $p -Name $pol.Value -ErrorAction Stop).($pol.Value)
                if (($pol.BadWhen -eq 'zero' -and $v -eq 0) -or ($pol.BadWhen -eq 'nonzero' -and $v -ne 0)) { $found += ($p -replace '^Registry::', '') }
            } catch { }
        }
        if ($found.Count -gt 0) {
            $r.State = 'Set'; $r.Result = 'SET'; $r.Level = $pol.Level; $r.Fixable = $true
            $r.Detail = $pol.Detail + ' Found at: ' + ($found -join '; ')
        }
        $rows += [pscustomobject]$r
    }

    # 4. USN journal on the Windows drive (reported only, never changed)
    $drive = $env:SystemDrive
    $r = [ordered]@{ Name = 'UsnJournal'; Display = "USN journal on $drive"; What = 'Record of created, renamed and deleted files'
                     Kind = 'info'; Core = $true; State = ''; StartType = ''; Normal = 'Active'; ProcessId = 0; Started = ''
                     Result = 'OK'; Level = 'ok'; Detail = ''; Fixable = $false }
    try {
        $out = & fsutil.exe usn queryjournal $drive 2>&1
        if ($LASTEXITCODE -eq 0) { $r.State = 'Active' }
        else {
            $r.State = 'Not active'; $r.Result = 'MISSING'; $r.Level = 'bad'
            $r.Detail = 'There is no journal on the Windows drive. It is on by default, so it was deleted. This tool does not recreate it. ' + (($out | Out-String).Trim())
        }
    } catch { $r.State = 'Unknown'; $r.Level = 'note'; $r.Detail = 'fsutil could not be run.' }
    $rows += [pscustomobject]$r

    # 5. Prefetch folder (reported only)
    $pf = Join-Path $env:SystemRoot 'Prefetch'
    $r = [ordered]@{ Name = 'PrefetchFolder'; Display = 'Prefetch folder'; What = 'Where Windows keeps the .pf files'
                     Kind = 'info'; Core = $true; State = ''; StartType = ''; Normal = 'Exists'; ProcessId = 0; Started = ''
                     Result = 'OK'; Level = 'ok'; Detail = ''; Fixable = $false }
    if (Test-Path $pf) {
        $count = 0
        try { $count = @(Get-ChildItem -Path $pf -Filter *.pf -ErrorAction Stop).Count } catch { }
        $r.State = "$count .pf files"
        if ($count -lt 20) { $r.Result = 'FEW FILES'; $r.Level = 'warn'; $r.Detail = 'A PC in daily use has hundreds. Very few can mean they were deleted or Prefetch was off.' }
        # Tampered files: read-only or hidden (Windows cannot update them), and files with identical content (one copied over another).
        $locked = @(); $byHash = @{}
        try {
            foreach ($f in (Get-ChildItem -Path $pf -Filter *.pf -Force -ErrorAction Stop)) {
                $attr = $f.Attributes
                if (($attr -band [System.IO.FileAttributes]::ReadOnly) -or ($attr -band [System.IO.FileAttributes]::Hidden)) { $locked += $f.Name }
                try {
                    $h = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                    if (-not $byHash.ContainsKey($h)) { $byHash[$h] = @() }
                    $byHash[$h] += $f.Name
                } catch { }
            }
        } catch { }
        $copies = @()
        foreach ($k in $byHash.Keys) { if (@($byHash[$k]).Count -gt 1) { $copies += (@($byHash[$k]) -join ' = ') } }
        if ($locked.Count -gt 0) {
            $r.Result = 'TAMPERED'; $r.Level = 'bad'
            $r.Detail = ('{0} read-only or hidden .pf file(s). Windows cannot update those, so their run count and time are frozen: {1}' -f $locked.Count, (($locked | Select-Object -First 8) -join ', '))
        }
        if ($copies.Count -gt 0) {
            if ($r.Level -ne 'bad') { $r.Result = 'COPIED FILES'; $r.Level = 'warn' }
            $r.Detail = ($r.Detail + ' ' + ('{0} group(s) of .pf files with identical content, which means one was copied over another: {1}' -f $copies.Count, (($copies | Select-Object -First 4) -join '; '))).Trim()
        }
    } else {
        $r.State = 'Missing'; $r.Result = 'MISSING'; $r.Level = 'bad'; $r.Detail = 'The Prefetch folder does not exist.'
    }
    $rows += [pscustomobject]$r
    return $rows
}

function Get-UserSids {
    $sids = @()
    try {
        foreach ($k in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop)) {
            if ($k.PSChildName -match '^S-1-5-21-[\d-]+$') { $sids += $k.PSChildName }
        }
    } catch { }
    return $sids
}

function Get-PolicyPaths($Pol) {
    $paths = @()
    if ($Pol.Machine) { $paths += ('HKLM:\' + $Pol.Key) }
    if ($Pol.User) { foreach ($sid in (Get-UserSids)) { $paths += ('Registry::HKEY_USERS\' + $sid + '\' + $Pol.Key) } }
    return $paths
}

function Get-AllRows {
    $boot = Get-BootTime
    $rows = @()
    foreach ($def in $ServiceList) {
        if ($def.Name.EndsWith('_*')) {
            $prefix = $def.Name.Substring(0, $def.Name.Length - 1)
            $found = @()
            try { $found = @(Get-CimInstance Win32_Service -Filter ("Name LIKE '" + $prefix.Replace('_', '[_]') + "%'") -ErrorAction Stop) } catch { }
            foreach ($f in $found) {
                $copy = @{ Name = [string]$f.Name; What = $def.What; Start = $def.Start; MustRun = $def.MustRun; Core = $def.Core }
                $rows += (Get-ServiceRow $copy $boot)
            }
            continue
        }
        $rows += (Get-ServiceRow $def $boot)
    }
    $rows += (Get-SettingRows)
    return $rows
}

function Get-ServiceEvents($Boot, $Rows) {
    # Start type changes (7040) and stops (7036) for the listed services since boot.
    $lines = @()
    $names = @()
    foreach ($r in $Rows) { if ($r.Kind -eq 'service' -or $r.Kind -eq 'driver') { $names += $r.Display; $names += $r.Name } }
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7040, 7036; StartTime = $Boot } -MaxEvents 3000 -ErrorAction Stop
    } catch { return $lines }
    foreach ($e in $events) {
        $p = @()
        foreach ($x in $e.Properties) { $p += [string]$x.Value }
        if ($p.Count -lt 2) { continue }
        $hit = $false
        foreach ($n in $names) { if ($n -and ($p[0] -eq $n -or ($p.Count -gt 3 -and $p[3] -eq $n))) { $hit = $true; break } }
        if (-not $hit) { continue }
        if ($e.Id -eq 7040) {
            $who = ''
            try { $who = $e.UserId.Translate([System.Security.Principal.NTAccount]).Value } catch { }
            $lines += ("{0}  start type of {1} changed from {2} to {3}{4}" -f (Format-Time $e.TimeCreated), $p[0], $p[1], $p[2], $(if ($who) { " by $who" } else { '' }))
        } elseif ($p[1] -match 'stopped') {
            $lines += ("{0}  {1} entered the stopped state" -f (Format-Time $e.TimeCreated), $p[0])
        }
        if ($lines.Count -ge 40) { break }
    }
    return $lines
}

function Get-EventNotes($Boot) {
    # Latest log clear, journal delete, clock change and shutdown. Lines start with "!" when it happened since boot.
    $notes = @()
    $checks = @(
        @{ Log = 'Microsoft-Windows-Ntfs/Operational'; Ids = @(3079);      Text = 'USN journal deleted' }
        @{ Log = 'Application';                         Ids = @(3079);      Text = 'USN journal deleted' }
        @{ Log = 'System';                              Ids = @(104);       Text = 'An event log was cleared' }
        @{ Log = 'Security';                            Ids = @(1102);      Text = 'Security log cleared' }
        @{ Log = 'Security';                            Ids = @(4616);      Text = 'System time changed' }
        @{ Log = 'System';                              Ids = @(1074);      Text = 'Last shutdown or restart request' }
        @{ Log = 'System';                              Ids = @(6005);      Text = 'Event Log service last started' }
    )
    foreach ($c in $checks) {
        try {
            $e = Get-WinEvent -FilterHashtable @{ LogName = $c.Log; Id = $c.Ids } -MaxEvents 1 -ErrorAction Stop
        } catch { continue }
        if ($null -eq $e) { continue }
        $flag = '  '
        if ($e.TimeCreated -gt $Boot -and $c.Ids[0] -ne 1074 -and $c.Ids[0] -ne 6005) { $flag = '! ' }
        $extra = ''
        if ($c.Ids[0] -eq 4616) {
            # svchost / w32time changes are Windows syncing the clock, not the user
            $procName = ''
            try { foreach ($x in $e.Properties) { $v = [string]$x.Value; if ($v -match '\.exe$') { $procName = $v } } } catch { }
            if ($procName) { $extra = ' by ' + $procName }
            if ($procName -match 'svchost\.exe$') { $flag = '  ' }
        }
        $notes += ("{0}{1}: {2}{3}" -f $flag, $c.Text, (Format-Time $e.TimeCreated), $extra)
    }
    return $notes
}

function Get-DriveNotes {
    $notes = @()
    try {
        foreach ($d in (Get-CimInstance Win32_LogicalDisk -ErrorAction Stop)) {
            if ($d.DriveType -ne 2 -and $d.DriveType -ne 3) { continue }
            $fs = [string]$d.FileSystem
            $flag = '  '
            $tail = ''
            if ($fs -and $fs -ne 'NTFS' -and $fs -ne 'ReFS') { $flag = '! '; $tail = ' (no USN journal on this file system)' }
            $kind = 'fixed'
            if ($d.DriveType -eq 2) { $kind = 'removable' }
            $notes += ("{0}{1} {2} {3}{4}" -f $flag, $d.DeviceID, $fs, $kind, $tail)
        }
    } catch { }
    return $notes
}

function Repair-Row($Row) {
    # Returns a list of text lines describing what was done.
    $log = @()
    if (-not $Row.Fixable) { return $log }
    if ($Row.Kind -eq 'setting') {
        try {
            if ($Row.Name -eq 'EnablePrefetcher') {
                Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -Value 3 -Type DWord -ErrorAction Stop
                $log += 'EnablePrefetcher set to 3. Prefetch starts recording again after a reboot.'
            } elseif ($Row.Name -eq 'MiniNt') {
                Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNt' -Recurse -Force -ErrorAction Stop
                $log += 'MiniNt key removed. Event logging comes back after a reboot.'
            } else {
                foreach ($pol in $PolicyList) {
                    if ($pol.Name -ne $Row.Name) { continue }
                    foreach ($p in (Get-PolicyPaths $pol)) {
                        $has = $false
                        try { $has = ($null -ne (Get-ItemProperty -Path $p -Name $pol.Value -ErrorAction Stop)) } catch { }
                        if ($has -and $pol.Fix -eq 'set1') {
                            Set-ItemProperty -Path $p -Name $pol.Value -Value 1 -Type DWord -ErrorAction Stop
                            $log += ("{0} set to 1 at {1}" -f $pol.Value, ($p -replace '^Registry::', ''))
                        } elseif ($has) {
                            Remove-ItemProperty -Path $p -Name $pol.Value -ErrorAction Stop
                            $log += ("{0} removed from {1}" -f $pol.Value, ($p -replace '^Registry::', ''))
                        }
                    }
                }
            }
        } catch { $log += ("Could not change {0}: {1}" -f $Row.Name, $_.Exception.Message) }
        return $log
    }

    $name   = $Row.Name
    $key    = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $name
    $normal = $Row.Normal
    $value  = 2
    if ($normal -eq 'Manual') { $value = 3 }
    if ($normal -eq 'System') { $value = 1 }

    if ($Row.StartType -eq 'Disabled') {
        $done = $false
        if ($Row.Kind -eq 'service') {
            try { Set-Service -Name $name -StartupType $normal -ErrorAction Stop; $done = $true; $log += "$name start type set to $normal." }
            catch { $log += ("$name could not be changed through the service manager ({0}). Trying the registry." -f $_.Exception.Message) }
        }
        if (-not $done) {
            try { Set-ItemProperty -Path $key -Name Start -Value $value -Type DWord -ErrorAction Stop; $log += "$name start value set to $value in the registry. It may need a reboot to apply." }
            catch { $log += ("$name start type could not be changed: {0}" -f $_.Exception.Message) }
        }
    }
    if ($Row.State -ne 'Running') {
        $started = $false
        if ($Row.Kind -eq 'service') {
            try { Start-Service -Name $name -ErrorAction Stop; $started = $true } catch { }
        }
        if (-not $started) {
            $out = & sc.exe start $name 2>&1
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1056) { $started = $true }
            else { $log += ("$name could not be started (sc exit code $LASTEXITCODE). A reboot may be needed. " + (($out | Out-String).Trim() -replace '\s+', ' ')) }
        }
        if ($started) { $log += "$name started." }
    }
    return $log
}

function Save-Report($Rows, [string]$Tag, $ExtraLines) {
    try {
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
        $base  = Join-Path $OutDir ("{0}_{1}" -f $Tag, $stamp)
        $Rows | Select-Object Name, Display, Kind, State, StartType, Normal, Started, Result, Detail |
            Export-Csv -Path ($base + '.csv') -NoTypeInformation -Encoding UTF8
        $boot = Get-BootTime
        $txt  = @()
        $txt += 'Service Checker report (' + $Tag + ')'
        $txt += 'Computer: ' + $env:COMPUTERNAME + '   User: ' + $env:USERNAME
        $txt += 'Scan time: ' + (Format-Time (Get-Date)) + '   Boot time: ' + (Format-Time $boot)
        $txt += 'Running as administrator: ' + (Test-IsAdmin)
        $txt += ''
        foreach ($r in $Rows) {
            $txt += ("[{0}] {1} ({2})  state: {3}  start type: {4}  process started: {5}" -f $r.Result, $r.Display, $r.Name, $r.State, $r.StartType, $r.Started)
            if ($r.Detail) { $txt += '      ' + $r.Detail }
        }
        if ($ExtraLines -and @($ExtraLines).Count -gt 0) { $txt += ''; $txt += $ExtraLines }
        Set-Content -Path ($base + '.txt') -Value $txt -Encoding UTF8
        return ($base + '.txt')
    } catch { return '' }
}

# =============================================================================
#  COMMAND LINE MODE
# =============================================================================
if ($NoGui) {
    $rows   = Get-AllRows
    $boot   = Get-BootTime
    $events = @(Get-ServiceEvents $boot $rows)
    $notes  = @('Event log checks ("!" means since boot):') + @(Get-EventNotes $boot) + @('Drives:') + @(Get-DriveNotes)
    $before = Save-Report $rows 'scan' ($events + $notes)
    $notes | ForEach-Object { Write-Host $_ }
    $rows | Format-Table Result, Name, State, StartType, Started -AutoSize | Out-String | Write-Host
    foreach ($r in $rows) { if ($r.Result -ne 'OK') { Write-Host ("{0}: {1}" -f $r.Name, $r.Detail) } }
    if ($events.Count) { Write-Host "`nService changes since boot:"; $events | ForEach-Object { Write-Host "  $_" } }
    if ($before) { Write-Host "`nReport saved to $before" }
    if ($Fix) {
        $fixLog = @()
        foreach ($r in $rows) { if ($r.Fixable) { $fixLog += (Repair-Row $r) } }
        $fixLog | ForEach-Object { Write-Host $_ }
        $rows = Get-AllRows
        [void](Save-Report $rows 'after_fix' $fixLog)
        $rows | Format-Table Result, Name, State, StartType -AutoSize | Out-String | Write-Host
    }
    if ($Json) { $rows | ConvertTo-Json -Depth 4 | Set-Content -Path $Json -Encoding UTF8 }
    return
}

# =============================================================================
#  WINDOW
# =============================================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:HasNative = $false
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SvcNative {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
}
"@ -ErrorAction Stop
    $script:HasNative = $true
} catch { }

function C([string]$hex) { return [System.Drawing.ColorTranslator]::FromHtml($hex) }
$ColWindow    = C '#1B1C1F'
$ColPanel     = C '#232529'
$ColPanelHead = C '#2A2C31'
$ColLogBack   = C '#141518'
$ColBorder    = C '#34373D'
$ColText      = C '#E6E7EA'
$ColTitle     = C '#F2F3F5'
$ColSub       = C '#C9CCD1'
$ColDim       = C '#9AA0A8'
$ColMuted     = C '#8E939B'
$ColAccent    = C '#B3263A'
$ColOK        = C '#4CC38A'
$ColWarn      = C '#E5B454'
$ColErr       = C '#FF6B6E'

$FontUI     = New-Object System.Drawing.Font('Segoe UI', 9.75)
$FontSmall  = New-Object System.Drawing.Font('Segoe UI', 8.5)
$FontSmallB = New-Object System.Drawing.Font('Segoe UI', 8.25, [System.Drawing.FontStyle]::Bold)
$FontTitle  = New-Object System.Drawing.Font('Segoe UI Semibold', 14.25)
$FontMono   = New-Object System.Drawing.Font('Consolas', 9)

function New-Label {
    param([string]$Text, [int]$X, [int]$Y, $Font, $Color)
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.AutoSize  = $true
    $l.Font      = $Font
    $l.ForeColor = $Color
    $l.BackColor = [System.Drawing.Color]::Transparent
    return $l
}

function New-FlatButton {
    param([string]$Text, [int]$X, [int]$Y, [int]$W, [int]$H, $Back, $Fore, $Border)
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $b.FlatAppearance.BorderColor = $Border
    $b.FlatAppearance.BorderSize  = 1
    $b.BackColor = $Back
    $b.ForeColor = $Fore
    $b.Font      = $FontUI
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    return $b
}

$Form = New-Object System.Windows.Forms.Form
$Form.Text            = 'Service Checker'
$Form.ClientSize      = New-Object System.Drawing.Size(1000, 700)
$Form.MinimumSize     = New-Object System.Drawing.Size(900, 560)
$Form.StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterScreen
$Form.BackColor       = $ColWindow
$Form.ForeColor       = $ColText
$Form.Font            = $FontUI

$Title    = New-Label 'Service Checker' 18 12 $FontTitle $ColTitle
$SubLabel = New-Label '' 20 44 $FontSmall $ColDim

$A = [System.Windows.Forms.AnchorStyles]
$BtnRescan = New-FlatButton 'Rescan' 18 70 96 30 $ColPanel $ColText $ColBorder
$BtnSelect = New-FlatButton 'Select problems' 122 70 132 30 $ColPanel $ColText $ColBorder
$BtnFix    = New-FlatButton 'Fix selected' 262 70 120 30 $ColAccent $ColTitle $ColAccent
$BtnFolder = New-FlatButton 'Open report folder' 390 70 150 30 $ColPanel $ColText $ColBorder
$Summary   = New-Label '' 556 77 $FontUI $ColSub

$Grid = New-Object System.Windows.Forms.DataGridView
$Grid.Location = New-Object System.Drawing.Point(18, 110)
$Grid.Size     = New-Object System.Drawing.Size(964, 380)
$Grid.Anchor   = $A::Top -bor $A::Left -bor $A::Right -bor $A::Bottom
$Grid.BackgroundColor  = $ColPanel
$Grid.GridColor        = $ColBorder
$Grid.BorderStyle      = [System.Windows.Forms.BorderStyle]::FixedSingle
$Grid.CellBorderStyle  = [System.Windows.Forms.DataGridViewCellBorderStyle]::SingleHorizontal
$Grid.EnableHeadersVisualStyles = $false
$Grid.RowHeadersVisible         = $false
$Grid.AllowUserToAddRows        = $false
$Grid.AllowUserToDeleteRows     = $false
$Grid.AllowUserToResizeRows     = $false
$Grid.MultiSelect               = $false
$Grid.SelectionMode             = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$Grid.ColumnHeadersBorderStyle  = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::None
$Grid.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::DisableResizing
$Grid.ColumnHeadersHeight       = 26
$Grid.RowTemplate.Height        = 24
$Grid.ColumnHeadersDefaultCellStyle.BackColor          = $ColPanelHead
$Grid.ColumnHeadersDefaultCellStyle.ForeColor          = $ColDim
$Grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $ColPanelHead
$Grid.ColumnHeadersDefaultCellStyle.Font               = $FontSmallB
$Grid.DefaultCellStyle.BackColor          = $ColPanel
$Grid.DefaultCellStyle.ForeColor          = $ColText
$Grid.DefaultCellStyle.SelectionBackColor = $ColPanelHead
$Grid.DefaultCellStyle.SelectionForeColor = $ColText
$Grid.DefaultCellStyle.Font               = $FontUI

$colChk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colChk.HeaderText = 'FIX'
$colChk.Width      = 40
$colChk.FlatStyle  = [System.Windows.Forms.FlatStyle]::Flat
function New-TextColumn([string]$Header, [int]$Width, [bool]$Fill) {
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.HeaderText = $Header
    $c.ReadOnly   = $true
    $c.SortMode   = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
    if ($Fill) { $c.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill } else { $c.Width = $Width }
    return $c
}
$colName    = New-TextColumn 'SERVICE' 190 $false
$colWhat    = New-TextColumn 'WHAT IT DOES' 0 $true
$colState   = New-TextColumn 'STATE' 96 $false
$colStart   = New-TextColumn 'START TYPE' 128 $false
$colStarted = New-TextColumn 'PROCESS STARTED' 140 $false
$colResult  = New-TextColumn 'RESULT' 140 $false
$colResult.DefaultCellStyle.Font = $FontSmallB
foreach ($col in @($colChk, $colName, $colWhat, $colState, $colStart, $colStarted, $colResult)) {
    [void]$Grid.Columns.Add([System.Windows.Forms.DataGridViewColumn]$col)
}

$DetailLabel = New-Object System.Windows.Forms.Label
$DetailLabel.Location  = New-Object System.Drawing.Point(18, 496)
$DetailLabel.Size      = New-Object System.Drawing.Size(964, 38)
$DetailLabel.Anchor    = $A::Left -bor $A::Right -bor $A::Bottom
$DetailLabel.Font      = $FontSmall
$DetailLabel.ForeColor = $ColSub
$DetailLabel.Text      = 'Click a row to see what the result means.'

$LogBox = New-Object System.Windows.Forms.RichTextBox
$LogBox.Location    = New-Object System.Drawing.Point(18, 538)
$LogBox.Size        = New-Object System.Drawing.Size(964, 146)
$LogBox.Anchor      = $A::Left -bor $A::Right -bor $A::Bottom
$LogBox.BackColor   = $ColLogBack
$LogBox.ForeColor   = $ColSub
$LogBox.Font        = $FontMono
$LogBox.ReadOnly    = $true
$LogBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$LogBox.DetectUrls  = $false

foreach ($ctl in @($Title, $SubLabel, $BtnRescan, $BtnSelect, $BtnFix, $BtnFolder, $Summary, $Grid, $DetailLabel, $LogBox)) {
    $Form.Controls.Add([System.Windows.Forms.Control]$ctl)
}

$script:Rows = @()

function Add-Log([string]$Text, $Color) {
    $LogBox.SelectionStart  = $LogBox.TextLength
    $LogBox.SelectionLength = 0
    $LogBox.SelectionColor  = $Color
    $LogBox.AppendText($Text + "`r`n")
    $LogBox.ScrollToCaret()
}

function Get-LevelColor([string]$Level) {
    if ($Level -eq 'ok')   { return $ColOK }
    if ($Level -eq 'warn') { return $ColWarn }
    if ($Level -eq 'note') { return $ColMuted }
    return $ColErr
}

function Update-Grid([bool]$WriteReport) {
    $Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $Grid.Rows.Clear()
    $boot = Get-BootTime
    $script:Rows = @(Get-AllRows)
    $bad = 0; $warn = 0
    foreach ($r in $script:Rows) {
        $label = $r.Display
        if ($r.Kind -eq 'service' -or $r.Kind -eq 'driver') { $label = $r.Display + ' (' + $r.Name + ')' }
        $i = $Grid.Rows.Add([object[]]@($false, $label, $r.What, $r.State, $r.StartType, $r.Started, $r.Result))
        $row = $Grid.Rows[$i]
        $row.Tag = $r
        $row.Cells[6].Style.ForeColor = Get-LevelColor $r.Level
        $row.Cells[6].Style.SelectionForeColor = Get-LevelColor $r.Level
        if (-not $r.Fixable) { $row.Cells[0].ReadOnly = $true }
        if ($r.Level -eq 'bad')  { $bad++ }
        if ($r.Level -eq 'warn') { $warn++ }
    }
    $admin = Test-IsAdmin
    $SubLabel.Text = ('Boot time: {0}     Scan: {1}     Administrator: {2}' -f (Format-Time $boot), (Format-Time (Get-Date)), $(if ($admin) { 'yes' } else { 'NO, results are incomplete and nothing can be fixed' }))
    if ($bad -eq 0 -and $warn -eq 0) { $Summary.Text = 'Everything looks normal.'; $Summary.ForeColor = $ColOK }
    else { $Summary.Text = ('{0} problem(s), {1} warning(s)' -f $bad, $warn); $Summary.ForeColor = $(if ($bad) { $ColErr } else { $ColWarn }) }

    $events = @(Get-ServiceEvents $boot $script:Rows)
    if ($events.Count -gt 0) {
        Add-Log 'Service changes in the System log since boot:' $ColDim
        foreach ($e in $events) { Add-Log ('  ' + $e) $ColWarn }
    } else {
        Add-Log 'No start type changes or stops for these services in the System log since boot.' $ColDim
    }
    $notes = @()
    Add-Log 'Event log checks:' $ColDim
    foreach ($n in @(Get-EventNotes $boot)) {
        $notes += $n
        if ($n.StartsWith('!')) { Add-Log ('  ' + $n.Substring(2) + '  (since boot)') $ColErr } else { Add-Log ('  ' + $n.Substring(2)) $ColSub }
    }
    Add-Log 'Drives:' $ColDim
    foreach ($n in @(Get-DriveNotes)) {
        $notes += $n
        if ($n.StartsWith('!')) { Add-Log ('  ' + $n.Substring(2)) $ColWarn } else { Add-Log ('  ' + $n.Substring(2)) $ColSub }
    }
    if ($WriteReport) {
        $path = Save-Report $script:Rows 'scan' (@($events) + @($notes))
        if ($path) { Add-Log ('Report saved: ' + $path) $ColDim }
        else { Add-Log ('Could not save a report to ' + $OutDir) $ColErr }
    }
    $Form.Cursor = [System.Windows.Forms.Cursors]::Default
}

$Grid.Add_SelectionChanged({
    if ($Grid.SelectedRows.Count -gt 0) {
        $r = $Grid.SelectedRows[0].Tag
        if ($null -ne $r) {
            $d = $r.Detail
            if (-not $d) { $d = 'Normal.' }
            $DetailLabel.Text = ($r.Display + ': ' + $d)
        }
    }
})
$Grid.Add_CurrentCellDirtyStateChanged({
    if ($Grid.IsCurrentCellDirty) { [void]$Grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) }
})

$BtnRescan.Add_Click({ Add-Log '--- Rescan ---' $ColDim; Update-Grid $true })

$BtnSelect.Add_Click({
    foreach ($row in $Grid.Rows) {
        $r = $row.Tag
        if ($null -ne $r -and $r.Fixable -and $r.Level -eq 'bad') { $row.Cells[0].Value = $true }
    }
})

$BtnFolder.Add_Click({
    try {
        if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        Start-Process explorer.exe $OutDir
    } catch { Add-Log ('Could not open ' + $OutDir) $ColErr }
})

$BtnFix.Add_Click({
    $picked = @()
    foreach ($row in $Grid.Rows) {
        if ($row.Cells[0].Value -eq $true -and $null -ne $row.Tag -and $row.Tag.Fixable) { $picked += $row.Tag }
    }
    if ($picked.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show($Form, 'Tick the FIX box on the rows you want to turn back on first. "Select problems" ticks every problem that can be fixed.', 'Service Checker', 'OK', 'Information')
        return
    }
    if (-not (Test-IsAdmin)) {
        [void][System.Windows.Forms.MessageBox]::Show($Form, 'Run Service Checker as administrator to change services.', 'Service Checker', 'OK', 'Warning')
        return
    }
    $before = Save-Report $script:Rows 'before_fix' @()
    $names  = ($picked | ForEach-Object { $_.Display }) -join ', '
    $msg = "This will turn these back on:`r`n`r`n$names`r`n`r`nA report of how they are right now was saved to:`r`n$before`r`n`r`nTake your screenshot of this window first if you need one for the ban log. Continue?"
    $answer = [System.Windows.Forms.MessageBox]::Show($Form, $msg, 'Fix selected', 'YesNo', 'Warning')
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    Add-Log '--- Fix ---' $ColDim
    $fixLog = @()
    foreach ($r in $picked) {
        foreach ($line in @(Repair-Row $r)) {
            $fixLog += $line
            $color = $ColOK
            if ($line -match 'could not|Could not') { $color = $ColErr }
            Add-Log $line $color
        }
    }
    Update-Grid $false
    $after = Save-Report $script:Rows 'after_fix' $fixLog
    if ($after) { Add-Log ('Report saved: ' + $after) $ColDim }
    $Form.Cursor = [System.Windows.Forms.Cursors]::Default
})

$Form.Add_Shown({
    if ($script:HasNative) {
        try {
            $on = 1
            [void][SvcNative]::DwmSetWindowAttribute($Form.Handle, 20, [ref]$on, 4)
            [void][SvcNative]::DwmSetWindowAttribute($Form.Handle, 19, [ref]$on, 4)
        } catch { }
    }
    Update-Grid $true
    if (-not (Test-IsAdmin)) { Add-Log 'Not running as administrator. Some services cannot be read and nothing can be fixed.' $ColErr }
})

[void]$Form.ShowDialog()
