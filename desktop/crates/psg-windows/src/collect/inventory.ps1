# Phone Spy Guard: read-only inventory of this PC, as JSON on stdout.
# Runs as the signed-in user; sections that need administrator rights fail
# quietly and are reported in "errors" so the app can show them as gaps.
# It changes nothing on the PC.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$out = [ordered]@{ errors = @() }

function Section($name, [scriptblock]$block) {
    try { $out[$name] = & $block }
    catch { $out['errors'] += ($name + ': ' + $_.Exception.Message) }
}

Section 'currentSid' { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }

Section 'bootMillis' {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    [int64](($os.LastBootUpTime.ToUniversalTime() - [datetime]'1970-01-01T00:00:00').TotalMilliseconds)
}

Section 'processes' {
    @(Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
        [ordered]@{ name = [string]$_.Name; path = [string]$_.ExecutablePath; pid = [int]$_.ProcessId }
    })
}

Section 'tasks' {
    @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $t = $_
        foreach ($a in @($t.Actions)) {
            if ($a.Execute) {
                [ordered]@{ path = [string]$t.TaskPath; name = [string]$t.TaskName; execute = [string]$a.Execute;
                            arguments = [string]$a.Arguments; state = [string]$t.State }
            }
        }
    })
}

Section 'startupLinks' {
    $shell = New-Object -ComObject WScript.Shell
    @(foreach ($f in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        if ($f -and (Test-Path -LiteralPath $f)) {
            Get-ChildItem -LiteralPath $f -File -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
                $target = $_.FullName; $arguments = ''
                if ($_.Extension -eq '.lnk') {
                    $lnk = $shell.CreateShortcut($_.FullName)
                    if ($lnk.TargetPath) { $target = $lnk.TargetPath }
                    $arguments = [string]$lnk.Arguments
                }
                [ordered]@{ folder = $f; name = $_.Name; target = [string]$target; arguments = $arguments }
            }
        }
    })
}

Section 'admins' {
    $sid = 'S-1-5-32-544'
    try {
        @(Get-LocalGroupMember -SID $sid -ErrorAction Stop | ForEach-Object {
            [ordered]@{ name = [string]$_.Name; sid = [string]$_.SID.Value; objectClass = [string]$_.ObjectClass }
        })
    } catch {
        # Get-LocalGroupMember fails on orphaned members; fall back to ADSI.
        $group = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $g = [ADSI]("WinNT://./" + $group + ",group")
        @($g.Invoke('Members') | ForEach-Object {
            $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
            $cls = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
            $parts = $path -replace '^WinNT://', '' -split '/'
            $name = ($parts[-2] + '\' + $parts[-1])
            $s = ''
            try { $s = (New-Object Security.Principal.NTAccount($name)).Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
            [ordered]@{ name = $name; sid = $s; objectClass = [string]$cls }
        })
    }
}

Section 'accounts' {
    @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
        $last = $null
        if ($_.LastLogon) { $last = [int64](($_.LastLogon.ToUniversalTime() - [datetime]'1970-01-01T00:00:00').TotalMilliseconds) }
        [ordered]@{ name = [string]$_.Name; sid = [string]$_.SID.Value; enabled = [bool]$_.Enabled; lastLogonMillis = $last }
    })
}

Section 'defender' {
    $s = Get-MpComputerStatus -ErrorAction Stop
    [ordered]@{ realtime = [bool]$s.RealTimeProtectionEnabled; antivirus = [bool]$s.AntivirusEnabled }
}

Section 'exclusions' {
    $p = Get-MpPreference -ErrorAction Stop
    $all = @(@($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension) | Where-Object { $_ })
    if (@($all | Where-Object { $_ -like 'N/A*' }).Count -gt 0) { throw 'Defender exclusions need administrator rights' }
    , $all
}

Section 'av' {
    @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
        Where-Object { ($_.productState -band 0x1000) -ne 0 } | ForEach-Object { [string]$_.displayName })
}

Section 'dns' {
    @(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { $_.ServerAddresses } |
        ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique)
}

Section 'partOfDomain' {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $azure = $false
    try { $azure = [bool]((& "$env:SystemRoot\System32\dsregcmd.exe" /status) -match 'AzureAdJoined\s*:\s*YES') } catch {}
    [bool]$cs.PartOfDomain -or $azure
}

Section 'rootCerts' {
    @(Get-ChildItem Cert:\CurrentUser\Root -ErrorAction Stop | ForEach-Object {
        [ordered]@{ thumbprint = [string]$_.Thumbprint; subject = [string]$_.Subject }
    })
}

Section 'wmi' {
    $consumers = @(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction Stop) +
                 @(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction Stop)
    @($consumers | Where-Object { $_ } | ForEach-Object {
        $cmd = if ($_.CommandLineTemplate) { $_.CommandLineTemplate } elseif ($_.ExecutablePath) { $_.ExecutablePath } else { 'script (' + $_.ScriptingEngine + ')' }
        [ordered]@{ name = [string]$_.Name; command = [string]$cmd }
    })
}

$out | ConvertTo-Json -Depth 5 -Compress
