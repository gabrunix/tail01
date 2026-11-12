#Requires -Version 5.1
<#
.SYNOPSIS
    G4brun1x Remote Access: OpenSSH Server + Tailscale, without tray UI.
.DESCRIPTION
    Windows 10/11; execute locally as Administrator.
    Downloads the latest official stable Tailscale MSI (no winget required),
    installs OpenSSH Server, logs in interactively from the console,
    enables unattended mode and restricts SSH inbound access to Tailscale.
    Does not install a hidden service: Tailscale and SSH remain visible in
    Windows Services and Installed Apps. Use only on devices you administer.
.NOTES
    Run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\G4brun1x-RemoteAccess.ps1
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:LogDirectory = Join-Path $env:ProgramData 'G4brun1x-RemoteAccess'
$script:LogFile = Join-Path $script:LogDirectory 'setup.log'
$script:FirewallRuleName = 'G4brun1x-OpenSSH-Tailscale-Only'

function Write-Step([string]$Message) {
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}
function Write-OK([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}
function Write-WarningMessage([string]$Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
}
function Require-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Ejecuta PowerShell como administrador y vuelve a lanzar el script.'
    }
}
function Get-TailscaleExe {
    $paths = @(
        (Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe')
    )
    if (${env:ProgramFiles(x86)}) {
        $paths += (Join-Path ${env:ProgramFiles(x86)} 'Tailscale\tailscale.exe')
        $paths += (Join-Path ${env:ProgramFiles(x86)} 'Tailscale IPN\tailscale.exe')
    }
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    }
    $command = Get-Command tailscale.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}
function Install-OpenSSH {
    Write-Step 'Preparando OpenSSH Server y Client...'
    foreach ($feature in @('OpenSSH.Server~~~~0.0.1.0', 'OpenSSH.Client~~~~0.0.1.0')) {
        $item = Get-WindowsCapability -Online -Name $feature
        if (-not $item) { throw "No se encontro la capacidad $feature en este Windows." }
        if ($item.State -ne 'Installed') {
            Write-Host "    Instalando $feature (puede usar Windows Update)..."
            $result = Add-WindowsCapability -Online -Name $feature
            if ($result.RestartNeeded) {
                Write-WarningMessage "Windows solicita reinicio para finalizar $feature."
            }
        } else {
            Write-OK "$feature ya instalado"
        }
    }
    $sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $sshd) { throw 'El servicio sshd no aparece tras instalar OpenSSH. Revisa si Windows necesita reiniciar.' }
    Set-Service -Name sshd -StartupType Automatic
    if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }
    Write-OK 'sshd iniciado y configurado en Automatico'

    # Use PowerShell as the default remote SSH shell.
    $openSSHReg = 'HKLM:\SOFTWARE\OpenSSH'
    if (-not (Test-Path $openSSHReg)) { New-Item -Path $openSSHReg -Force | Out-Null }
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    New-ItemProperty -Path $openSSHReg -Name 'DefaultShell' -Value $shell -PropertyType String -Force | Out-Null
    Write-OK 'PowerShell configurado como shell SSH'

    # Windows' default OpenSSH rule allows connections on all network interfaces.
    # Disable it now, and create a narrower rule ONLY after Tailscale authenticates.
    $defaultRule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    if ($defaultRule) {
        $defaultRule | Disable-NetFirewallRule
        Write-OK 'Regla SSH general de Windows desactivada'
    }
}
function Download-AndInstall-Tailscale {
    $existing = Get-TailscaleExe
    if ($existing) {
        Write-OK "Tailscale ya instalado: $existing"
        return $existing
    }
    Write-Step 'Buscando el MSI estable mas reciente en el sitio oficial de Tailscale...'
    # Ensures old Windows PowerShell installations can negotiate TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $platform = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    switch ($platform.ToUpperInvariant()) {
        'X64'   { $architecture = 'amd64'; break }
        'X86'   { $architecture = 'x86'; break }
        'ARM64' { $architecture = 'arm64'; break }
        default { throw "Arquitectura no soportada: $platform" }
    }
    $index = 'https://pkgs.tailscale.com/stable/'
    $page = Invoke-WebRequest -Uri $index -UseBasicParsing
    $regex = 'tailscale-setup-\d+(?:\.\d+){2,3}-' + [regex]::Escape($architecture) + '\.msi'
    $matches = [regex]::Matches([string]$page.Content, $regex)
    if ($matches.Count -lt 1) {
        throw "No se encontro un MSI oficial para $architecture en $index"
    }
    $installerName = $matches[0].Value
    $url = $index + $installerName
    $msiPath = Join-Path $env:TEMP $installerName
    Write-Host "    Descargando: $url"
    Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing
    if (-not (Test-Path $msiPath)) { throw 'Fallo la descarga del MSI.' }

    # Verify checksum published by Tailscale AND Windows Authenticode signature.
    $hashText = (Invoke-WebRequest -Uri ($url + '.sha256') -UseBasicParsing).Content
    $match = [regex]::Match([string]$hashText, '(?i)\b[0-9a-f]{64}\b')
    if (-not $match.Success) { throw 'No se pudo interpretar el SHA256 oficial de Tailscale.' }
    $localHash = (Get-FileHash -Algorithm SHA256 -Path $msiPath).Hash
    if ($localHash -ine $match.Value) { throw 'El SHA256 del instalador no coincide con el publicado por Tailscale.' }
    $signature = Get-AuthenticodeSignature -FilePath $msiPath
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch 'Tailscale') {
        throw "La firma digital del MSI no pudo validarse como Tailscale (estado: $($signature.Status))."
    }
    Write-OK 'Descarga validada mediante SHA256 y firma digital'

    Write-Step 'Instalando Tailscale sin iniciar su interfaz grafica...'
    $msiLog = Join-Path $script:LogDirectory 'tailscale-msi.log'
    $args = @('/i', ('"' + $msiPath + '"'), '/qn', '/norestart',
              'TS_NOLAUNCH=1', 'TS_INSTALLUPDATES=always',
              '/L*v', ('"' + $msiLog + '"'))
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru
    if ($proc.ExitCode -notin @(0, 3010)) {
        throw "MSI finalizo con error $($proc.ExitCode). Consulta $msiLog"
    }
    if ($proc.ExitCode -eq 3010) { Write-WarningMessage 'MSI recomienda reiniciar Windows al finalizar.' }
    $exe = Get-TailscaleExe
    if (-not $exe) { throw 'Tailscale parece instalado pero tailscale.exe no fue localizado.' }
    Write-OK "Tailscale instalado: $exe"
    return $exe
}
function Start-TailscaleService {
    Write-Step 'Arrancando el servicio de Tailscale...'
    $service = Get-Service -Name Tailscale -ErrorAction SilentlyContinue
    if (-not $service) { throw 'No existe el servicio Tailscale. Revisa la instalacion.' }
    Set-Service Tailscale -StartupType Automatic
    if ((Get-Service Tailscale).Status -ne 'Running') { Start-Service Tailscale }
    (Get-Service Tailscale).WaitForStatus('Running', [TimeSpan]::FromSeconds(45))
    Write-OK 'Servicio Tailscale activo y configurado en Automatico'
}
function Connect-Tailscale([string]$Cli) {
    Write-Step 'Autenticacion de Tailscale'
    $state = ''
    try {
        $raw = & $Cli status --json 2>$null | Out-String
        if ($LASTEXITCODE -eq 0 -and $raw.Trim()) {
            $state = (ConvertFrom-Json $raw).BackendState
        }
    } catch { $state = '' }

    if ($state -ne 'Running') {
        Write-Host ''
        Write-Host '  Se imprimira un enlace HTTPS de inicio de sesion.' -ForegroundColor Yellow
        Write-Host '  Copialo en tu navegador (incluso en tu telefono), inicia sesion y autoriza el PC.'
        Write-Host '  MANTEN ESTA CONSOLA ABIERTA HASTA COMPLETAR LA AUTENTICACION.' -ForegroundColor Yellow
        Write-Host ''
        # The official CLI prints the authentication URL and waits for approval.
        & $Cli up --unattended
        if ($LASTEXITCODE -ne 0) { throw "tailscale up fallo (codigo $LASTEXITCODE)." }
    } else {
        Write-OK 'Este equipo ya aparece autenticado en Tailscale'
    }

    # This must be set AFTER authentication to survive logoff/restart on Windows.
    & $Cli set --unattended=true
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo activar el modo desatendido de Tailscale.' }
    Write-OK 'Modo desatendido activado: sigue conectado sin sesion de Windows'

    $raw = & $Cli status --json | Out-String
    if ($LASTEXITCODE -ne 0 -or (ConvertFrom-Json $raw).BackendState -ne 'Running') {
        throw 'La autenticacion termino, pero Tailscale no muestra estado Running.'
    }
    $ip = ((& $Cli ip -4 | Select-Object -First 1) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $ip -notmatch '^100\.(\d{1,3}\.){2}\d{1,3}$') {
        throw "No se obtuvo una IP Tailscale IPv4 valida: '$ip'"
    }
    return $ip
}
function Protect-OpenSSHFirewall([string]$Ip) {
    Write-Step 'Protegiendo SSH: se admitiran conexiones por la interfaz Tailscale...'
    $ipConfig = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $Ip -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ipConfig) {
        throw "No se pudo identificar la interfaz con la IP Tailscale $Ip. No se habilito el puerto SSH."
    }
    $interface = $ipConfig.InterfaceAlias
    # Remove only the rule maintained by this script (repeatable/idempotent).
    Get-NetFirewallRule -Name $script:FirewallRuleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $script:FirewallRuleName `
        -DisplayName 'G4brun1x - SSH solo mediante Tailscale' `
        -Direction Inbound -Action Allow -Enabled True -Profile Any `
        -Protocol TCP -LocalPort 22 -InterfaceAlias $interface `
        -RemoteAddress '100.64.0.0/10' | Out-Null
    Write-OK "Acceso SSH permitido por adaptador '$interface' desde la tailnet (IPv4)"
    Write-WarningMessage 'Comprueba manualmente si existen otras reglas SSH de firewall creadas anteriormente.'
}
function Disable-TailscaleTray {
    Write-Step 'Desactivando el inicio automatico del icono/interfaz de Tailscale...'
    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    )
    # Also cover active/loaded user profiles, without loading or modifying offline hives.
    $hives = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-[0-9-]+$' }
    foreach ($hive in $hives) {
        $registryPaths += "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
    }
    foreach ($path in ($registryPaths | Select-Object -Unique)) {
        if (-not (Test-Path $path)) { continue }
        try {
            $property = Get-ItemProperty -LiteralPath $path -Name 'Tailscale' -ErrorAction SilentlyContinue
            if ($property -and ($property.Tailscale -match '(?i)tailscale-ipn(\.exe)?|[\\/]Tailscale[\\/]')) {
                Remove-ItemProperty -LiteralPath $path -Name Tailscale -Force
                Write-Host "    Inicio grafico eliminado de $path"
            }
        } catch {
            Write-WarningMessage "No se pudo revisar entrada de inicio: $path"
        }
    }

    $startupDirectories = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    foreach ($dir in ($startupDirectories | Select-Object -Unique)) {
        $shortcut = Join-Path $dir 'Tailscale.lnk'
        if (Test-Path -LiteralPath $shortcut) {
            Remove-Item -LiteralPath $shortcut -Force
            Write-Host "    Acceso directo de inicio eliminado: $shortcut"
        }
    }
    # The GUI and service are separate; do NOT stop tailscaled / Tailscale service.
    Get-Process -Name 'tailscale-ipn' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Write-OK 'GUI cerrada y autoarranque habitual desactivado; servicio conservado'
    Write-WarningMessage 'El icono podria reaparecer tras futuras actualizaciones o en perfiles de Windows no cargados.'
}
function Show-Result([string]$Cli, [string]$Ip) {
    Write-Host ''
    Write-Host '========================================================' -ForegroundColor Green
    Write-Host '          G4BRUN1X REMOTE ACCESS - TERMINADO' -ForegroundColor Green
    Write-Host '========================================================' -ForegroundColor Green
    Write-Host ('Equipo          : ' + $env:COMPUTERNAME)
    Write-Host ('Usuario Windows : ' + $env:USERNAME)
    Write-Host ('IP Tailscale    : ' + $Ip) -ForegroundColor Cyan
    Write-Host ('Comando SSH     : ssh ' + $env:USERNAME + '@' + $Ip) -ForegroundColor Yellow
    Write-Host ('Servicio SSH    : ' + (Get-Service sshd).Status)
    Write-Host ('Servicio VPN    : ' + (Get-Service Tailscale).Status)
    Write-Host ('Interfaz GUI    : No iniciada automaticamente (usuario actual / inicio comun)')
    Write-Host ''
    Write-Host 'Para consultar desde esta consola:'
    Write-Host ('  & "' + $Cli + '" status')
    Write-Host ('  & "' + $Cli + '" ip -4')
    Write-Host ''
    Write-Host 'Desde otro equipo con Tailscale en la misma tailnet:'
    Write-Host ('  ssh ' + $env:USERNAME + '@' + $Ip) -ForegroundColor Yellow
    Write-Host 'Usa la contrasena REAL de Windows o tu llave SSH (no el PIN de Windows Hello).'
    Write-Host 'Tu PC debe permanecer encendido y sin suspension.'
    Write-Host '========================================================' -ForegroundColor Green
}

try {
    Require-Admin
    if (-not [Environment]::OSVersion.Platform.ToString().Equals('Win32NT')) {
        throw 'Este script es exclusivo para Windows.'
    }
    if (-not (Test-Path $script:LogDirectory)) {
        New-Item -Path $script:LogDirectory -ItemType Directory -Force | Out-Null
    }
    "[$(Get-Date -Format o)] Inicio G4brun1x Remote Access en $env:COMPUTERNAME" |
        Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host '       G4BRUN1X REMOTE ACCESS - Windows 10/11' -ForegroundColor Cyan
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-WarningMessage 'Se restringira el firewall SSH a Tailscale. Ejecuta localmente, no desde SSH.'
    Install-OpenSSH
    $tailscale = Download-AndInstall-Tailscale
    Start-TailscaleService
    $tailscaleIP = Connect-Tailscale -Cli $tailscale
    Protect-OpenSSHFirewall -Ip $tailscaleIP
    Disable-TailscaleTray
    Show-Result -Cli $tailscale -Ip $tailscaleIP
    "[$(Get-Date -Format o)] Instalacion finalizada. IP: $tailscaleIP" |
        Out-File -FilePath $script:LogFile -Append -Encoding UTF8
} catch {
    Write-Host ''
    Write-Host ('[ERROR] ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host 'Comprueba tu conexion a Internet, Windows Update, permisos y certificados.'
    Write-Host ('Log de instalacion: ' + $script:LogFile)
    if (Test-Path $script:LogDirectory) {
        "[$(Get-Date -Format o)] ERROR: $($_.Exception.Message)" |
            Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    }
    exit 1
}