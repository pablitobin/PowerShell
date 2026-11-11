<#
.SYNOPSIS
    Captura debug de IKE/SAML en un FortiGate para una IP publica de usuario que no logra conectar
    por VPN IPsec (IKEv2 + SAML, FortiClient).

.DESCRIPTION
    - Se conecta por SSH al FortiGate (modulo Posh-SSH).
    - Pre-checks: version, puerto SAML para IKE, phase1 con SAML, config de user saml.
    - Activa debug de ike / samld / fnbamd filtrado por la IP remota.
    - En paralelo (otro canal SSH) corre un sniffer para UDP 500/4500 y el puerto TCP SAML.
    - Deja correr N segundos mientras el usuario intenta conectar.
    - Apaga el debug SIEMPRE (incluso con Ctrl+C) y guarda todo en una carpeta.
    - Al final hace un analisis heuristico de los logs y sugiere causas probables.

    No modifica la configuracion del FortiGate (solo comandos diagnose / show / get).

.EXAMPLE
    .\FortiGate_IPsec_SAML_Debug.ps1 -FortiGate 10.0.0.1 -RemoteIP 190.31.53.134 -DurationSeconds 180

.EXAMPLE
    .\FortiGate_IPsec_SAML_Debug.ps1 -FortiGate fw.empresa.com -Port 2222 -RemoteIP 190.31.53.134 -Vdom root -NoSniffer
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$FortiGate,
    [Parameter(Mandatory)] [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')] [string]$RemoteIP,
    [int]$Port = 22,
    [pscredential]$Credential = (Get-Credential -Message "Admin del FortiGate"),
    [int]$DurationSeconds = 120,
    [string]$Vdom,
    [int]$SamlPort = 0,          # 0 = autodetectar (auth-ike-saml-port, default 1001)
    [switch]$NoSniffer,
    [string]$OutputDir = (Join-Path (Get-Location) ("FGT_IPsecSAML_{0}_{1}" -f $RemoteIP, (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    throw "Falta el modulo Posh-SSH. Instalalo con: Install-Module Posh-SSH -Scope CurrentUser"
}
Import-Module Posh-SSH

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$PrecheckLog = Join-Path $OutputDir 'precheck.log'
$DebugLog    = Join-Path $OutputDir 'debug_ike_saml.log'
$SnifferLog  = Join-Path $OutputDir 'sniffer.log'
$PostLog     = Join-Path $OutputDir 'postcheck.log'
$SummaryFile = Join-Path $OutputDir 'resumen.txt'

$PromptRegex = '(?m)^[^\r\n]*\S+ (\([^)]*\) )?[#$] ?$'

#region helpers
function Read-Stream {
    param($Stream)
    $sb = [System.Text.StringBuilder]::new()
    while ($Stream.DataAvailable) {
        $chunk = $Stream.Read()
        if ($chunk -match '--More--') {
            $Stream.Write(' ')
            $chunk = $chunk -replace '\s*--More--\s*', ''
        }
        [void]$sb.Append($chunk)
        Start-Sleep -Milliseconds 50
    }
    $sb.ToString()
}

function Invoke-FgtCommand {
    param($Stream, [string]$Command, [int]$TimeoutSec = 20)
    $Stream.WriteLine($Command)
    $out = [System.Text.StringBuilder]::new()
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        Start-Sleep -Milliseconds 300
        [void]$out.Append((Read-Stream $Stream))
    } until (($out.ToString() -match $PromptRegex -and -not $Stream.DataAvailable) -or (Get-Date) -gt $deadline)
    $out.ToString()
}

function Write-Log {
    param([string]$Path, [string]$Text)
    Add-Content -Path $Path -Value $Text -Encoding UTF8
}
#endregion

$session = $null
$dbg = $null
$snf = $null
$debugEnabled = $false

try {
    Write-Host "[*] Conectando a $FortiGate`:$Port ..." -ForegroundColor Cyan
    $session = New-SSHSession -ComputerName $FortiGate -Port $Port -Credential $Credential -AcceptKey -ConnectionTimeout 15
    $dbg = New-SSHShellStream -SessionId $session.SessionId -TerminalName 'vt100' -Columns 250 -Rows 500
    Start-Sleep -Seconds 2
    [void](Read-Stream $dbg)   # banner

    if ($Vdom) {
        Write-Log $PrecheckLog (Invoke-FgtCommand $dbg 'config vdom')
        Write-Log $PrecheckLog (Invoke-FgtCommand $dbg "edit $Vdom")
    }

    #region pre-checks
    Write-Host "[*] Pre-checks..." -ForegroundColor Cyan
    $status = Invoke-FgtCommand $dbg 'get system status'
    Write-Log $PrecheckLog $status

    $major = 0; $minor = 0
    if ($status -match 'v(\d+)\.(\d+)\.(\d+)') {
        $major = [int]$Matches[1]; $minor = [int]$Matches[2]
        Write-Host ("    FortiOS {0}.{1}.{2}" -f $Matches[1], $Matches[2], $Matches[3])
    }
    if ($major -gt 0 -and ($major -lt 7 -or ($major -eq 7 -and $minor -lt 2))) {
        Write-Warning "FortiOS < 7.2: IPsec + SAML (IKEv2) no esta soportado en esta version."
    }

    $globalCmd = 'show full-configuration system global | grep saml'
    if ($Vdom) {
        # system global es de contexto global
        Write-Log $PrecheckLog (Invoke-FgtCommand $dbg 'end')
        Write-Log $PrecheckLog (Invoke-FgtCommand $dbg 'config global')
    }
    $global = Invoke-FgtCommand $dbg $globalCmd
    Write-Log $PrecheckLog $global
    if ($Vdom) {
        Write-Log $PrecheckLog (Invoke-FgtCommand $dbg 'end')
        Write-Log $PrecheckLog (Invoke-FgtCommand $dbg 'config vdom')
        Write-Log $PrecheckLog (Invoke-FgtCommand $dbg "edit $Vdom")
    }

    if ($SamlPort -eq 0) {
        $SamlPort = if ($global -match 'auth-ike-saml-port\s+(\d+)') { [int]$Matches[1] } else { 1001 }
    }
    Write-Host "    Puerto SAML IKE: TCP $SamlPort"

    $p1 = Invoke-FgtCommand $dbg 'show vpn ipsec phase1-interface | grep -f saml'
    Write-Log $PrecheckLog $p1
    if ($p1 -notmatch 'saml-server') {
        Write-Warning "No encontre ninguna phase1-interface con 'saml-server'. El tunel no tiene SAML configurado (o esta en otra VDOM)."
    } elseif ($p1 -notmatch 'ike-version 2') {
        Write-Warning "La phase1 con SAML no muestra 'ike-version 2'. SAML sobre IPsec requiere IKEv2."
    }

    Write-Log $PrecheckLog (Invoke-FgtCommand $dbg 'show user saml')

    # IKE sobre TCP (FortiOS 7.4): puerto en system settings y 'transport' en la phase1
    $sett = Invoke-FgtCommand $dbg 'show full-configuration system settings | grep ike-tcp-port'
    Write-Log $PrecheckLog $sett
    $IkeTcpPort = if ($sett -match 'ike-tcp-port\s+(\d+)') { [int]$Matches[1] } else { 4500 }
    if ($p1 -match 'set transport (tcp|auto)') {
        Write-Host "    Phase1 permite IKE sobre TCP (transport $($Matches[1])), puerto TCP $IkeTcpPort"
    }
    Write-Log $PrecheckLog (Invoke-FgtCommand $dbg 'diagnose sys ntp status' -TimeoutSec 10)
    #endregion

    #region debug
    Write-Host "[*] Activando debug filtrado por $RemoteIP ..." -ForegroundColor Cyan
    $setup = @(
        'diagnose debug disable'
        'diagnose debug reset'
    )
    foreach ($c in $setup) { Write-Log $DebugLog (Invoke-FgtCommand $dbg $c) }

    # La sintaxis del filtro de IKE cambio entre versiones: probamos la nueva y caemos a la vieja.
    Write-Log $DebugLog (Invoke-FgtCommand $dbg 'diagnose vpn ike log filter clear')
    $f = Invoke-FgtCommand $dbg "diagnose vpn ike log filter rem-addr4 $RemoteIP"
    Write-Log $DebugLog $f
    if ($f -match 'Command fail|Unknown action|command parse error') {
        Write-Log $DebugLog (Invoke-FgtCommand $dbg 'diagnose vpn ike log-filter clear')
        $f = Invoke-FgtCommand $dbg "diagnose vpn ike log-filter rem-addr4 $RemoteIP"
        Write-Log $DebugLog $f
        if ($f -match 'Command fail|Unknown action|command parse error') {
            Write-Log $DebugLog (Invoke-FgtCommand $dbg "diagnose vpn ike log-filter dst-addr4 $RemoteIP")
        }
    }

    $enable = @(
        'diagnose debug application ike -1'
        'diagnose debug application samld -1'
        'diagnose debug application fnbamd -1'
        'diagnose debug console timestamp enable'
        'diagnose debug enable'
    )
    foreach ($c in $enable) { Write-Log $DebugLog (Invoke-FgtCommand $dbg $c) }
    $debugEnabled = $true

    if (-not $NoSniffer) {
        $snf = New-SSHShellStream -SessionId $session.SessionId -TerminalName 'vt100' -Columns 250 -Rows 500
        Start-Sleep -Seconds 1
        [void](Read-Stream $snf)
        if ($Vdom) {
            [void](Invoke-FgtCommand $snf 'config vdom')
            [void](Invoke-FgtCommand $snf "edit $Vdom")
        }
        $filter = "host $RemoteIP and (udp port 500 or udp port 4500 or tcp port $IkeTcpPort or tcp port $SamlPort)"
        $snf.WriteLine("diagnose sniffer packet any '$filter' 4 0 l")
    }

    Write-Host ""
    Write-Host ">>> Pedile al usuario que intente conectar AHORA. Capturando $DurationSeconds s (Ctrl+C corta y limpia)." -ForegroundColor Yellow
    $end = (Get-Date).AddSeconds($DurationSeconds)
    while ((Get-Date) -lt $end) {
        $d = Read-Stream $dbg
        if ($d) {
            Write-Log $DebugLog $d
            foreach ($line in ($d -split "`r?`n")) {
                if ($line -match 'fail|error|mismatch|no proposal|expired|invalid|denied|reject') {
                    Write-Host $line -ForegroundColor Red
                } elseif ($line) {
                    Write-Host $line -ForegroundColor DarkGray
                }
            }
        }
        if ($snf) {
            $s = Read-Stream $snf
            if ($s) { Write-Log $SnifferLog $s; Write-Host $s -ForegroundColor Green }
        }
        Start-Sleep -Milliseconds 500
    }
    #endregion
}
finally {
    if ($snf) {
        $snf.Write([string][char]3)   # Ctrl+C para el sniffer
        Start-Sleep -Seconds 1
        Write-Log $SnifferLog (Read-Stream $snf)
        $snf.Dispose()
    }
    if ($dbg -and $debugEnabled) {
        Write-Host "`n[*] Apagando debug..." -ForegroundColor Cyan
        foreach ($c in @('diagnose debug disable', 'diagnose debug reset', 'diagnose vpn ike log filter clear')) {
            try { Write-Log $DebugLog (Invoke-FgtCommand $dbg $c) } catch { Write-Warning "No pude ejecutar '$c': $_" }
        }
        try {
            Write-Log $PostLog (Invoke-FgtCommand $dbg 'diagnose vpn ike gateway list' -TimeoutSec 30)
            Write-Log $PostLog (Invoke-FgtCommand $dbg 'diagnose firewall auth list' -TimeoutSec 30)
        } catch { Write-Warning "Post-checks fallaron: $_" }
    }
    if ($dbg) { $dbg.Dispose() }
    if ($session) { Remove-SSHSession -SessionId $session.SessionId | Out-Null }
}

#region analisis heuristico
$dbgText = if (Test-Path $DebugLog)   { Get-Content $DebugLog   -Raw } else { '' }
$snfText = if (Test-Path $SnifferLog) { Get-Content $SnifferLog -Raw } else { '' }
$findings = [System.Collections.Generic.List[string]]::new()

if (-not $NoSniffer) {
    $u500  = ([regex]::Matches($snfText, "$([regex]::Escape($RemoteIP))\.\d+ -> \S+\.500:")).Count
    $u4500 = ([regex]::Matches($snfText, "$([regex]::Escape($RemoteIP))\.\d+ -> \S+\.4500:")).Count
    $tSaml = ([regex]::Matches($snfText, "$([regex]::Escape($RemoteIP))\.\d+ -> \S+\.$($SamlPort):")).Count
    $findings.Add("Paquetes desde el usuario: UDP500=$u500  UDP4500=$u4500  TCP$SamlPort=$tSaml")

    if ($u500 + $u4500 + $tSaml -eq 0) {
        $findings.Add("NO llego ningun paquete desde $RemoteIP. Revisar: IP publica correcta/CGNAT del ISP, gateway configurado en FortiClient, firewall/ISP del usuario, local-in policy o geo-block en el FortiGate.")
    } elseif ($u500 -gt 0 -and $u4500 -eq 0 -and $dbgText -notmatch 'SA proposal chosen') {
        $findings.Add("Llega UDP 500 pero nunca UDP 4500: posible NAT-T bloqueado en el camino o la negociacion muere en SA_INIT (ver debug).")
    }
    if ($u500 -gt 0 -and $tSaml -eq 0) {
        $findings.Add("Hubo IKE pero ningun intento al TCP $SamlPort (login SAML). FortiClient no abre/llega al portal SAML: puerto filtrado en la red del usuario, certificado del puerto SAML no confiable, o phase1 sin saml-server/IKEv2.")
    }
}

$patterns = [ordered]@{
    'no proposal chosen|peer SA proposal not match|negotiation failure' = 'Propuestas IKE/DH no coinciden entre FortiClient y la phase1.'
    'retransmit'                                                         = 'Hay retransmisiones IKE: las respuestas del FortiGate no llegan al cliente (fragmentacion/MTU, NAT, firewall del usuario).'
    'fragment'                                                           = 'Aparece fragmentacion IKE: probar habilitar fragmentacion IKEv2 en phase1 y FortiClient.'
    'NotBefore|NotOnOrAfter|expired|clock|skew'                          = 'Posible problema de tiempo/validez en la assertion SAML (hora del FortiGate vs IdP, o certificado vencido).'
    'signature|verify'                                                   = 'Revisar validacion de firma SAML: certificado del IdP (idp-cert) desactualizado.'
    'entity|audience|destination|acs'                                    = 'Revisar entity-id / single-sign-on-url (ACS) entre FortiGate e IdP.'
    'group|grp'                                                          = 'Revisar mapeo de grupos: user-group/group-name del claim SAML vs grupo de la phase1/politica.'
    'auth.*fail|authentication fail|denied'                              = 'Falla de autenticacion registrada (ver lineas de samld/fnbamd).'
    'certificate|cert'                                                   = 'Hay mensajes de certificados: revisar cert de la phase1 / del puerto SAML / del IdP.'
}
foreach ($k in $patterns.Keys) {
    if ($dbgText -match "(?i)$k") { $findings.Add("[debug ~ /$k/] $($patterns[$k])") }
}
if ($dbgText -notmatch [regex]::Escape($RemoteIP)) {
    $findings.Add("El debug no menciona $RemoteIP: no hubo negociacion IKE de esa IP en la ventana de captura (o el filtro no aplico en esta version).")
}

$summary = @(
    "FortiGate:  $FortiGate"
    "IP usuario: $RemoteIP"
    "Puerto SAML: $SamlPort"
    "Carpeta:    $OutputDir"
    ""
    "Hallazgos (heuristicos, confirmar leyendo los logs):"
) + ($findings | ForEach-Object { " - $_" })

$summary | Set-Content -Path $SummaryFile -Encoding UTF8
Write-Host ""
$summary | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
#endregion
