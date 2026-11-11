Script para debuguear un usuario que no logra conectar por VPN IPsec (IKEv2 + SAML, FortiClient) contra un FortiGate, filtrando por su IP publica.

Requisitos:

\# Modulo Posh-SSH: `Install-Module Posh-SSH -Scope CurrentUser`

\# Usuario admin del FortiGate con acceso SSH y permisos para `diagnose`

\# FortiOS 7.2 o superior (SAML sobre IPsec requiere IKEv2 y FortiClient 7.2+)

Uso:

```powershell
.\FortiGate_IPsec_SAML_Debug.ps1 -FortiGate 10.0.0.1 -RemoteIP 190.31.53.134 -DurationSeconds 180
# multi-VDOM / puerto SSH custom / sin sniffer
.\FortiGate_IPsec_SAML_Debug.ps1 -FortiGate fw.empresa.com -Port 2222 -RemoteIP 190.31.53.134 -Vdom root -NoSniffer
```

Que hace:

1. Pre-checks: version de FortiOS, `auth-ike-saml-port` (default TCP 1001), phase1-interface con `saml-server` e `ike-version 2`, `show user saml`, estado NTP.
2. Activa `diagnose debug application ike/samld/fnbamd -1` con filtro IKE por la IP remota (prueba la sintaxis nueva `log filter rem-addr4` y cae a `log-filter` en versiones viejas).
3. En un segundo canal SSH corre `diagnose sniffer packet` para UDP 500, UDP 4500 y el puerto TCP SAML.
4. Captura durante `-DurationSeconds` mientras el usuario intenta conectar. Las lineas con error se muestran en rojo.
5. Apaga el debug siempre (bloque `finally`, incluso con Ctrl+C) y corre `diagnose vpn ike gateway list` y `diagnose firewall auth list`.
6. Genera `resumen.txt` con hallazgos heuristicos (por ejemplo: no llega trafico, NAT-T bloqueado, nunca llega al puerto SAML, proposal mismatch, problemas de hora/certificado/grupos en SAML).

No modifica la configuracion del FortiGate. Solo ejecuta comandos `get`, `show` y `diagnose`.

Salida: carpeta `FGT_IPsecSAML_<ip>_<fecha>` con `precheck.log`, `debug_ike_saml.log`, `sniffer.log`, `postcheck.log` y `resumen.txt`.

Ojo: el analisis automatico es por palabras clave y puede dar falsos positivos (por ejemplo, la palabra "group" aparece en logs normales). Confirmalo siempre leyendo `debug_ike_saml.log`. Los logs pueden contener usuarios y datos del IdP: sanitizalos antes de compartirlos.
