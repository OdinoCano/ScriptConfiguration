function Get-Config {
    param([string]$path)
    try {
        $response = Invoke-RestMethod -Uri "$apiURL/config/$path" -Method Get -Headers @{ "Content-Type" = "application/json" } -TimeoutSec 10
    }
    catch {
        Write-Host "Fallo la API, leyendo el archivo de configuración local..."
        if (Test-Path $jsonPath) {
            $response = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        } else {
            Write-Host "No se encontró el archivo de configuración local."
            exit 1
        }
    }
    return $response
}

function Set-Admin {
    param (
        [string]$adminUsername,
        [securestring]$adminPassword
    )
    # Cambiar contraseña del administrador y activarlo
    Set-LocalUser -Name $adminUsername -Password $adminPassword
    Enable-LocalUser -Name $adminUsername

    Write-Host "El equipo se reiniciará en 10 segundos..."
    Start-Sleep -Seconds 10
    Restart-Computer -Force
    Write-Host "Reiniciando"
}

function Find-Microsip {
    $microsipExe = "Microsip.exe"
    $searchPaths = @(
        "C:\Program Files (x86)\Microsip",
        "C:\Program Files\Microsip",
        "C:\Archivos de programa (x86)\Microsip",
        "C:\Archivos de programa\Microsip",
        "C:\Users\$env:USERNAME\AppData\Local\Programs\Microsip",
        "C:\Users\$env:USERNAME\AppData\Local\Microsip",
        "C:\Users\$env:USERNAME\AppData\Roaming\Microsip",
        "C:\Users\$env:USERNAME\AppData\Local\Microsip\Microsip"
    )
    foreach ($path in $searchPaths) {
        $exePath = Join-Path $path $microsipExe
        if (Test-Path $exePath) {
            return $exePath
        }
    }
    # If not found in common paths, search entire C: drive (may take time)
    $found = Get-ChildItem -Path "C:\" -Filter $microsipExe -Recurse -ErrorAction SilentlyContinue -Force | Select-Object -First 1
    if ($found) {
        return $found.FullName
    } else {
        return $null
    }
}

function Find-Chrome {
    $chromeExe = "chrome.exe"
    $searchPaths = @(
        "C:\Program Files\Google\Chrome\Application",
        "C:\Program Files (x86)\Google\Chrome\Application",
        "C:\Archivos de programa\Google\Chrome\Application",
        "C:\Archivos de programa (x86)\Google\Chrome\Application"
    )
    foreach ($path in $searchPaths) {
        $exePath = Join-Path $path $chromeExe
        if (Test-Path $exePath) {
            return $exePath
        }
    }
    # If not found in common paths, search entire C: drive (may take time)
    $found = Get-ChildItem -Path "C:\" -Filter $chromeExe -Recurse -ErrorAction SilentlyContinue -Force | Select-Object -First 1
    if ($found) {
        return $found.FullName
    } else {
        return $null
    }
}

function Find-StartupFolder {
    param([string]$username)
    $paths = @(
        "C:\Users\$username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\Usuarios\$username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\Users\$username\AppData\Roaming\Microsoft\Windows\Menú Inicio\Programas\Inicio",
        "C:\Usuarios\$username\AppData\Roaming\Microsoft\Windows\Menú Inicio\Programas\Inicio"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            return $path
        }
    }
    return $null
}

function Remove-Bloatware {
    $appsToRemovePatterns = @(
        # Aplicaciones comunes de bloatware
        "Microsoft.Xbox", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo", "Microsoft.WindowsMaps", "Microsoft.People", "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.BingNews",
        "Microsoft.BingWeather", "Microsoft.SkypeApp", "Microsoft.MicrosoftStickyNotes",
        "Microsoft.Todos", "Microsoft.YourPhone", "Microsoft.OneConnect", "Microsoft.MixedReality.Portal",
        "Microsoft.WindowsFeedbackHub", "Microsoft.Office.OneNote", "Microsoft.MicrosoftEdgeDevToolsClient",
        "Microsoft.Cortana", "Microsoft.XboxGameOverlay", "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxSpeechToTextOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.Xbox.TCUI",
        "Microsoft.MicrosoftMahjong", "Microsoft.MicrosoftJigsaw", "Microsoft.MicrosoftSudoku",
        "Microsoft.MicrosoftMinesweeper", "Microsoft.MicrosoftTreasureHunt", "Microsoft.MicrosoftUltimateWordGames",
        "Microsoft.MSPaint", "Microsoft.GamingApp", "Microsoft.BingSports", "Microsoft.BingFinance",
        "Microsoft.BingFoodAndDrink", "Microsoft.BingTravel", "Microsoft.BingHealthAndFitness",
        "king.com.CandyCrush", "king.com.BubbleWitch", "king.com.FarmHeroes", "king.com."
    )

    foreach ($pattern in $appsToRemovePatterns) {
        # Eliminar AppxPackage instalado por usuario
        $appxMatches = Get-AppxPackage | Where-Object { $_.Name -like "$pattern*" }
        foreach ($app in $appxMatches) {
            Write-Host "Eliminando AppxPackage: $($app.Name)"
            try {
                $app | Remove-AppxPackage -ErrorAction Stop
            } catch {
                Write-Warning "No se pudo eliminar $($app.Name): $_"
            }
        }

        # Eliminar AppxProvisionedPackage (preinstalado para nuevos usuarios)
        $provMatches = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "$pattern*" }
        foreach ($prov in $provMatches) {
            Write-Host "Eliminando ProvisionedPackage: $($prov.DisplayName)"
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop
            } catch {
                Write-Warning "No se pudo eliminar $($prov.DisplayName): $_"
            }
        }
    }

    Write-Host "Bloatware, juegos y apps innecesarias eliminadas."
}

# Verificar que se ejecute como administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Este script debe ejecutarse como administrador."
    exit 1
}

# Configuración inicial
$jsonPath = "config.json"

$config = Get-Config $args[0]
$apiURL = $config.api.url
$currentUsername = $env:USERNAME
$newUsername = $config.usuario.nombre
$newPassword = $config.usuario.contrasegna | ConvertTo-SecureString -AsPlainText -Force

# Detectar el nombre real del usuario administrador local (puede variar según idioma)
$adminUserObj = Get-LocalUser | Where-Object { $_.SID -like '*-500' }
if ($adminUserObj) {
    $adminUsername = $adminUserObj
} else {
    Write-Error "No se pudo detectar el usuario administrador local."
    exit 1
}
$adminPassword = $config.administrador.contrasegna | ConvertTo-SecureString -AsPlainText -Force

# Crear o actualizar usuario sin privilegios de administrador
$user = Get-LocalUser -Name $newUsername -ErrorAction SilentlyContinue
if ($user) {
    Write-Host "El usuario $newUsername ya existe."
    # Quitar privilegios de administrador si los tiene
    $adminGroup = (Get-LocalGroup | Where-Object { $_.SID -like '*-544' }).Name
    if (Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $newUsername }) {
        Write-Host "El usuario $newUsername tiene privilegios de administrador. Se eliminarán."
        Remove-LocalGroupMember -Group $adminGroup -Member $newUsername -ErrorAction SilentlyContinue
        # Actualizar contraseña
        Set-LocalUser -Name $newUsername -Password $newPassword
        Set-Admin -adminUsername $adminUsername -adminPassword $adminPassword
    }
} else {
    New-LocalUser -Name $newUsername -Password $newPassword -FullName $newUsername -UserMayNotChangePassword -PasswordNeverExpires
    $usersGroup = (Get-LocalGroup | Where-Object { $_.SID -like '*-545' }).Name
    Add-LocalGroupMember -Group $usersGroup -Member $newUsername
    Set-Admin -adminUsername $adminUsername -adminPassword $adminPassword
}

$softphonePath = Find-Microsip
if (-not $softphonePath) {
    Write-Host "No se encontró Microsip. Asegúrate de que esté instalado."
    exit 1
}
$chromePath = Find-Chrome
if (-not $chromePath) {
    Write-Host "No se encontró Google Chrome. Asegúrate de que esté instalado."
    exit 1
}

# Ruta base del usuario
$localAppData = [Environment]::GetFolderPath("LocalApplicationData")
$partes = $localAppData -split "$currentUsername"
$localAppData = $partes[0] + $newUsername

#$chromeUserDataRoot = Join-Path $localAppData "AppData\Local\Google\Chrome\User Data"
#
#if (Test-Path $chromeUserDataRoot) {
#    # Buscar todos los archivos 'Preferences' dentro de cualquier subcarpeta (Default, Profile 1, etc.)
#    $preferencesFiles = Get-ChildItem -Path $chromeUserDataRoot -Recurse -Filter "Preferences" -ErrorAction SilentlyContinue
#    foreach ($file in $preferencesFiles) {
#        try {
#            # Leer y convertir JSON
#            $jsonRaw = Get-Content $file.FullName -Raw
#            $prefs = $jsonRaw | ConvertFrom-Json
#
#            # Asegurar que exista 'session'
#            if (-not $prefs.PSObject.Properties["session"]) {
#                $prefs | Add-Member -MemberType NoteProperty -Name "session" -Value @{}
#            }
#
#            if ($prefs.session -isnot [System.Collections.IDictionary]) {
#                $prefs.session = @{}
#            }
#
#            # Modificar la configuración de inicio
#            $prefs.session.restore_on_startup = 4
#            $prefs.session.startup_urls = $config.chrome.urls
#
#            # Guardar el JSON actualizado
#            $prefs | ConvertTo-Json -Depth 10 -Compress | Set-Content -Path $file.FullName -Encoding UTF8
#            Write-Host "Actualizado: $($file.FullName)"
#        } catch {
#            Write-Warning "No se pudo modificar: $($file.FullName) - $_"
#        }
#    }
#} else {
#    Write-Warning "La carpeta Chrome\User Data no existe: $chromeUserDataRoot"
#}

# Configurar Microsip
$microsipConfigPath = Join-Path $localAppData "AppData\Roaming\MicroSIP\MicroSIP.ini"

if (Test-Path $microsipConfigPath) {
    # Cargar contenido del archivo
    $lines = Get-Content $microsipConfigPath

    $settingsToUpdate = @{
        "accountId"          ="1"
        "videoBitrate"       ="256"
        "featureCodeCP"      ="**"
        "featureCodeBT"      ="##"
        "featureCodeAT"      ="*2"
        "enableFeatureCodeCP"="1"
        "enableFeatureCodeBT"="0"
        "enableFeatureCodeAT"="0"
        "FWD"                ="0"
        "singleMode"         = "1"
        "volumeRing"         = "100"
        "recordingPath"      = "C:\Users\$newUsername\Desktop\Recordings"
        "audioCodecs"        = "PCMA/8000/1 PCMU/8000/1"
        "enableSTUN"         = "1"
        "STUN"               = "stun.l.google.com:19302"
    }

    $accountToUpdate = @{
        "label"              =$config.usuario.extenextension
        "server"             ="45.33.28.106:49999"
        "proxy"              ="45.33.28.106:49999"
        "domain"             ="45.33.28.106:49999"
        "username"           =$config.usuario.extenextension
        "authID"             =$config.usuario.extenextension
        "displayName"        =$config.usuario.extenextension
        "dialingPrefix"      =""
        "dialPlan"           =""
        "hideCID"            ="0"
        "voicemailNumber"    =$config.usuario.extenextension
        "transport"          ="udp"
        "publicAddr"         =""
        "SRTP"               =""
        "registerRefresh"    ="300"
        "keepAlive"          ="15"
        "publish"            ="0"
        "ICE"                ="0"
        "allowRewrite"       ="0"
        "disableSessionTimer"="0"
    }

    $inSettings = $false

    # Inicializar variables
    $updatedLines = @()
    $inSettings = $false
    $inAccount1 = $false
    $account1Found = $false
    $accountSectionName = "[Account1]"

    foreach ($line in $lines) {
        if ($line -match "^\[(.+)\]") {
            $section = $matches[1]
            $inSettings = ($section -eq "Settings")
            $inAccount1 = ($section -eq "Account1")
            if ($inAccount1) { $account1Found = $true }
            $updatedLines += $line
            continue
        }
        if ($inSettings -and $line -match "^([^=]+)=(.*)$") {
            $key = $matches[1].Trim()
            if ($settingsToUpdate.ContainsKey($key)) {
                $updatedLines += "$key=$($settingsToUpdate[$key])"
                continue
            }
        } elseif ($inAccount1 -and $line -match "^([^=]+)=(.*)$") {
            $key = $matches[1].Trim()
            if ($accountToUpdate.ContainsKey($key)) {
                $updatedLines += "$key=$($accountToUpdate[$key])"
                continue
            }
        }
        $updatedLines += $line
    }

    # Agregar [Account1] si no existe
    if (-not $account1Found) {
        $updatedLines += $accountSectionName
        foreach ($key in $accountToUpdate.Keys) {
            $updatedLines += "$key=$($accountToUpdate[$key])"
        }
    }

    # Guardar cambios
    $updatedLines | Set-Content $microsipConfigPath -Encoding UTF8
    Write-Host "Archivo de configuración actualizado correctamente."
}

# === CREAR ACCESOS DIRECTOS EN STARTUP ===
$startupFolder = Find-StartupFolder -username $newUsername
if (-not $startupFolder) {
    Write-Warning "No se encontro la carpeta de inicio para el usuario $newUsername."
    exit
}

New-Item -Path $startupFolder -ItemType Directory -Force | Out-Null
$WshShell = New-Object -ComObject WScript.Shell

$link1 = $WshShell.CreateShortcut("$startupFolder\Chrome.lnk")
$link1.TargetPath = $chromePath
$link1.Save()

$link2 = $WshShell.CreateShortcut("$startupFolder\Microsip.lnk")
$link2.TargetPath = $softphonePath
$link2.Save()

# Eliminar bloatware
Remove-Bloatware

# Habilitar RDP editando el registro directamente
$rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
try {
    if (-not (Test-Path $rdpRegPath)) {
        Write-Warning "La clave del registro para Terminal Server no existe."
        exit 1
    } else {
        $rdpEnabled = Get-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -ErrorAction Stop
        if ($rdpEnabled.fDenyTSConnections -ne 0) {
            Set-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -Value 0
            Set-Service -Name TermService -StartupType Automatic
            Start-Service -Name TermService
            Enable-NetFirewallRule -Group "@FirewallAPI.dll,-28752"
            Write-Host "Servicio de RDP habilitado e iniciado."
        } else {
            Write-Host "RDP ya estaba habilitado."
        }
    }
} catch {
    Write-Warning "Error al acceder o modificar la clave de registro de RDP: $_"
    exit 1
}

$rdpGroupSID = 'S-1-5-32-555'
$rdpGroup = Get-LocalGroup | Where-Object { $_.SID -eq $rdpGroupSID }

if ($null -eq $rdpGroup) {
    Write-Warning "No se encontró el grupo de Escritorio Remoto (SID $rdpGroupSID). ¿Está habilitada la funcionalidad de RDP?"
    exit 1
} else {
    try {
        $rdpUsers = Get-LocalGroupMember -Group $rdpGroup.Name -ErrorAction Stop
        if (-not ($rdpUsers | Where-Object { $_.Name -eq $newUsername })) {
            Add-LocalGroupMember -Group $rdpGroup.Name -Member $newUsername
            Write-Host "Usuario $newUsername agregado al grupo '$($rdpGroup.Name)'."
        } else {
            Write-Host "El usuario $newUsername ya está en el grupo '$($rdpGroup.Name)'."
        }
    } catch {
        Write-Warning "Error al trabajar con el grupo '$($rdpGroup.Name)': $_"
        exit 1
    }
}

# Habilitar Defender en su máxima protección
if (Get-Service -Name WinDefend -ErrorAction SilentlyContinue) {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -EnableControlledFolderAccess Enabled
    Set-MpPreference -EnableExploitProtection $true
    Set-MpPreference -EnableNetworkProtection $true
    Set-MpPreference -DisableIOAVProtection $false
} else {
    Write-Warning "Microsoft Defender no está habilitado. Algunas protecciones no se aplicarán."
}

# Función para establecer propiedades de registro
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [Parameter(Mandatory = $true)]$Value,
        [ValidateSet("String", "DWord", "QWord", "Binary", "MultiString", "ExpandString")]
        [string]$Type = "DWord"
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    if (-not (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    } else {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    }
}

# Prevenir DLL Injection
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1

# Bloquear ejecución de scripts de PowerShell (para no admins)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ConsoleSessionConfigurationName" -Value "RestrictedShell" -Type "String"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" -Name "EnableScripts" -Value 0

# Habilitar DEP y ASLR
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 1

# Habilitar UAC
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# Política de ejecución: solo scripts firmados
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force

# Activar protección SmartScreen
Set-MpPreference -EnableSmartScreenForExplorer $true

# Bloquear PowerShell v2
if (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue) {
    Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -NoRestart
}

# Solo el acceso de escritura
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies" -Name "WriteProtect" -Value 1

# Bloquear solo dispositivos nuevos (ya usados, permitidos)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyUnspecified" -Value 1

# Configuración de políticas de restricción de dispositivos
$usbRestrictionsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
Set-RegistryValue -Path $usbRestrictionsPath -Name "DenyDeviceIDs" -Value @(
    "USB\VID_0BDA&PID_5411",
    "USB\VID_0BDA&PID_5412"
) -Type "MultiString"

# Lista blanca de VID conocidos
$allowedVIDs = @(
    "VID_046D",  # Logitech
    "VID_045E",  # Microsoft
    "VID_04F2",  # Chicony
    "VID_1A2C",  # Teclado/mouse genérico
    "VID_05AC",  # Apple
    "VID_0BDA",  # Realtek
    "VID_0C45"   # Cámara genérica
)

Write-Host "`nDispositivos HID / Entrada conectados:`n" -ForegroundColor Cyan

# Enumerar y analizar dispositivos de entrada conectados
#Get-PnpDevice | Where-Object {
#    $_.Class -match 'Keyboard|Mouse|HID|Input' -or
#    $_.FriendlyName -match 'HID|Teclado|Keyboard|Mouse'
#} | ForEach-Object {
#    $instanceId = $_.InstanceId
#    $vid = if ($instanceId -match 'VID_([0-9A-F]{4})') { "VID_$($matches[1])" } else { "N/A" }
#    $pidValue = if ($instanceId -match 'PID_([0-9A-F]{4})') { "PID_$($matches[1])" } else { "N/A" }
#
#    Write-Host "Nombre  : $($_.FriendlyName)"
#    Write-Host "Clase   : $($_.Class)"
#    Write-Host "Estado  : $($_.Status)"
#    Write-Host "ID      : $instanceId"
#    Write-Host "VID/PID : $vid / $pidValue"
#
#    if ($vid -ne "N/A" -and $allowedVIDs -notcontains $vid) {
#        Write-Host "⚠️  Dispositivo NO reconocido (posiblemente sospechoso)" -ForegroundColor Yellow
#    } else {
#        Write-Host "✔️  Dispositivo permitido" -ForegroundColor Green
#    }
#
#    Write-Host ""
#}
#
## Protección contra dispositivos de inyección tipo Rubber Ducky
#Set-RegistryValue -Path $usbRestrictionsPath -Name "AllowDeviceIDs" -Value "" -Type "MultiString"
#
## Habilitar política contra contraseñas en blanco (fuerza bruta)
#Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

Write-Host "Configuraciones de seguridad aplicadas correctamente. Reinicia el sistema para completar los cambios." -ForegroundColor Green

Write-Host "El equipo se reiniciará en 10 segundos..."
Start-Sleep -Seconds 10
# Reiniciar el equipo
Restart-Computer -Force
Write-Host "Reiniciando"