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
            exit
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
    $appsToRemove = @(
        # Apps comunes de bloatware y utilidades innecesarias
        "Microsoft.Xbox*", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo", "Microsoft.WindowsMaps", "Microsoft.People", "Microsoft.Microsoft3DViewer",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.BingNews",
        "Microsoft.BingWeather", "Microsoft.SkypeApp", "Microsoft.MicrosoftStickyNotes",
        "Microsoft.Todos", "Microsoft.YourPhone", "Microsoft.OneConnect", "Microsoft.MixedReality.Portal",
        "Microsoft.WindowsFeedbackHub", "Microsoft.Office.OneNote", "Microsoft.MicrosoftEdgeDevToolsClient",
        "Microsoft.Cortana", "Microsoft.XboxGameOverlay", "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxSpeechToTextOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.Xbox.TCUI",
        # Juegos y entretenimiento
        "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MicrosoftMahjong", "Microsoft.MicrosoftJigsaw",
        "Microsoft.MicrosoftSudoku", "Microsoft.MicrosoftMinesweeper", "Microsoft.MicrosoftTreasureHunt",
        "Microsoft.MicrosoftUltimateWordGames", "Microsoft.MSPaint", "Microsoft.GamingApp",
        "Microsoft.ZuneVideo", "Microsoft.ZuneMusic", "Microsoft.BingSports", "Microsoft.BingFinance",
        "Microsoft.BingFoodAndDrink", "Microsoft.BingTravel", "Microsoft.BingHealthAndFitness",
        "king.com.CandyCrush*", "king.com.BubbleWitch*", "king.com.FarmHeroes*", "king.com.*",
        "Microsoft.Xbox*", "Microsoft.XboxApp", "Microsoft.XboxGameCallableUI", "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.Xbox.TCUI"
    )

    foreach ($app in $appsToRemove) {
        $foundApp = Get-AppxPackage -Name $app
        $foundProv = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app }
        if ($foundApp -or $foundProv) {
            Write-Host "Eliminando $app..."
            if ($foundApp) { $foundApp | Remove-AppxPackage -ErrorAction SilentlyContinue }
            if ($foundProv) { $foundProv | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue }
        } else {
            Write-Host "No se encuentra la app $app"
        }
    }

    Write-Host "Aplicaciones innecesarias, juegos y entretenimiento eliminados para uso en call center."
}

# Verificar que se ejecute como administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script debe ejecutarse como administrador."
    exit
}

# Configuración inicial
$jsonPath = "config.json"

$config = Get-Config $args[0]
$apiURL = $config.api.url
$currentUsername = $env:USERNAME
$newUsername = $config.usuario.nombre
$newPassword = $config.usuario.contrasegna | ConvertTo-SecureString -AsPlainText -Force

$adminUsername = "Administrador"
$adminPassword = $config.administrador.contrasegna | ConvertTo-SecureString -AsPlainText -Force

# Crear o actualizar usuario sin privilegios de administrador
$user = Get-LocalUser -Name $newUsername -ErrorAction SilentlyContinue
if ($user) {
    Write-Host "El usuario $newUsername ya existe."
    # Quitar privilegios de administrador si los tiene
    if (Get-LocalGroupMember -Group "Administradores" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $newUsername }) {
        Write-Host "El usuario $newUsername tiene privilegios de administrador. Se eliminarán."
        Remove-LocalGroupMember -Group "Administradores" -Member $newUsername -ErrorAction SilentlyContinue
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
    exit
}
$chromePath = Find-Chrome
if (-not $chromePath) {
    Write-Host "No se encontró Google Chrome. Asegúrate de que esté instalado."
    exit
}

# Ruta base del usuario
$localAppData = [Environment]::GetFolderPath("LocalApplicationData")
$partes = $localAppData -split "$currentUsername"
$localAppData = $partes[0] + $newUsername

$chromeUserDataRoot = Join-Path $localAppData "AppData\Local\Google\Chrome\User Data"

if (Test-Path $chromeUserDataRoot) {
    # Buscar todos los archivos 'Preferences' dentro de cualquier subcarpeta (Default, Profile 1, etc.)
    $preferencesFiles = Get-ChildItem -Path $chromeUserDataRoot -Recurse -Filter "Preferences" -ErrorAction SilentlyContinue
    foreach ($file in $preferencesFiles) {
        try {
            # Leer y convertir JSON
            $jsonRaw = Get-Content $file.FullName -Raw
            $prefs = $jsonRaw | ConvertFrom-Json

            # Asegurar que exista 'session'
            if (-not $prefs.PSObject.Properties["session"]) {
                $prefs | Add-Member -MemberType NoteProperty -Name "session" -Value @{}
            }

            if ($prefs.session -isnot [System.Collections.IDictionary]) {
                $prefs.session = @{}
            }

            # Modificar la configuración de inicio
            $prefs.session.restore_on_startup = 4
            $prefs.session.startup_urls = $config.chrome.urls

            # Guardar el JSON actualizado
            $prefs | ConvertTo-Json -Depth 10 -Compress | Set-Content -Path $file.FullName -Encoding UTF8
            Write-Host "Actualizado: $($file.FullName)"
        } catch {
            Write-Warning "No se pudo modificar: $($file.FullName) - $_"
        }
    }
} else {
    Write-Warning "La carpeta Chrome\User Data no existe: $chromeUserDataRoot"
}

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
        "recordingPath"      = "C:\Users\asesor17\Desktop\Recordings"
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
        "password"           ="4f3450af2fe98cdc6b90c1a2cbffb478b91265c1dd0afcaae1df801e43829fc788fd0d510adb291ebc8d08944c49d2eb9c4e2b8827fa5634f05129a3f642d7c774654a3f92d9755d"
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

# Verificar si RDP está habilitado, si no, habilitarlo
$rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpEnabled = (Get-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections").fDenyTSConnections
if ($rdpEnabled -ne 0) {
    Set-ItemProperty -Path $rdpRegPath -Name "fDenyTSConnections" -Value 0
    Write-Host "RDP habilitado."
} else {
    Write-Host "RDP ya estaba habilitado."
}

# Verificar si hay usuarios habilitados para RDP
$rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
if (-not $rdpUsers) {
    # Agregar el usuario configurado al grupo de RDP
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $newUsername
    Write-Host "Usuario $newUsername agregado al grupo de Remote Desktop Users."
} else {
    Write-Host "Ya existen usuarios en el grupo de Remote Desktop Users."
}

# Habilitar servicio RDP
Set-Service -Name TermService -StartupType Automatic
Start-Service -Name TermService

# Función para establecer propiedades de registro
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [Parameter(Mandatory = $true)]$Value,
        [string]$Type = "DWord"
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

# Prevenir DLL Injection
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1

# Bloquear ejecución de scripts de PowerShell (para no admins)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" -Name "EnableScripts" -Value 0

# Restringe la ejecución a configuraciones controladas
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ConsoleSessionConfigurationName" -Value "RestrictedShell" -Type String

# Política de ejecución: solo scripts firmados
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force

# Activar protección SmartScreen
Set-MpPreference -EnableSmartScreenForExplorer $true

# Habilitar DEP y ASLR
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 1

# Habilitar UAC
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# Habilitar Defender en su máxima protección
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -EnableExploitProtection $true
Set-MpPreference -EnableNetworkProtection $true
Set-MpPreference -DisableIOAVProtection $false

# Bloquear PowerShell v2
Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -NoRestart

# Bloquear dispositivos USB
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4

Write-Host "Configuraciones de seguridad aplicadas correctamente. Reinicia el sistema para completar los cambios." -ForegroundColor Green

Write-Host "El equipo se reiniciará en 10 segundos..."
Start-Sleep -Seconds 10
# Reiniciar el equipo
Restart-Computer -Force
Write-Host "Reiniciando"
