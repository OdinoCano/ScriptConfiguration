function Get-Config {
    param([string]$path)
    
    # Leer configuración local primero para obtener la URL de la API
    $jsonPath = "config.json"
    if (-not (Test-Path $jsonPath)) {
        Write-Error "No se encontró el archivo de configuración local ($jsonPath)."
        exit 1
    }
    
    $localConfig = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
    $apiURL = $localConfig.api.url
    
    try {
        Write-Host "Intentando obtener configuración desde API: $apiURL"
        $response = Invoke-RestMethod -Uri "$apiURL/config/$path" -Method Get -Headers @{ "Content-Type" = "application/json" } -TimeoutSec 10
        Write-Host "Configuración obtenida desde API exitosamente."
    }
    catch {
        Write-Warning "Fallo la API ($($_.Exception.Message)), usando configuración local..."
        $response = $localConfig
    }
    return $response
}

function Test-UserActiveSession {
    param([string]$username)
    
    try {
        # Verificar sesiones activas usando quser
        $sessions = quser 2>$null | Select-String $username
        if ($sessions) {
            return $true
        }
        
        # Verificar también con WMI como respaldo
        $query = "SELECT * FROM Win32_ComputerSystem WHERE UserName LIKE '%$username'"
        $userLoggedIn = Get-WmiObject -Query $query | Where-Object { $_.UserName -like "*\$username" }
        return ($userLoggedIn -ne $null)
    }
    catch {
        Write-Warning "No se pudo verificar sesiones activas: $($_.Exception.Message)"
        return $false
    }
}

function Close-UserSession {
    param([string]$username)
    
    Write-Warning "El usuario '$username' tiene una sesión activa. Cerrando sesión..."
    
    try {
        # Obtener todas las sesiones del usuario
        $sessions = quser 2>$null | Select-String $username
        
        foreach ($session in $sessions) {
            # Extraer el ID de sesión (puede variar el formato)
            $sessionData = $session -split '\s+'
            $sessionId = $null
            
            # Buscar el ID numérico en la línea
            foreach ($item in $sessionData) {
                if ($item -match '^\d+$') {
                    $sessionId = $item
                    break
                }
            }
            
            if ($sessionId) {
                Write-Host "Cerrando sesión ID: $sessionId"
                logoff $sessionId /server:$env:COMPUTERNAME
            }
        }
        
        # Esperar a que las sesiones se cierren completamente
        Write-Host "Esperando a que las sesiones se cierren completamente..."
        Start-Sleep -Seconds 10
        
        # Verificar que las sesiones se cerraron
        $remainingSessions = Test-UserActiveSession -username $username
        if ($remainingSessions) {
            throw "Las sesiones del usuario '$username' no se cerraron completamente."
        }
        
        Write-Host "Sesiones de '$username' cerradas exitosamente."
        return $true
    }
    catch {
        Write-Error "No se pudo cerrar las sesiones de '$username': $($_.Exception.Message)"
        return $false
    }
}

function Update-UserProfileRegistry {
    param([string]$newUsername, [string]$sid)
    
    try {
        $profileRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        
        if (Test-Path $profileRegPath) {
            # Actualizar la ruta del perfil en el registro
            Set-ItemProperty -Path $profileRegPath -Name "ProfileImagePath" -Value "C:\Users\$newUsername"
            Write-Host "Ruta de perfil actualizada en el registro para SID: $sid"
            
            # También actualizar otras entradas relacionadas si existen
            $profilesPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            Get-ChildItem $profilesPath | ForEach-Object {
                $profilePath = $_.GetValue("ProfileImagePath")
                if ($profilePath -and $profilePath -like "*\$oldUsername") {
                    Set-ItemProperty -Path $_.PSPath -Name "ProfileImagePath" -Value ($profilePath -replace "\\$oldUsername", "\$newUsername")
                }
            }
            
            return $true
        }
        else {
            Write-Error "No se encontró la clave de registro para el perfil del usuario (SID: $sid)."
            return $false
        }
    }
    catch {
        Write-Error "Error al actualizar el registro: $($_.Exception.Message)"
        return $false
    }
}

function Test-ProfilePathDependencies {
    param([string]$oldUsername, [string]$newUsername)
    
    Write-Host "Verificando dependencias de rutas hardcodeadas..."
    
    $warnings = @()
    
    # Verificar tareas programadas
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*$oldUsername*" -or $_.Actions.Arguments -like "*$oldUsername*" }
        if ($tasks) {
            $warnings += "Se encontraron tareas programadas que referencian al usuario anterior: $($tasks.TaskName -join ', ')"
        }
    }
    catch {
        $warnings += "No se pudieron verificar las tareas programadas: $($_.Exception.Message)"
    }
    
    # Verificar servicios con rutas específicas
    try {
        $services = Get-WmiObject Win32_Service | Where-Object { $_.PathName -like "*$oldUsername*" }
        if ($services) {
            $warnings += "Se encontraron servicios que referencian al usuario anterior: $($services.Name -join ', ')"
        }
    }
    catch {
        $warnings += "No se pudieron verificar los servicios: $($_.Exception.Message)"
    }
    
    return $warnings
}

# =====================================
# SCRIPT PRINCIPAL
# =====================================

# Verificar que se ejecute como administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Este script debe ejecutarse como administrador."
    exit 1
}

Write-Host "=== INICIANDO PROCESO DE CAMBIO DE NOMBRE DE USUARIO ===" -ForegroundColor Green

# Obtener configuración
try {
    $config = Get-Config $args[0]
    $username = $config.usuario.nombre
    $newUsername = $config.usuario.change
    
    if (-not $username -or -not $newUsername) {
        Write-Error "La configuración debe incluir 'usuario.nombre' y 'usuario.change'."
        exit 1
    }
    
    Write-Host "Usuario actual: $username"
    Write-Host "Nuevo usuario: $newUsername"
}
catch {
    Write-Error "Error al obtener la configuración: $($_.Exception.Message)"
    exit 1
}

# Validaciones previas
$computerName = $env:COMPUTERNAME
if ($newUsername -eq $computerName) {
    Write-Error "El nuevo nombre de usuario no puede ser igual al nombre del equipo ($computerName)."
    exit 1
}

if ($username -eq $newUsername) {
    Write-Warning "El nombre de usuario actual ya es '$newUsername'. No se requiere cambio."
    exit 0
}

# Verificar que el usuario existe
try {
    $user = Get-LocalUser -Name $username -ErrorAction Stop
    Write-Host "Usuario '$username' encontrado."
}
catch {
    Write-Error "El usuario '$username' no existe: $($_.Exception.Message)"
    exit 1
}

# Verificar que el nuevo nombre no esté en uso
try {
    $existingUser = Get-LocalUser -Name $newUsername -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-Error "Ya existe un usuario con el nombre '$newUsername'."
        exit 1
    }
}
catch {
    Write-Host "Es normal que falle si el usuario no existe"
    exit 1
}

# Verificar y cerrar sesiones activas
if (Test-UserActiveSession -username $username) {
    $sessionClosed = Close-UserSession -username $username
    if (-not $sessionClosed) {
        Write-Error "No se pudieron cerrar las sesiones del usuario. Aborting proceso."
        exit 1
    }
}

# Verificar dependencias potenciales
$warnings = Test-ProfilePathDependencies -oldUsername $username -newUsername $newUsername
if ($warnings) {
    Write-Warning "ADVERTENCIAS ENCONTRADAS:"
    foreach ($warning in $warnings) {
        Write-Warning "- $warning"
    }
    
    $continue = Read-Host "¿Desea continuar? (s/N)"
    if ($continue -ne 's' -and $continue -ne 'S') {
        Write-Host "Proceso cancelado por el usuario."
        exit 0
    }
}

# Obtener SID antes del cambio
$userSID = $user.SID.Value
Write-Host "SID del usuario: $userSID"

# Paso 1: Cambiar el nombre de usuario
Write-Host "=== PASO 1: Cambiando nombre de usuario ===" -ForegroundColor Yellow
try {
    Rename-LocalUser -Name $username -NewName $newUsername
    Write-Host "✓ Nombre de usuario cambiado de '$username' a '$newUsername'." -ForegroundColor Green
}
catch {
    Write-Error "Error al cambiar el nombre de usuario: $($_.Exception.Message)"
    exit 1
}

# Paso 2: Cambiar la carpeta de perfil
Write-Host "=== PASO 2: Cambiando carpeta de perfil ===" -ForegroundColor Yellow
$profilePath = "C:\Users\$username"
$newProfilePath = "C:\Users\$newUsername"

if (Test-Path $profilePath) {
    try {
        # Verificar que no haya procesos usando la carpeta
        $processesUsingFolder = Get-Process | Where-Object { 
            try { 
                $_.MainModule.FileName -like "$profilePath*" 
            } catch { 
                $false 
            }
        }
        
        if ($processesUsingFolder) {
            Write-Warning "Procesos detectados usando la carpeta de perfil: $($processesUsingFolder.ProcessName -join ', ')"
            Write-Host "Esperando 5 segundos adicionales..."
            Start-Sleep -Seconds 5
        }
        
        Rename-Item -Path $profilePath -NewName $newUsername -Force
        Write-Host "✓ Carpeta de perfil cambiada de '$profilePath' a '$newProfilePath'." -ForegroundColor Green
    }
    catch {
        Write-Error "Error crítico al cambiar la carpeta de perfil: $($_.Exception.Message)"
        Write-Warning "Intentando revertir el cambio de nombre de usuario..."
        
        try {
            Rename-LocalUser -Name $newUsername -NewName $username
            Write-Host "Nombre de usuario revertido exitosamente."
        }
        catch {
            Write-Error "No se pudo revertir el cambio de nombre. Intervención manual requerida."
        }
        exit 1
    }
}
else {
    Write-Warning "La carpeta de perfil '$profilePath' no existe o ya fue cambiada."
}

# Paso 3: Actualizar el registro
Write-Host "=== PASO 3: Actualizando registro de Windows ===" -ForegroundColor Yellow
$registryUpdated = Update-UserProfileRegistry -newUsername $newUsername -sid $userSID

if (-not $registryUpdated) {
    Write-Warning "El registro no se actualizó correctamente. Esto puede causar problemas de perfil."
}

# Paso 4: Verificaciones finales
Write-Host "=== PASO 4: Verificaciones finales ===" -ForegroundColor Yellow

try {
    $updatedUser = Get-LocalUser -Name $newUsername
    if ($updatedUser.SID.Value -eq $userSID) {
        Write-Host "✓ Usuario renombrado correctamente - SID coincide." -ForegroundColor Green
    }
    else {
        Write-Warning "SID no coincide - posible problema."
    }
}
catch {
    Write-Error "Error en la verificación final: $($_.Exception.Message)"
}

# Mostrar advertencias finales
Write-Host "=== PROCESO COMPLETADO ===" -ForegroundColor Green
Write-Warning "IMPORTANTE - Acciones requeridas post-cambio:"
Write-Warning "1. Reinicia el sistema para asegurar que todos los cambios tomen efecto"
Write-Warning "2. Verifica que el usuario pueda iniciar sesión correctamente"
Write-Warning "3. Revisa manualmente:"
Write-Warning "   - Aplicaciones que puedan tener configuraciones específicas del usuario"
Write-Warning "   - Accesos directos del escritorio o menú inicio"
Write-Warning "   - Permisos ACL en archivos y carpetas críticas"
Write-Warning "   - Configuraciones de red mapeadas"
Write-Warning "   - Tareas programadas del usuario"

if ($warnings) {
    Write-Warning "4. Revisa las advertencias mostradas anteriormente sobre dependencias"
}

Write-Host "El usuario '$username' ha sido renombrado a '$newUsername' exitosamente." -ForegroundColor Green