# Script para gestionar políticas de instalación de dispositivos
# Requiere ejecutarse como Administrador

# Verificar si se ejecuta como administrador
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Este script requiere permisos de administrador." -ForegroundColor Red
    Write-Host "Ejecuta PowerShell como administrador y vuelve a intentar." -ForegroundColor Yellow
    exit 1
}

# Definir la ruta del registro
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$valueName = "DenyUnspecified"

# Función para verificar si existe la clave del registro
function Test-RegistryPath {
    param($Path)
    return Test-Path $Path
}

# Función para crear la clave del registro si no existe
function New-RegistryPath {
    param($Path)
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
        Write-Host "Creada la clave del registro: $Path" -ForegroundColor Green
    }
}

# Función para obtener el valor actual del registro
function Get-CurrentValue {
    param($Path, $Name)
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $value.$Name
    }
    catch {
        return $null
    }
}

# Función para establecer el valor del registro
function Set-RegistryValue {
    param($Path, $Name, $Value)
    try {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
        Write-Host "Valor establecido: $Name = $Value" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error al establecer el valor del registro: $_" -ForegroundColor Red
        return $false
    }
}

# Función para actualizar las políticas de grupo
function Update-GroupPolicies {
    Write-Host "Actualizando políticas de grupo..." -ForegroundColor Yellow
    try {
        & gpupdate /force
        Write-Host "Políticas de grupo actualizadas correctamente." -ForegroundColor Green
    }
    catch {
        Write-Host "Error al actualizar las políticas de grupo: $_" -ForegroundColor Red
    }
}

# Función para obtener dispositivos con problemas de políticas
function Get-RestrictedDevices {
    Write-Host "Buscando dispositivos con restricciones de políticas..." -ForegroundColor Yellow
    
    # Obtener dispositivos con problemas (código de error 22 = dispositivo deshabilitado por política)
    $restrictedDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { 
        $_.ConfigManagerErrorCode -eq 22 -or 
        $_.ConfigManagerErrorCode -eq 28 -or
        $_.Status -eq "Error"
    }
    
    if ($restrictedDevices.Count -gt 0) {
        Write-Host "Dispositivos encontrados con restricciones:" -ForegroundColor Cyan
        $restrictedDevices | ForEach-Object {
            Write-Host "  - $($_.Name) (ID: $($_.DeviceID))" -ForegroundColor White
        }
        return $restrictedDevices
    } else {
        Write-Host "No se encontraron dispositivos con restricciones de políticas." -ForegroundColor Green
        return @()
    }
}

# Función para intentar habilitar dispositivos restringidos
function Enable-RestrictedDevices {
    param($Devices)
    
    if ($Devices.Count -eq 0) {
        Write-Host "No hay dispositivos para habilitar." -ForegroundColor Green
        return
    }
    
    Write-Host "Intentando habilitar dispositivos restringidos..." -ForegroundColor Yellow
    
    foreach ($device in $Devices) {
        try {
            $deviceId = $device.DeviceID
            Write-Host "Habilitando: $($device.Name)" -ForegroundColor White
            
            # Intentar habilitar el dispositivo usando pnputil
            & pnputil /enable-device "$deviceId"
            
            # También intentar con DevCon si está disponible (método alternativo)
            # & devcon enable "$deviceId"
            
        }
        catch {
            Write-Host "  Error al habilitar $($device.Name): $_" -ForegroundColor Red
        }
    }
    
    Write-Host "Proceso de habilitación completado." -ForegroundColor Green
}

# Función para mostrar el menú de opciones
function Show-Menu {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  GESTIÓN DE POLÍTICAS DE DISPOSITIVOS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Presiona:" -ForegroundColor Yellow
    Write-Host "  ENTER - Restaurar política a 1 y finalizar" -ForegroundColor Green
    Write-Host "  ESC   - Buscar y habilitar dispositivos restringidos nuevamente" -ForegroundColor Magenta
    Write-Host "  Q     - Salir sin cambios" -ForegroundColor Red
    Write-Host ""
}

# INICIO DEL SCRIPT PRINCIPAL
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SCRIPT DE GESTIÓN DE DISPOSITIVOS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Verificar/crear la clave del registro
New-RegistryPath -Path $registryPath

# Obtener el valor actual
$currentValue = Get-CurrentValue -Path $registryPath -Name $valueName
Write-Host "Valor actual de DenyUnspecified: $currentValue" -ForegroundColor White

# Cambiar el valor a 1
Write-Host "Cambiando DenyUnspecified a 1..." -ForegroundColor Yellow
if (Set-RegistryValue -Path $registryPath -Name $valueName -Value 1) {
    
    # Actualizar políticas de grupo
    Update-GroupPolicies
    
    # Esperar un momento para que se apliquen las políticas
    Write-Host "Esperando a que se apliquen las políticas..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    
    # Buscar y mostrar dispositivos con restricciones
    $restrictedDevices = Get-RestrictedDevices
    
    # Bucle principal del menú
    do {
        Show-Menu
        
        # Leer la tecla presionada
        $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        
        switch ($key.VirtualKeyCode) {
            13 { # ENTER
                Write-Host ""
                Write-Host "Restaurando política a 1 y finalizando..." -ForegroundColor Green
                Set-RegistryValue -Path $registryPath -Name $valueName -Value 1
                Update-GroupPolicies
                Write-Host "Script finalizado." -ForegroundColor Green
                $continue = $false
            }
            27 { # ESC
                Write-Host ""
                Write-Host "Buscando dispositivos restringidos nuevamente..." -ForegroundColor Magenta
                $restrictedDevices = Get-RestrictedDevices
                Enable-RestrictedDevices -Devices $restrictedDevices
                $continue = $true
            }
            81 { # Q
                Write-Host ""
                Write-Host "Saliendo sin cambios..." -ForegroundColor Red
                $continue = $false
            }
            default {
                Write-Host ""
                Write-Host "Opción no válida. Usa ENTER, ESC o Q." -ForegroundColor Red
                $continue = $true
            }
        }
        
    } while ($continue)
    
} else {
    Write-Host "Error al cambiar el valor del registro. Abortando script." -ForegroundColor Red
}

Write-Host ""
Write-Host "Script terminado." -ForegroundColor Cyan