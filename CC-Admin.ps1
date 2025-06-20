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

# Verificar que se ejecute como administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Este script debe ejecutarse como administrador."
    exit 1
}

$jsonPath = "config.json"

$config = Get-Config $args[0]

$adminUserObj = Get-LocalUser | Where-Object { $_.SID -like '*-500' }
if ($adminUserObj) {
    $adminUsername = $adminUserObj
} else {
    Write-Error "No se pudo detectar el usuario administrador local."
    exit 1
}
$adminPassword = $config.administrador.contrasegna | ConvertTo-SecureString -AsPlainText -Force

Set-Admin -adminUsername $adminUsername -adminPassword $adminPassword

# Quitar privilegios de administrador a todos los usuarios excepto el administrador local
$adminGroup = [ADSI]"WinNT://./Administrators,group"
$members = @($adminGroup.psbase.Invoke("Members")) | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }

foreach ($member in $members) {
  if ($member -ne $adminUsername) {
    try {
      $adminGroup.Remove("WinNT://./$member")
      Write-Host "Se ha quitado $member del grupo de administradores."
    } catch {
      Write-Warning "No se pudo quitar $member del grupo de administradores: $_"
    }
  }
}