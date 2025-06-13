# Verifica si hay políticas que bloqueen dispositivos no especificados
$restrictionsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if (Test-Path $restrictionsPath) {
    $denyUnspecified = Get-ItemProperty -Path $restrictionsPath -Name "DenyUnspecified" -ErrorAction SilentlyContinue
    if ($denyUnspecified.DenyUnspecified -eq 1) {
        Remove-ItemProperty -Path $restrictionsPath -Name "DenyUnspecified" -Force
        Write-Host "Política 'DenyUnspecified' eliminada." -ForegroundColor Green
    }
}

# Eliminar listas de dispositivos bloqueados (DenyDeviceIDs)
Remove-ItemProperty -Path $restrictionsPath -Name "DenyDeviceIDs" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $restrictionsPath -Name "DenyDeviceClasses" -ErrorAction SilentlyContinue

# Eliminar la clave completa si está vacía
if ((Get-Item -Path $restrictionsPath).Property.Count -eq 0) {
    Remove-Item -Path $restrictionsPath -Force
}

$hidClassGuid = "{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}"  # GUID de dispositivos HID
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\AllowDeviceClasses" -Name "1" -Value $hidClassGuid -Type String -Force

# Desactiva la protección
Set-MpPreference -EnableControlledFolderAccess Disabled

# Obtén el ID de hardware del mouse (conéctalo primero)
$mouseID = (Get-PnpDevice -Class Mouse | Where-Object { $_.Status -eq "OK" }).InstanceId

# Añádelo a las exclusiones de Defender (si aplica)
Add-MpPreference -ExclusionDevice $mouseID

# Configurar Windows para permitir controladores no firmados (solo en modo pruebas)
bcdedit /set nointegritychecks on
bcdedit /set testsigning on

gpupdate /force
# Desactiva la protección en tiempo real temporalmente
Set-MpPreference -DisableRealtimeMonitoring $true

Restart-Service -Name WinDefend -Force
