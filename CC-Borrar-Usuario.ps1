# 1. Cerrar sesión del usuario si está activa
# *Este paso es manual si el usuario está logueado*
$username = "asesor17"
# 2. Eliminar el usuario local
if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name $username
    Write-Host "Usuario $username eliminado."
}

# 3. Eliminar carpeta(s) de perfil que comiencen con el nombre del usuario
$matchingProfiles = Get-ChildItem -Path "C:\Users" -Directory | Where-Object {
    $_.Name -like "$username*"
}
foreach ($profile in $matchingProfiles) {
    try {
        Remove-Item -Recurse -Force -Path $profile.FullName
        Write-Host "Carpeta del perfil eliminada: $($profile.FullName)"
    } catch {
        Write-Warning "No se pudo eliminar: $($profile.FullName) - $_"
    }
}

# 4. Eliminar entrada del registro del perfil
$regKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
Get-ChildItem $regKey | ForEach-Object {
    $sidKey = $_.PSChildName
    $path = (Get-ItemProperty "$regKey\$sidKey").ProfileImagePath
    if ($path -like "*\$username") {
        Remove-Item "$regKey\$sidKey" -Recurse -Force
        Write-Host "Clave del registro eliminada: $sidKey"
    }
}