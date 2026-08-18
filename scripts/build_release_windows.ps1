param(
    [string]$Version = "",
    [string]$OutputDir = "",
    [string]$ProfilePath = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $Version) { $Version = (Select-String -Path (Join-Path $ProjectRoot "lib/constants.lua") -Pattern "APP_VERSION\s*=\s*'([^']+)'" | Select-Object -First 1).Matches[0].Groups[1].Value }
if (-not $OutputDir) { $OutputDir = Join-Path $ProjectRoot "dist" }
if (-not $ProfilePath) { $ProfilePath = Join-Path $ProjectRoot ".zhongkui.release.env" }
if (-not (Test-Path -LiteralPath $ProfilePath)) { throw "Release profile not found: $ProfilePath" }

$release = @{}
Get-Content -LiteralPath $ProfilePath | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        $value = $matches[2].Trim()
        if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $release[$matches[1]] = $value
    }
}

$required = @(
    "RELEASE_MYSQL_HOST", "RELEASE_MYSQL_PORT", "RELEASE_MYSQL_USER", "RELEASE_MYSQL_PASSWORD",
    "RELEASE_REDIS_HOST", "RELEASE_REDIS_PORT", "RELEASE_REDIS_PASSWORD",
    "RELEASE_LDAP_STATE", "RELEASE_LDAP_PRIMARY_SERVER", "RELEASE_LDAP_BIND_USER", "RELEASE_LDAP_BIND_PASSWORD",
    "RELEASE_LDAP_SEARCH_BASE", "RELEASE_LDAP_USER_ATTRIBUTE", "RELEASE_LDAP_BIND_TEMPLATE",
    "RELEASE_LDAP_START_TLS", "RELEASE_LDAP_TLS_VERIFY", "RELEASE_LDAP_TIMEOUT",
    "RELEASE_DINGTALK_STATE", "RELEASE_DINGTALK_WEBHOOK"
)
foreach ($name in $required) { if (-not $release[$name]) { throw "Missing $name in $ProfilePath" } }

$workDir = Join-Path $ProjectRoot ".release-work-windows"
if (Test-Path -LiteralPath $workDir) { Remove-Item -LiteralPath $workDir -Recurse -Force }
New-Item -ItemType Directory -Path $workDir, $OutputDir -Force | Out-Null

function Set-ConfigValue($object, [string]$name, $value) {
    if ($null -eq $object.PSObject.Properties[$name]) { $object | Add-Member -NotePropertyName $name -NotePropertyValue $value }
    else { $object.$name = $value }
}

try {
    foreach ($role in @("master", "node")) {
        $packageName = "zhongkui-waf-$role-$Version"
        $stageDir = Join-Path $workDir $packageName
        New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
        Get-ChildItem -LiteralPath $ProjectRoot -Force | Where-Object { $_.Name -notin @(".release-work-windows", ".release-work", "dist") } |
            Copy-Item -Destination $stageDir -Recurse -Force

        $configPath = Join-Path $stageDir "conf/system-$role.json"
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        Set-ConfigValue $config.redis "host" $release.RELEASE_REDIS_HOST
        Set-ConfigValue $config.redis "port" ([int]$release.RELEASE_REDIS_PORT)
        Set-ConfigValue $config.redis "password" $release.RELEASE_REDIS_PASSWORD
        if ($role -eq "master") {
            Set-ConfigValue $config.mysql "host" $release.RELEASE_MYSQL_HOST
            Set-ConfigValue $config.mysql "port" ([int]$release.RELEASE_MYSQL_PORT)
            Set-ConfigValue $config.mysql "user" $release.RELEASE_MYSQL_USER
            Set-ConfigValue $config.mysql "password" $release.RELEASE_MYSQL_PASSWORD
        }
        Set-ConfigValue $config.ldap "state" $release.RELEASE_LDAP_STATE
        Set-ConfigValue $config.ldap "servers" @($release.RELEASE_LDAP_PRIMARY_SERVER, $release.RELEASE_LDAP_BACKUP_SERVER | Where-Object { $_ })
        Set-ConfigValue $config.ldap "bind_user" $release.RELEASE_LDAP_BIND_USER
        Set-ConfigValue $config.ldap "bind_password" $release.RELEASE_LDAP_BIND_PASSWORD
        Set-ConfigValue $config.ldap "search_base" $release.RELEASE_LDAP_SEARCH_BASE
        Set-ConfigValue $config.ldap "user_attribute" $release.RELEASE_LDAP_USER_ATTRIBUTE
        Set-ConfigValue $config.ldap "bind_template" $release.RELEASE_LDAP_BIND_TEMPLATE
        Set-ConfigValue $config.ldap "start_tls" $release.RELEASE_LDAP_START_TLS
        Set-ConfigValue $config.ldap "tls_verify" $release.RELEASE_LDAP_TLS_VERIFY
        Set-ConfigValue $config.ldap "timeout" ([int]$release.RELEASE_LDAP_TIMEOUT)
        Set-ConfigValue $config.dingtalk "state" $release.RELEASE_DINGTALK_STATE
        Set-ConfigValue $config.dingtalk "webhook" $release.RELEASE_DINGTALK_WEBHOOK
        Set-ConfigValue $config.dingtalk "at_mobiles" $release.RELEASE_DINGTALK_AT_MOBILES
        $config | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $configPath -Encoding utf8

        $otherRole = if ($role -eq "master") { "node" } else { "master" }
        foreach ($path in @(".git", ".github", ".codeartsdoer", ".codex", "dist", "release", ".release-work", ".release-work-native", ".release-work-windows", "docs/superpowers", "ssh", ".zhongkui.private.env", ".zhongkui.release.env", "conf/system.json", "conf/system-$otherRole.json")) {
            $target = Join-Path $stageDir $path
            if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
        }

        $archive = Join-Path $OutputDir "$packageName.tar.gz"
        Remove-Item -LiteralPath $archive, "$archive.sha256" -Force -ErrorAction SilentlyContinue
        & node (Join-Path $PSScriptRoot "create_release_archive.js") $workDir $archive $packageName
        if ($LASTEXITCODE -ne 0) { throw "archive creation failed for $role" }
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath "$archive.sha256" -Value "$hash  $packageName.tar.gz" -NoNewline -Encoding ascii
        Write-Output "Release created: $archive"
    }
}
finally {
    if (Test-Path -LiteralPath $workDir) { Remove-Item -LiteralPath $workDir -Recurse -Force }
}
