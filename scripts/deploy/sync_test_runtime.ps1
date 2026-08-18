param(
    [ValidateSet("master", "node", "all")]
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$PrivateProfile = Join-Path $ProjectRoot ".zhongkui.private.env"
if (-not (Test-Path -LiteralPath $PrivateProfile)) { throw "Private test profile not found" }

$values = @{}
Get-Content -LiteralPath $PrivateProfile | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        $values[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'")
    }
}

$targets = @()
if ($Target -in @("master", "all")) {
    $targets += @{ Name = "master"; Host = $values.host; Port = [int]$values.port; User = $values.username; Password = $values.password; Root = $values.project_root }
}
if ($Target -in @("node", "all")) {
    $targets += @{ Name = "node"; Host = $values.node_host; Port = [int]$values.node_port; User = $values.node_username; Password = $values.node_password; Root = $values.node_project_root }
}

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Import-Module Posh-SSH -ErrorAction Stop
$archive = Join-Path $env:TEMP "zhongkui-waf-runtime-sync.tar.gz"
Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue

try {
    & tar.exe -C $ProjectRoot -czf $archive lib/cc_cluster.lua lib/sql.lua lib/constants.lua admin/lua/cluster_node.lua admin/view/defense/cc.html
    if ($LASTEXITCODE -ne 0) { throw "Failed to create runtime sync archive" }

    foreach ($targetItem in $targets) {
        foreach ($name in @("Host", "Port", "User", "Password", "Root")) {
            if (-not $targetItem[$name]) { throw "Missing $name for $($targetItem.Name) test target" }
        }
        $secure = ConvertTo-SecureString $targetItem.Password -AsPlainText -Force
        $credential = [pscredential]::new($targetItem.User, $secure)
        $remoteArchive = "/tmp/zhongkui-waf-runtime-sync.tar.gz"
        Set-SCPItem -ComputerName $targetItem.Host -Port $targetItem.Port -Credential $credential -AcceptKey -Path $archive -Destination "/tmp/" -NewName "zhongkui-waf-runtime-sync.tar.gz" -Force -OperationTimeout 30 | Out-Null
        $session = New-SSHSession -ComputerName $targetItem.Host -Port $targetItem.Port -Credential $credential -AcceptKey -ConnectionTimeout 15
        try {
            $command = "set -e; ROOT='$($targetItem.Root)'; test -d `"`$ROOT`"; if [ `"`$(id -u)`" -eq 0 ]; then RUN=''; else RUN='sudo -n'; fi; `$RUN tar -xzf $remoteArchive -C `"`$ROOT`"; if [ -x /opt/openresty/nginx/sbin/nginx ]; then `$RUN /opt/openresty/nginx/sbin/nginx -t && `$RUN /opt/openresty/nginx/sbin/nginx -s reload; else `$RUN nginx -t && `$RUN nginx -s reload; fi; rm -f $remoteArchive; grep -n APP_VERSION `"`$ROOT/lib/constants.lua`"; grep -n requests_24h `"`$ROOT/lib/sql.lua`"; echo SYNC_OK"
            $result = Invoke-SSHCommand -SessionId $session.SessionId -Command $command -TimeOut 45
            if ($result.ExitStatus -ne 0) { throw "$($targetItem.Name) sync failed: $($result.Error) $($result.Output -join '; ')" }
            Write-Output "[$($targetItem.Name)]"
            $result.Output
        }
        finally {
            Remove-SSHSession -SessionId $session.SessionId | Out-Null
        }
    }
}
finally {
    Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
}
