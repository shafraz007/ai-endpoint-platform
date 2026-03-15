$ErrorActionPreference='Stop'
$base='http://localhost:8070'
$dbURL=$env:DATABASE_URL
if (-not $dbURL) { $dbURL='postgres://aiuser:aipassword@localhost:5432/aiendpoint?sslmode=disable' }

$tmpFind='tmp_find_admin_user.go'
@'
package main
import (
  "context"
  "fmt"
  "os"
  "strings"
  "time"
  "github.com/jackc/pgx/v5/pgxpool"
)
func main(){
  dbURL:=os.Getenv("DATABASE_URL")
  if strings.TrimSpace(dbURL)=="" { dbURL="postgres://aiuser:aipassword@localhost:5432/aiendpoint?sslmode=disable" }
  ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second); defer cancel()
  pool,err:=pgxpool.New(ctx,dbURL); if err!=nil { fmt.Println("ERR"); os.Exit(1) }
  defer pool.Close()
  var u string
  err=pool.QueryRow(ctx,`SELECT username FROM users WHERE role='admin' ORDER BY id LIMIT 1`).Scan(&u)
  if err!=nil || strings.TrimSpace(u)=="" { fmt.Println("ERR"); os.Exit(1) }
  fmt.Println(u)
}
'@ | Set-Content -Path $tmpFind

$env:DATABASE_URL=$dbURL
$adminUser=(go run ./$tmpFind).Trim()
if (-not $adminUser -or $adminUser -eq 'ERR') { throw 'admin user resolve failed' }
$secret=[Environment]::GetEnvironmentVariable('ADMIN_JWT_SECRET','Process')
if (-not $secret) { $secret=[Environment]::GetEnvironmentVariable('ADMIN_JWT_SECRET','User') }
if (-not $secret) { throw 'ADMIN_JWT_SECRET missing' }
$token=(go run ./scripts/jwtgen -subject $adminUser -role admin -secret $secret -ttl 600).Trim()
if (-not $token) { throw 'token generation failed' }
$headers=@{ Authorization = "Bearer $token" }

$agentId='dc0621ed-4d62-4308-8332-ad7136030483'
$runAt=(Get-Date).ToUniversalTime().AddSeconds(-2).ToString('o')
$schedName='smoke-health-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$body=@{
  name=$schedName; kind='task'; target_scope='agent'; target_agent_id=$agentId;
  command_type='ai_task'; payload='Check device health'; run_at=$runAt;
  repeat_interval_seconds=0; enabled=$true; next_run_at=$runAt
} | ConvertTo-Json -Depth 5

$created=Invoke-RestMethod -Uri "$base/api/schedules" -Method Post -UseBasicParsing -ContentType 'application/json' -Body $body -Headers $headers
$sid=$created.id
Write-Output ('schedule_id=' + $sid)

$deadline=(Get-Date).AddSeconds(120)
$final=''
$cmdId=''
while((Get-Date) -lt $deadline){
  $cmds=Invoke-RestMethod -Uri "$base/api/commands?agent_id=$agentId&limit=50" -UseBasicParsing -Headers $headers
  $match=$cmds | Where-Object { $_.schedule_id -eq $sid } | Select-Object -First 1
  if ($match) {
    $cmdId=$match.id
    $final=$match.status
    if ($final -eq 'succeeded' -or $final -eq 'failed' -or $final -eq 'completed') { break }
  }
  Start-Sleep -Seconds 2
}

$from=(Get-Date).ToUniversalTime().AddMinutes(-30).ToString('o')
$to=(Get-Date).ToUniversalTime().AddMinutes(2).ToString('o')
$report=Invoke-RestMethod -Uri "$base/api/reports/executions?from=$([uri]::EscapeDataString($from))&to=$([uri]::EscapeDataString($to))&schedule_id=$sid&agent_id=$([uri]::EscapeDataString($agentId))&limit=20" -UseBasicParsing -Headers $headers
$latest=$report | Select-Object -First 1

Invoke-WebRequest -Uri "$base/api/schedules/$sid" -Method Delete -UseBasicParsing -Headers $headers | Out-Null

Write-Output ('command_id=' + $cmdId)
Write-Output ('command_status=' + $final)
if ($latest) {
  Write-Output ('report_status=' + $latest.status)
  Write-Output 'report_output_start'
  Write-Output ($latest.output)
  Write-Output 'report_output_end'
} else {
  Write-Output 'report_row=none'
}

Remove-Item ./$tmpFind -Force -ErrorAction SilentlyContinue
