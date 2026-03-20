# 1. Setup Directories and Paths
$configDir = "C:\config"
$configPath = "$configDir\config.alloy"
$exePath = "C:\temp\alloy-installer-windows-amd64.exe"

# Ensure directories exist
if (!(Test-Path "C:\temp")) { New-Item -Path "C:\temp" -ItemType Directory | Out-Null }
if (!(Test-Path $configDir)) { New-Item -Path $configDir -ItemType Directory | Out-Null }

# 2. Define and Write the Config BEFORE Installation
# config from https://raw.githubusercontent.com/grafana/alloy-scenarios/refs/heads/main/windows/config.alloy with localhost changed and security log added
$alloyConfig = @"
// ####################################
// Windows Server Metrics Configuration
// ####################################

prometheus.exporter.windows "default" {
  enabled_collectors = ["cpu","cs","logical_disk","net","os","service","system", "memory", "scheduled_task", "tcp"]
}

// Configure a prometheus.scrape component to collect windows metrics.
prometheus.scrape "example" {
  targets    = prometheus.exporter.windows.default.targets
  forward_to = [prometheus.remote_write.demo.receiver]
}

prometheus.remote_write "demo" {
  endpoint {
    url = "http://192.168.1.175:9090/api/v1/write"
  }
}

// ####################################
// Windows Server Logs Configuration
// ####################################

loki.source.windowsevent "application"  {
    eventlog_name = "Application"
    use_incoming_timestamp = true
    forward_to = [loki.process.endpoint.receiver]
}

loki.source.windowsevent "System"  {
    eventlog_name = "System"
    use_incoming_timestamp = true
    forward_to = [loki.process.endpoint.receiver]
}

loki.source.windowsevent "security" {
  eventlog_name = "Security"
  use_incoming_timestamp = true
  forward_to    = [loki.process.endpoint.receiver]
}

loki.process "endpoint" {
  forward_to = [loki.write.endpoint.receiver]
  stage.json {
      expressions = {
          message = "",
          Overwritten = "",
          source = "",
          computer = "",
          eventRecordID = "",
          channel = "",
          component_id = "",
          execution = "",
      }
  }

  // Extract nested fields from the "execution" object (e.g. processId, processName).
  stage.json {
      source = "execution"
      expressions = {
          processId = "",
          processName = "",
      }
  }

  stage.structured_metadata {
      values = {
          "eventRecordID" = "",
          "channel" = "",
          "component_id" = "",
          "execution_processId" = "processId",
          "execution_processName" = "processName",
      }
  }

  stage.eventlogmessage {
      source = "message"
      overwrite_existing = true
  }

  stage.labels {
      values = {
          "service_name" = "source",
      }
}

stage.output {
    source = "message"
}

}


loki.write "endpoint" {
    endpoint {
        url ="http://192.168.1.175:3100/loki/api/v1/push"
    }
}

livedebugging{}
"@

Write-Host "Populating configuration at $configPath..." -ForegroundColor Cyan
Set-Content -Path $configPath -Value $alloyConfig -Force

# 3. Download the Executable Installer
# Note: Using the .exe release instead of .msi
$version = "1.14.1" 
$url = "https://github.com/grafana/alloy/releases/download/v$version/alloy-installer-windows-amd64.exe"

Write-Host "Downloading Grafana Alloy Installer v$version..." -ForegroundColor Cyan
Invoke-RestMethod -Uri $url -OutFile $exePath

# 4. Silent Installation with Pre-populated Config
Write-Host "Running headless installation..." -ForegroundColor Cyan
$arguments = "/S /CONFIG=`"$configPath`" /DISABLEREPORTING=yes"
Start-Process -FilePath $exePath -ArgumentList $arguments -Wait

# 5. Firewall Configuration (Outbound Only)
Write-Host "Configuring Firewall..." -ForegroundColor Cyan
Remove-NetFirewallRule -DisplayName "Allow Alloy Outbound to Loki" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Allow Alloy Outbound to Prometheus" -ErrorAction SilentlyContinue

New-NetFirewallRule -DisplayName "Allow Alloy Outbound to Loki" `
    -Direction Outbound -Action Allow -Protocol TCP `
    -RemoteAddress 192.168.1.175 -RemotePort 3100

New-NetFirewallRule -DisplayName "Allow Alloy Outbound to Prometheus" `
    -Direction Outbound -Action Allow -Protocol TCP `
    -RemoteAddress 192.168.1.175 -RemotePort 9090

# 6. Final Status Check
Write-Host "Verifying Alloy Service..." -ForegroundColor Cyan
$service = Get-Service -Name "Alloy" -ErrorAction SilentlyContinue
if ($service.Status -eq "Running") {
    Write-Host "Success: Alloy is installed and shipping data." -ForegroundColor Green
} else {
    Write-Host "Warning: Service installed but not running. Check Event Viewer." -ForegroundColor Red
}