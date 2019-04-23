# Copyright 2019 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

<#
.SYNOPSIS
  Preloads a Windows image with components for joining a Kubernetes cluster.

.NOTES
  This script needs to work in concert with the startup script for Windows
  Kubernetes nodes on GCE
  (https://github.com/kubernetes/kubernetes/blob/master/cluster/gce/windows/configure.ps1)
  and related scripts. In particular, these directories must match between this
  script and those:
    K8S_DIR
    NODE_DIR
    CNI_DIR
#>

# TODO(pjh): remaining tasks:
#  - Install crictl: https://github.com/kubernetes-sigs/cri-tools/releases.
#    Wait until available in GCS (PR forthcoming).
#  - Uninstall KB4486553
#    (https://github.com/kubernetes/kubernetes/issues/76666).
#  - Pull files from GCS instead of from Github and PowerShell Gallery.
#  - Figure out how to get the right version of the kubelet + kube-proxy onto
#    the prebuilt image.
#  - Try again to create the initial container network.

$ErrorActionPreference = 'Stop'
# Turn on tracing to debug:
# Set-PSDebug -Trace 1

$K8S_DIR = 'C:\etc\kubernetes'
$NODE_DIR = $K8S_DIR + '\node\bin'
$CNI_DIR = $K8S_DIR + '\cni'
$CNI_RELEASE_VERSION = 'v0.8.0'
$STACKDRIVER_VERSION = 'v1-9'
$STACKDRIVER_INSTALLER = "StackdriverLogging-$STACKDRIVER_VERSION.exe"
$STACKDRIVER_ROOT = 'C:\Program Files (x86)\Stackdriver'
$INFRA_CONTAINER = "mcr.microsoft.com/k8s/core/pause:1.0.0"
$GCE_METADATA_SERVER = "169.254.169.254"
# The "management" interface is used by the kubelet and by Windows pods to talk
# to the rest of the Kubernetes cluster *without NAT*. This interface does not
# exist until an initial HNS network has been created on the Windows node - see
# Add-InitialHnsNetwork().
$MGMT_ADAPTER_NAME = "vEthernet (Ethernet*"
# Directory where we'll save license files for scripts and binaries that we
# download onto the node.
$LICENSE_DIR = 'C:\Program Files\Google\Compute Engine\THIRD_PARTY_NOTICES'
# File indicating that this boot is not the first boot. Created during the
# first boot, of course.
$NOT_FIRST_BOOT_FILE = 'C:\NotFirstBoot.txt'

# Writes $Message to the console. Terminates the script if $Fatal is set.
function Log-Output {
  param (
    [parameter(Mandatory=$true)] [string]$Message,
    [switch]$Fatal
  )

  Write-Host "${Message}"
  if (${Fatal}) {
    Exit 1
  }
}

function Test-IsFirstBoot {
  if (Test-Path $NOT_FIRST_BOOT_FILE) {
    return $false
  }
  return $true
}

function Set-NotFirstBootMarker {
  New-Item -Force -ItemType file $NOT_FIRST_BOOT_FILE | Out-Null
}

function Remove-NotFirstBootMarker {
  Remove-Item $NOT_FIRST_BOOT_FILE
}

# Returns the GCE instance metadata value for $Key. If the key is not present
# in the instance metadata returns $Default if set, otherwise returns $null.
function Get-InstanceMetadata {
  param (
    [parameter(Mandatory=$true)] [string]$Key,
    [parameter(Mandatory=$false)] [string]$Default
  )

  $url = "http://metadata.google.internal/computeMetadata/v1/instance/$Key"
  try {
    $client = New-Object Net.WebClient
    $client.Headers.Add('Metadata-Flavor', 'Google')
    return ($client.DownloadString($url)).Trim()
  }
  catch [System.Net.WebException] {
    if ($Default) {
      return $Default
    }
    else {
      Log-Output "Failed to retrieve value for $Key."
      return $null
    }
  }
}

# Verifies that the SHA1 hash of $Path is $Hash, throwing an exception if it is
# not.
function Validate-SHA1 {
  param(
    [parameter(Mandatory=$true)] [string]$Hash,
    [parameter(Mandatory=$true)] [string]$Path
  )

  $actual = Get-FileHash -Path $Path -Algorithm SHA1
  # Note: Powershell string comparisons are case-insensitive by default, and
  # this is important here because Linux shell scripts produce lowercase hashes
  # but Powershell Get-FileHash produces uppercase hashes. This must be case-
  # insensitive to work.
  if ($actual.Hash -ne $Hash) {
    Log-Output "$Path corrupted, sha1 $actual doesn't match expected $Hash"
    throw ("$Path corrupted, sha1 $actual doesn't match expected $Hash")
  }
}

# Attempts to download the file at $Url, saving it to $OutFile. Will retry a
# small number of times before failing. A SHA1 hash value may be optionally
# passed for validation.
function Download-WithRetries {
  param (
    [parameter(Mandatory=$true)] [string]$Url,
    [parameter(Mandatory=$true)] [string]$OutFile,
    [parameter(Mandatory=$false)] [string]$Hash
  )

  # TODO(pjh): when we get a Windows version that has Powershell 6 installed we
  # can just set `-MaximumRetryCount 5 -RetryIntervalSec 60` instead.
  $attempts = 0
  while ($attempts -lt 5) {
    # Attempt to download the file
    try {
      $attempts += 1
      Invoke-WebRequest $Url -OutFile $OutFile -TimeoutSec 60
      if ($Hash) {
        try {
          Validate-SHA1 -Hash $Hash -Path $OutFile
        } catch {
          $message = $_.Exception.ToString()
          Log-Output ("Hash validation of $url failed. Will retry. " +
                      "Error: $message")
          continue
        }
        Log-Output "Verified $url has SHA1 = $Hash"
      }
      return
    }
    catch {
      $message = $_.Exception.ToString()
      Log-Output `
          "Failed to download file from $Url. Will retry. Error: $message"
      Start-Sleep 5
    }
  }
  Log-Output -Fatal "Failed to download file from $Url after several retries."
}

# Returns the repository that the Windows base container images should be
# pulled from.
function Get-BaseContainerRepo {
  return 'mcr.microsoft.com/windows'
}

# Returns the label that should be used for pulling the Windows base container
# images.
function Get-BaseContainerVersionLabel {
  param (
    [parameter(Mandatory=$true)] [string]$WindowsVersion
  )

  # For more information about Windows container version labels see:
  # https://hub.docker.com/r/microsoft/windowsservercore/
  # https://blogs.technet.microsoft.com/virtualization/2017/10/18/container-images-are-now-out-for-windows-server-version-1709/
  # https://azure.microsoft.com/en-us/blog/microsoft-syndicates-container-catalog/
  # https://blogs.technet.microsoft.com/virtualization/2018/11/13/windows-server-2019-now-available/
  if ($WindowsVersion -eq '2019') {
    return 'ltsc2019'
  }
  # Semi-annual versions ('1803', '1809', ...):
  return $WindowsVersion
}

# Returns true if the specified $WindowsVersion supports the Nanoserver base
# container image.
function Supports-NanoserverContainerImage {
  param (
    [parameter(Mandatory=$true)] [string]$WindowsVersion
  )

  # Windows Server 2019 does not support the Nanoserver container image, only
  # Servercore:
  # https://blogs.technet.microsoft.com/virtualization/2018/11/13/windows-server-2019-now-available/.
  if ($WindowsVersion -eq '2019') {
    return $false
  }
  return $true
}

# Returns the name of the Windows Server Core base container image for the
# specified Windows version.
function Get-ServerCoreImageName {
  param (
    [parameter(Mandatory=$true)] [string]$WindowsVersion
  )

  $repo = Get-BaseContainerRepo
  $image = 'servercore'
  $label = Get-BaseContainerVersionLabel $WindowsVersion
  return "${repo}/${image}:${label}"
}

# Returns the name of the Windows Nanoserver base container image for the
# specified Windows version.
function Get-NanoserverImageName {
  param (
    [parameter(Mandatory=$true)] [string]$WindowsVersion
  )

  $repo = Get-BaseContainerRepo $WindowsVersion
  $image = 'nanoserver'
  $label = Get-BaseContainerVersionLabel $WindowsVersion
  return "${repo}/${image}:${label}"
}

# Returns an array containing the Windows base container images that may be
# used with the specified Windows version.
function Get-BaseContainerImageNames {
  param (
    [parameter(Mandatory=$true)] [string]$WindowsVersion
  )

  $images = @(Get-ServerCoreImageName $WindowsVersion)
  if (Supports-NanoserverContainerImage $WindowsVersion) {
    $images += (Get-NanoserverImageName $WindowsVersion)
  }
  return $images
}

# Pulls the Windows container base images. Most Windows containers are built on
# top of one of these base images, so pre-pulling them ensures that pulling and
# running subsequent containers is fast.
function Pull-BaseContainerImages {
  $windows_version = Get-InstanceMetadata 'attributes/version'
  $container_images = Get-BaseContainerImageNames $windows_version
  ForEach ($image in $container_images) {
    Log-Output "Pulling container image: $image"
    & docker pull $image
    if (!$?) {
      throw "Error running 'docker pull $image'"
    }
  }

}

# Writes IPv4 route information to the console.
function Dump-Routes {
  $active = $(Get-NetRoute -PolicyStore ActiveStore | Out-String)
  $persistent = $(Get-NetRoute -PolicyStore PersistentStore | Out-String)
  Log-Output "Active routes:`n$active"
  Log-Output "Persistent routes:`n$persistent"
}

# Fails and exits if the route to the GCE metadata server is not present,
# otherwise does nothing and emits nothing.
function Verify-GceMetadataServerRouteIsPresent {
  Try {
    Get-NetRoute `
        -ErrorAction "Stop" `
        -AddressFamily IPv4 `
        -DestinationPrefix ${GCE_METADATA_SERVER}/32 | Out-Null
  } catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
    Log-Output -Fatal `
        ("GCE metadata server route is not present as expected.`n" +
         "$(Get-NetRoute -AddressFamily IPv4 | Out-String)")
  }
}

# Checks if the route to the GCE metadata server is present. Returns when the
# route is NOT present or after a timeout has expired.
function WaitFor-GceMetadataServerRouteToBeRemoved {
  $elapsed = 0
  $timeout = 60
  Log-Output ("Waiting up to ${timeout} seconds for GCE metadata server " +
              "route to be removed")
  while (${elapsed} -lt ${timeout}) {
    Try {
      Get-NetRoute `
          -ErrorAction "Stop" `
          -AddressFamily IPv4 `
          -DestinationPrefix ${GCE_METADATA_SERVER}/32 | Out-Null
    } catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
      break
    }
    $sleeptime = 2
    Start-Sleep ${sleeptime}
    ${elapsed} += ${sleeptime}
  }
}

# Adds a route to the GCE metadata server to every network interface.
function Add-GceMetadataServerRoute {
  # Before setting up HNS the Windows VM has a "vEthernet (nat)" interface and
  # a "Ethernet" interface, and the route to the metadata server exists on the
  # Ethernet interface. After adding the HNS network a "vEthernet (Ethernet)"
  # interface is added, and it seems to subsume the routes of the "Ethernet"
  # interface (trying to add routes on the Ethernet interface at this point just
  # results in "New-NetRoute : Element not found" errors). I don't know what's
  # up with that, but since it's hard to know what's the right thing to do here
  # we just try to add the route on all of the network adapters.
  Get-NetAdapter | ForEach-Object {
    $adapter_index = $_.InterfaceIndex
    New-NetRoute `
        -ErrorAction Ignore `
        -DestinationPrefix "${GCE_METADATA_SERVER}/32" `
        -InterfaceIndex ${adapter_index} `
        -PolicyStore ActiveStore | Out-Null
    New-NetRoute `
        -ErrorAction Ignore `
        -DestinationPrefix "${GCE_METADATA_SERVER}/32" `
        -InterfaceIndex ${adapter_index} `
        -PolicyStore PersistentStore | Out-Null
  }
  Log-Output 'Metadata server route re-added.'
}

# Writes debugging information, such as Windows version and patch info, to the
# console.
function Write-DebugInfoToConsole {
  try {
    $version = $([System.Environment]::OSVersion.Version | Out-String)
    $hotfixes = $(Get-Hotfix | Out-String)
    $image = $(Get-InstanceMetadata 'image' | Out-String)
    $docker_info = $(docker info | Out-String)
    Log-Output "Windows version:`n$version"
    Log-Output "Installed hotfixes:`n$hotfixes"
    Log-Output "GCE Windows image:`n$image"
    Log-Output "docker info:`n$docker_info"
  } catch { }
}

# Creates various directories needed for holding objects, data and logs.
# Note: C:\tmp is required for running certain kubernetes tests.
#       C:\var\log is used by kubelet to store container logs and also
#       hard-coded in the fluentd/stackdriver config for log collection.
function Create-Directories {
  Log-Output "Creating $K8S_DIR and other required directories."
  foreach ($dir in
      ($K8S_DIR, $NODE_DIR, $CNI_DIR, $LICENSE_DIR, 'C:\tmp', 'C:\var\log')) {
    mkdir -Force $dir
  }
}

# Disables Windows updates, which can cause the node to reboot at arbitrary
# times.
function Disable-WindowsUpdates {
  Log-Output "Disabling Windows Update service"
  sc.exe config wuauserv start=disabled
  sc.exe stop wuauserv
}

# Installs external PowerShell modules that we'll need when configuring
# Kubernetes.
function Install-PowershellModules {
  # https://github.com/cloudbase/powershell-yaml
  Log-Output "Installing powershell-yaml module from external repo"
  Install-Module -Name powershell-yaml -Force
  Download-WithRetries `
      -Url 'https://github.com/cloudbase/powershell-yaml/raw/master/LICENSE' `
      -OutFile "$LICENSE_DIR\LICENSE_powershell-yaml.txt"
}

# Disables Windows Defender realtime scanning and uninstalls the Defender
# service.
#
# IMPORTANT: after calling this function during image preparation we must
# restart once before invoking sysprep, otherwise sysprep will fail with the
# message "There are one or more Windows updates that require a reboot. To run
# Sysprep, reboot the computer and restart the application."
#
# TODO(pjh): remove this once the Windows fix for
# https://github.com/kubernetes/kubernetes/issues/75148 has been released, then
# monitor Defender's CPU consumption to make sure it's not unreasonable.
function Disable-WindowsDefender {
  if ((Get-WindowsFeature -Name 'Windows-Defender').Installed) {
    Log-Output "Disabling Windows Defender service"
    Set-MpPreference -DisableRealtimeMonitoring $true
    Uninstall-WindowsFeature -Name 'Windows-Defender'
  } else {
    Log-Output -Fatal "Windows Defender unexpectedly not installed."
  }
}

# Uninstalls Windows updates that are known to cause problems on Kubernetes
# nodes. The system must be restarted at some point after calling this function
# in order to complete the uninstallation.
function Uninstall-BuggyHotfixes {
  Log-Output "Before wusa.exe"
  & wmic qfe list
  Get-Hotfix

  # TODO(pjh): clean up this function.
  # None of these seem to do anything :(
  # https://github.com/kubernetes/kubernetes/issues/76666#issuecomment-493634697
  & wusa /uninstall /kb:4486553 /quiet /norestart
  & cmd.exe /c wusa.exe /uninstall /kb:4486553 /quiet /norestart
  & wusa /uninstall /kb:4486553 /norestart
  # This one hangs forever - waiting for confirmation I guess.
  #& cmd.exe /c wusa.exe /uninstall /kb:4486553 /norestart

  Log-Output "After wusa.exe"
  & wmic qfe list
  Get-Hotfix
}

# Pulls the Kubernetes infra/pause container image onto the node.
# TODO(pjh): downloading this container image can take a couple minutes; can
# this function be executed asynchronously while performing other steps?
function Pull-InfraContainer {
  & docker pull $INFRA_CONTAINER
  if (!$?) {
    throw "Error running 'docker pull $INFRA_CONTAINER'"
  }
}

# Downloads external scripts and binaries that will be used for configuring or
# running Kubernetes.
function Download-ScriptsAndBinaries {
  # Update TLS setting to enable Github downloads and disable progress bar to
  # increase download speed.
  [Net.ServicePointManager]::SecurityProtocol = `
      [Net.SecurityProtocolType]::Tls12
  $ProgressPreference = 'SilentlyContinue'

  Download-WithRetries `
      -Url 'https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1' `
      -OutFile "$K8S_DIR\hns.psm1"
  Download-WithRetries `
      -Url 'https://github.com/Microsoft/SDN/raw/master/License.txt' `
      -OutFile "$LICENSE_DIR\LICENSE_Microsoft-SDN.txt"

  Download-WithRetries `
      -Url 'https://github.com/pjh/gce-tools/raw/master/GceTools/GetGcePdName/GetGcePdName.dll' `
      -OutFile "$K8S_DIR\GetGcePdName.dll"
  Download-WithRetries `
      -Url 'https://github.com/pjh/gce-tools/raw/master/LICENSE' `
      -OutFile "$LICENSE_DIR\LICENSE_pjh-gce-tools.txt"

  Download-WithRetries `
      -Url "https://dl.google.com/cloudagents/windows/$STACKDRIVER_INSTALLER" `
      -OutFile "$K8S_DIR\$STACKDRIVER_INSTALLER"
}

# Downloads and installs the CNI binaries that we use on our Windows Kubernetes
# nodes.
function DownloadAndInstall-CniBinaries {
  $tmp_dir = 'C:\cni_tmp'
  New-Item $tmp_dir -ItemType 'directory' -Force | Out-Null

  $release_url = ('https://github.com/containernetworking/plugins/releases/' +
      'download/' + $CNI_RELEASE_VERSION + '/')
  $sha_url = ($release_url +
      "cni-plugins-windows-amd64-$CNI_RELEASE_VERSION.tgz.sha1")
  $tgz_url = ($release_url +
      "cni-plugins-windows-amd64-$CNI_RELEASE_VERSION.tgz")
  Download-WithRetries -Url $sha_url -OutFile $tmp_dir\cni-plugins.sha1
  $sha1_val = ($(Get-Content $tmp_dir\cni-plugins.sha1) -split ' ',2)[0]
  Download-WithRetries `
      -Url $tgz_url `
      -OutFile $tmp_dir\cni-plugins.tgz `
      -Hash $sha1_val
  Download-WithRetries `
      -Url 'https://github.com/containernetworking/plugins/raw/master/LICENSE' `
      -OutFile "$LICENSE_DIR\LICENSE_containernetworking-plugins.txt"

  Push-Location $tmp_dir
  # tar can only extract in the current directory.
  tar -xvf $tmp_dir\cni-plugins.tgz
  Move-Item -Force host-local.exe $CNI_DIR\
  Move-Item -Force win-bridge.exe $CNI_DIR\
  Pop-Location
  Remove-Item -Force -Recurse $tmp_dir
}

# Writes the Microsoft container image license file to a well-known directory
# on the disk.
function Write-ContainerImageLicense {
  # License text copied from
  # https://hub.docker.com/_/microsoft-windows-servercore on 2019-05-14. A more
  # official location might be
  # https://docs.microsoft.com/en-us/virtualization/windowscontainers/images-eula
  # but I don't know a good way to fetch the raw license text (as opposed to
  # the full html).
  Set-Content $LICENSE_DIR\LICENSE_Microsoft-container-image.txt `
'MICROSOFT SOFTWARE SUPPLEMENTAL LICENSE TERMS CONTAINER OS IMAGE
Microsoft Corporation (or based on where you live, one of its affiliates) (referenced as "us," "we," or "Microsoft") licenses this Container OS Image supplement to you ("Supplement"). You are licensed to use this Supplement in conjunction with the underlying host operating system software ("Host Software") solely to assist running the containers feature in the Host Software. The Host Software license terms apply to your use of the Supplement. You may not use it if you do not have a license for the Host Software. You may use this Supplement with each validly licensed copy of the Host Software.

ADDITIONAL LICENSING REQUIREMENTS AND/OR USE RIGHTS
Your use of the Supplement as specified in the preceding paragraph may result in the creation or modification of a container image ("Container Image") that includes certain Supplement components. For clarity, a Container Image is separate and distinct from a virtual machine or virtual appliance image. Pursuant to these license terms, we grant you a restricted right to redistribute such Supplement components under the following conditions:
(i) you may use the Supplement components only as used in, and as a part of, your Container Image,
(ii) you may use such Supplement components in your Container Image as long as you have significant primary functionality in your Container Image that is materially separate and distinct from the Supplement; and
(iii) you agree to include these license terms (or similar terms required by us or a hoster) with your Container Image to properly license the possible use of the Supplement components by your end-users. We reserve all other rights not expressly granted herein.

By using this Supplement, you accept these terms. If you do not accept them, do not use this Supplement.

As part of the Supplemental License Terms for this Container OS Image for Windows containers, you are also subject to the underlying Windows Server host software license terms, which are located at https://www.microsoft.com/en-us/useterms.'
}

# Adds an initial HNS network on the Windows node which forces the creation of
# a virtual switch and the "management" interface that will be used to
# communicate with the rest of the Kubernetes cluster without NAT.
#
# Note that adding the initial HNS network may cause connectivity to the GCE
# metadata server to be lost due to a Windows bug.
# Configure-HostNetworkingService() restores connectivity, look there for
# details.
#
# Download-ScriptsAndBinaries must have been called first.
function Add-InitialHnsNetwork {
  $INITIAL_HNS_NETWORK = 'External'

  Import-Module -Force $K8S_DIR\hns.psm1

  Dump-Routes

  # This comes from
  # https://github.com/Microsoft/SDN/blob/master/Kubernetes/flannel/l2bridge/start.ps1#L74
  # (or
  # https://github.com/Microsoft/SDN/blob/master/Kubernetes/windows/start-kubelet.ps1#L206).
  #
  # daschott noted on Slack: "L2bridge networks require an external vSwitch.
  # The first network ("External") with hardcoded values in the script is just
  # a placeholder to create an external vSwitch. This is purely for convenience
  # to be able to remove/modify the actual HNS network ("cbr0") or rejoin the
  # nodes without a network blip. Creating a vSwitch takes time, causes network
  # blips, and it makes it more likely to hit the issue where flanneld is
  # stuck, so we want to do this as rarely as possible."
  $hns_network = Get-HnsNetwork | Where-Object Name -eq $INITIAL_HNS_NETWORK
  if ($hns_network) {
    Log-Output `
        -Fatal `
        "Warning: initial '$INITIAL_HNS_NETWORK' HNS network already exists"
  }
  Log-Output ("Creating initial HNS network to force creation of " +
              "${MGMT_ADAPTER_NAME} interface")
  # Note: RDP connections will hiccup when running this command.
  New-HNSNetwork `
      -Type "L2Bridge" `
      -AddressPrefix "192.168.255.0/30" `
      -Gateway "192.168.255.1" `
      -Name $INITIAL_HNS_NETWORK `
      -Verbose

  # There is an HNS bug where the route to the GCE metadata server will be
  # removed when the HNS network is created:
  # https://github.com/Microsoft/hcsshim/issues/299#issuecomment-425491610.
  # The behavior here is very unpredictable: the route may only be removed
  # after some delay, or it may appear to be removed then you'll add it back
  # but then it will be removed once again. So, we first wait a long
  # unfortunate amount of time to ensure that things have quiesced, then we
  # wait until we're sure the route is really gone before re-adding it again.
  Log-Output "Waiting 45 seconds for host network state to quiesce"
  Start-Sleep 45
  WaitFor-GceMetadataServerRouteToBeRemoved
  Log-Output "Re-adding the GCE metadata server route"
  Add-GceMetadataServerRoute
  Verify-GceMetadataServerRouteIsPresent
  Dump-Routes
}

# Adds a registry key for docker in EventLog so that log messages are mapped
# correctly.
# https://github.com/MicrosoftDocs/Virtualization-Documentation/pull/503
function Create-DockerRegistryKey {
  $tmp_dir = 'C:\tmp_docker_reg'
  New-Item -Force -ItemType 'directory' ${tmp_dir} | Out-Null
  $reg_file = 'docker.reg'
  Set-Content ${tmp_dir}\${reg_file} `
'Windows Registry Editor Version 5.00
 [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\docker]
"CustomSource"=dword:00000001
"EventMessageFile"="C:\\Program Files\\docker\\dockerd.exe"
"TypesSupported"=dword:00000007'

  Log-Output "Importing registry key for Docker"
  reg import ${tmp_dir}\${reg_file}
  Remove-Item -Force -Recurse ${tmp_dir}
}

# Configures the Docker daemon and restarts the service.
function Configure-Dockerd {
  Set-Content "C:\ProgramData\docker\config\daemon.json" @'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "1m",
    "max-file": "5"
  }
}
'@

  Restart-Service Docker
}

# Installs the Stackdriver logging agent according to
# https://cloud.google.com/logging/docs/agent/installation.
function Install-LoggingAgent {
  # Start the installer silently.
  Log-Output 'Invoking Stackdriver installer'
  Start-Process $K8S_DIR\$STACKDRIVER_INSTALLER -ArgumentList "/S" -Wait

  # The installer automatically starts the Stackdriver logging service; wait
  # for it to start (it will be in the "StartPending" state initially), then
  # stop it and prevent it from automatically starting on subsequent boots.
  $elapsed = 0
  $timeout = 180
  Log-Output "Waiting up to $timeout seconds for StackdriverLogging to start"
  while (((Get-Service StackdriverLogging).Status -ne 'Running') -and
         ($elapsed -lt $timeout)) {
    Start-Sleep 10
    $elapsed += 10
  }
  if ($elapsed -ge $timeout) {
    # Note: we wait for the Stackdriver service to finish starting before
    # touching it out of an abundance of caution. It appears that we can still
    # set the StartType to Manual even while the service is in the StartPending
    # state, so if this timeout is hit regularly we can probably just remove
    # this check.
    Get-Service -ErrorAction Continue StackdriverLogging |
        Select-Object * | Out-String
    Log-Output -Fatal "StackdriverLogging service did not start in time."
  }

  # StackdriverLogging sometimes is unstoppable, so we work around it by
  # killing the processes.
  Stop-Service -NoWait -ErrorAction Ignore StackdriverLogging
  # TODO: check periodically to lower the wait time
  Start-Sleep 10
  if ((Get-Service StackdriverLogging).Status -ne 'Stopped') {
    # Force kill the processes.
    Stop-Process -Force -PassThru -Id (Get-WmiObject win32_process |
      Where CommandLine -Like '*Stackdriver/logging*').ProcessId
  }

  # Prevent StackdriverLogging from starting automatically; we'll manually
  # start it when joining the node to the K8s cluster, and sometimes the
  # service fails to start so it's better for that failure to happen at a point
  # where we'll notice it instead of during Windows boot.
  Set-Service StackdriverLogging -StartupType Manual
  Get-Service -ErrorAction Continue StackdriverLogging |
      Select-Object * | Out-String

  # Create a configuration file for kubernetes containers.
  # The config.d directory should have already been created automatically, but
  # try creating again just in case.
  New-Item "$STACKDRIVER_ROOT\LoggingAgent\config.d" `
      -ItemType 'directory' `
      -Force | Out-Null
  $FLUENTD_CONFIG | Out-File `
      -FilePath "$STACKDRIVER_ROOT\LoggingAgent\config.d\k8s_containers.conf" `
      -Encoding ASCII

  Remove-Item -Force $K8S_DIR\$STACKDRIVER_INSTALLER
}

$FLUENTD_CONFIG = @'
# This configuration file for Fluentd is used to watch changes to kubernetes
# container logs in the directory /var/lib/docker/containers/ and submit the
# log records to Google Cloud Logging using the cloud-logging plugin.
#
# Example
# =======
# A line in the Docker log file might look like this JSON:
#
# {"log":"2014/09/25 21:15:03 Got request with path wombat\\n",
#  "stream":"stderr",
#   "time":"2014-09-25T21:15:03.499185026Z"}
#
# The original tag is derived from the log file's location.
# For example a Docker container's logs might be in the directory:
#  /var/lib/docker/containers/997599971ee6366d4a5920d25b79286ad45ff37a74494f262e3bc98d909d0a7b
# and in the file:
#  997599971ee6366d4a5920d25b79286ad45ff37a74494f262e3bc98d909d0a7b-json.log
# where 997599971ee6... is the Docker ID of the running container.
# The Kubernetes kubelet makes a symbolic link to this file on the host
# machine in the /var/log/containers directory which includes the pod name,
# the namespace name and the Kubernetes container name:
#    synthetic-logger-0.25lps-pod_default_synth-lgr-997599971ee6366d4a5920d25b79286ad45ff37a74494f262e3bc98d909d0a7b.log
#    ->
#    /var/lib/docker/containers/997599971ee6366d4a5920d25b79286ad45ff37a74494f262e3bc98d909d0a7b/997599971ee6366d4a5920d25b79286ad45ff37a74494f262e3bc98d909d0a7b-json.log
# The /var/log directory on the host is mapped to the /var/log directory in the container
# running this instance of Fluentd and we end up collecting the file:
#   /var/log/containers/synthetic-logger-0.25lps-pod_default_synth-lgr-997599971ee6366d4a5920d25b79286ad45ff37a74494f262e3bc98d909d0a7b.log
# This results in the tag:
#  var.log.containers.synthetic-logger-0.25lps-pod_default_synth-lgr-997599971ee6366d4a5920d25b79286ad45ff37a74494f262e3bc98d909d0a7b.log
# where 'synthetic-logger-0.25lps-pod' is the pod name, 'default' is the
# namespace name, 'synth-lgr' is the container name and '997599971ee6..' is
# the container ID.
# The record reformer is used to extract pod_name, namespace_name and
# container_name from the tag and set them in a local_resource_id in the
# format of:
# 'k8s_container.<NAMESPACE_NAME>.<POD_NAME>.<CONTAINER_NAME>'.
# The reformer also changes the tags to 'stderr' or 'stdout' based on the
# value of 'stream'.
# local_resource_id is later used by google_cloud plugin to determine the
# monitored resource to ingest logs against.

# Json Log Example:
# {"log":"[info:2016-02-16T16:04:05.930-08:00] Some log text here\n","stream":"stdout","time":"2016-02-17T00:04:05.931087621Z"}
# TODO: Support CRI log format, which requires the multi_format plugin.
<source>
  @type tail
  path /var/log/containers/*.log
  pos_file /var/log/gcp-containers.log.pos
  # Tags at this point are in the format of:
  # reform.var.log.containers.<POD_NAME>_<NAMESPACE_NAME>_<CONTAINER_NAME>-<CONTAINER_ID>.log
  tag reform.*
  format json
  time_key time
  time_format %Y-%m-%dT%H:%M:%S.%NZ
  read_from_head true
</source>

# Example:
# I0204 07:32:30.020537    3368 server.go:1048] POST /stats/container/: (13.972191ms) 200 [[Go-http-client/1.1] 10.244.1.3:40537]
<source>
  @type tail
  format multiline
  multiline_flush_interval 5s
  format_firstline /^\w\d{4}/
  format1 /^(?<severity>\w)(?<time>\d{4} [^\s]*)\s+(?<pid>\d+)\s+(?<source>[^ \]]+)\] (?<message>.*)/
  time_format %m%d %H:%M:%S.%N
  path /etc/kubernetes/logs/kubelet.log
  pos_file /etc/kubernetes/logs/gcp-kubelet.log.pos
  tag kubelet
</source>

# Example:
# I1118 21:26:53.975789       6 proxier.go:1096] Port "nodePort for kube-system/default-http-backend:http" (:31429/tcp) was open before and is still needed
<source>
  @type tail
  format multiline
  multiline_flush_interval 5s
  format_firstline /^\w\d{4}/
  format1 /^(?<severity>\w)(?<time>\d{4} [^\s]*)\s+(?<pid>\d+)\s+(?<source>[^ \]]+)\] (?<message>.*)/
  time_format %m%d %H:%M:%S.%N
  path /etc/kubernetes/logs/kube-proxy.log
  pos_file /etc/kubernetes/logs/gcp-kube-proxy.log.pos
  tag kube-proxy
</source>

<match reform.**>
  @type record_reformer
  enable_ruby true
  <record>
    # Extract local_resource_id from tag for 'k8s_container' monitored
    # resource. The format is:
    # 'k8s_container.<namespace_name>.<pod_name>.<container_name>'.
    "logging.googleapis.com/local_resource_id" ${"k8s_container.#{tag_suffix[4].rpartition('.')[0].split('_')[1]}.#{tag_suffix[4].rpartition('.')[0].split('_')[0]}.#{tag_suffix[4].rpartition('.')[0].split('_')[2].rpartition('-')[0]}"}
    # Rename the field 'log' to a more generic field 'message'. This way the
    # fluent-plugin-google-cloud knows to flatten the field as textPayload
    # instead of jsonPayload after extracting 'time', 'severity' and
    # 'stream' from the record.
    message ${record['log']}
    # If 'severity' is not set, assume stderr is ERROR and stdout is INFO.
    severity ${record['severity'] || if record['stream'] == 'stderr' then 'ERROR' else 'INFO' end}
  </record>
  tag ${if record['stream'] == 'stderr' then 'raw.stderr' else 'raw.stdout' end}
  remove_keys stream,log
</match>

# TODO: detect exceptions and forward them as one log entry using the
# detect_exceptions plugin

# This section is exclusive for k8s_container logs. These logs come with
# 'raw.stderr' or 'raw.stdout' tags.
<match {raw.stderr,raw.stdout}>
  @type google_cloud
  # Try to detect JSON formatted log entries.
  detect_json true
  # Allow log entries from multiple containers to be sent in the same request.
  split_logs_by_tag false
  # Set the buffer type to file to improve the reliability and reduce the memory consumption
  buffer_type file
  buffer_path /var/log/fluentd-buffers/kubernetes.containers.buffer
  # Set queue_full action to block because we want to pause gracefully
  # in case of the off-the-limits load instead of throwing an exception
  buffer_queue_full_action block
  # Set the chunk limit conservatively to avoid exceeding the recommended
  # chunk size of 5MB per write request.
  buffer_chunk_limit 512k
  # Cap the combined memory usage of this buffer and the one below to
  # 512KiB/chunk * (6 + 2) chunks = 4 MiB
  buffer_queue_limit 6
  # Never wait more than 5 seconds before flushing logs in the non-error case.
  flush_interval 5s
  # Never wait longer than 30 seconds between retries.
  max_retry_wait 30
  # Disable the limit on the number of retries (retry forever).
  disable_retry_limit
  # Use multiple threads for processing.
  num_threads 2
  use_grpc true
  # Skip timestamp adjustment as this is in a controlled environment with
  # known timestamp format. This helps with CPU usage.
  adjust_invalid_timestamps false
</match>

# Attach local_resource_id for 'k8s_node' monitored resource.
<filter **>
  @type record_transformer
  enable_ruby true
  <record>
    "logging.googleapis.com/local_resource_id" ${"k8s_node.NODE_NAME"}
  </record>
</filter>
'@.replace('NODE_NAME', (hostname))

& googet -noconfirm update
try {
  if (Test-IsFirstBoot) {
    Set-NotFirstBootMarker
    Disable-WindowsDefender
    # TODO(pjh): fix the buggy Uninstall-BuggyHotfixes function and call it
    # here.
    # Uninstall-BuggyHotfixes
    Restart-Computer
  }
  Log-Output 'After reboot:'
  & wmic qfe list
  Get-Hotfix

  Write-DebugInfoToConsole
  Create-Directories
  Disable-WindowsUpdates
  Pull-BaseContainerImages
  Install-PowershellModules
  Write-ContainerImageLicense
  Download-ScriptsAndBinaries
  DownloadAndInstall-CniBinaries
  Install-LoggingAgent
  Create-DockerRegistryKey
  Configure-Dockerd
  Pull-InfraContainer

  # TODO(pjh): invoking this causes the metadata server to be unreachable on
  # next boot. To debug this, comment out the sysprep invocation at the end of
  # this script, run it, then connect and run sysprep manually with the
  # no-shutdown flag set. Then, you can see what the routes look like after
  # sysprep, and you can set a new password before shutting down so that you
  # can troubleshoot during the next boot.
  # Add-InitialHnsNetwork

  Verify-GceMetadataServerRouteIsPresent
  Dump-Routes

  Remove-NotFirstBootMarker
  Log-Output 'Done, launching sysprep.'
  & 'C:\Program Files\Google\Compute Engine\sysprep\gcesysprep.bat'
}
catch {
  Write-Host 'Exception caught in script:'
  Write-Host $_.InvocationInfo.PositionMessage
  Write-Host "Windows build failed: $($_.Exception.Message)"
  exit 1
}
