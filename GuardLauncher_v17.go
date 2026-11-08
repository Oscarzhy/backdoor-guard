package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

const appVersion = "v17.16"

type Endpoint struct {
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	IPs          []string `json:"ips"`
	ResolveError string   `json:"resolveError,omitempty"`
}

type FirewallNotification struct {
	Type        string `json:"type"`
	Time        string `json:"time"`
	RecordID    int64  `json:"recordId"`
	PID         int64  `json:"pid"`
	Application string `json:"application"`
	Destination string `json:"destination"`
	DestPort    string `json:"destPort"`
	Protocol    string `json:"protocol"`
	FilterRTID  string `json:"filterRtId"`
}

type Config struct {
	Group              string     `json:"group"`
	StateDir           string     `json:"stateDir"`
	StateRoot          string     `json:"stateRoot"`
	LauncherPath       string     `json:"launcherPath"`
	JavaPaths          []string   `json:"javaPaths"`
	Endpoints          []Endpoint `json:"endpoints"`
	ProtectedPaths     []string   `json:"protectedPaths"`
	CallerAppData      string     `json:"callerAppData"`
	CallerLocalAppData string     `json:"callerLocalAppData"`
	CallerUserProfile  string     `json:"callerUserProfile"`
	CallerPublic       string     `json:"callerPublic"`
	ParentPID          int        `json:"parentPid"`
	ParentPath         string     `json:"parentPath"`
	SessionStartUtc    string     `json:"sessionStartUtc"`
	UserSID            string     `json:"userSid"`
	LogPath            string     `json:"logPath"`
	AuditLogPath       string     `json:"auditLogPath"`
	NotificationPath   string     `json:"notificationPath"`
	Schema             int        `json:"schema"`
	Version            string     `json:"version"`
	WatchdogReadyToken string     `json:"watchdogReadyToken"`
	Strict             bool       `json:"strict"`
}

type watchdogHeartbeat struct {
	Schema            int    `json:"schema"`
	Group             string `json:"group"`
	PID               int    `json:"pid"`
	ProcessCreatedUtc string `json:"processCreatedUtc"`
	HeartbeatUtc      string `json:"heartbeatUtc"`
	Sequence          int64  `json:"sequence"`
	Status            string `json:"status"`
	Message           string `json:"message"`
}

type processIdentity struct {
	PID          int    `json:"pid"`
	Executable   string `json:"executablePath"`
	CreationDate string `json:"creationDate"`
}

type watchdogParentReadyAck struct {
	Schema    int    `json:"schema"`
	Group     string `json:"group"`
	ParentPID int    `json:"parentPid"`
	Token     string `json:"token"`
	ReadyUtc  string `json:"readyUtc"`
}

type parentLivenessLease struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func parentLivenessMutexName(group string) string {
	return `Local\HachimiGuardParentLease-` + strings.TrimSpace(group)
}

// startParentLivenessLease creates a group-scoped Windows named mutex before UAC
// starts. The main GuardLauncher process owns it for its entire lifetime. The
// Watchdog can therefore distinguish a temporarily missing WMI process row from
// an actually terminated parent without relying on a single CIM snapshot.
func startParentLivenessLease(group string) (*parentLivenessLease, error) {
	group = strings.TrimSpace(group)
	if group == "" {
		return nil, errors.New("cannot create parent liveness lease without a session group")
	}
	name := parentLivenessMutexName(group)
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("encode parent liveness mutex name: %w", err)
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutex := kernel32.NewProc("CreateMutexW")
	releaseMutex := kernel32.NewProc("ReleaseMutex")
	setLastError := kernel32.NewProc("SetLastError")
	lease := &parentLivenessLease{stop: make(chan struct{}), done: make(chan struct{})}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(lease.done)
		setLastError.Call(0)
		h, _, callErr := createMutex.Call(0, 1, uintptr(unsafe.Pointer(namePtr)))
		lastErr := syscall.GetLastError()
		if h == 0 {
			if lastErr != syscall.Errno(0) {
				callErr = lastErr
			}
			ready <- fmt.Errorf("CreateMutexW failed for %q: %v", name, callErr)
			return
		}
		if lastErr == syscall.ERROR_ALREADY_EXISTS {
			_ = syscall.CloseHandle(syscall.Handle(h))
			ready <- fmt.Errorf("parent liveness mutex %q already exists; refusing to join another session's lease", name)
			return
		}
		ready <- nil
		<-lease.stop
		r1, _, releaseErr := releaseMutex.Call(h)
		if r1 == 0 {
			writeFileLog(fmt.Sprintf("[WARN] [%s] ReleaseMutex failed for parent liveness lease %q: %v", timestamp(), name, releaseErr))
		}
		if closeErr := syscall.CloseHandle(syscall.Handle(h)); closeErr != nil {
			writeFileLog(fmt.Sprintf("[WARN] [%s] CloseHandle failed for parent liveness lease %q: %v", timestamp(), name, closeErr))
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return lease, nil
}

func (l *parentLivenessLease) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		close(l.stop)
		<-l.done
	})
}

const powershellJavaProcessFunctions = `
function Get-GuardProcessSnapshot($session){
  try{
    $all=@(Get-CimInstance -ClassName Win32_Process -OperationTimeoutSec 8 -ErrorAction Stop)
    if($all.Count -lt 1){throw 'Win32_Process 返回空快照'}
    return [pscustomobject]@{Processes=$all;NativeFallback=$false}
  }catch{
    $detail='CIM unavailable HResult='+$_.Exception.HResult+' FQID='+$_.FullyQualifiedErrorId+' :: '+$_.Exception.Message
    if(Get-Command Write-GuardLog -ErrorAction SilentlyContinue){Write-GuardLog('[process-fallback] '+$detail)}
    $all=[Diagnostics.Process]::GetProcesses()
    if($all.Count -lt 1){throw ($detail+'；原生进程枚举也为空')}
    $rows=New-Object System.Collections.Generic.List[object]
    $launcherName=[IO.Path]::GetFileNameWithoutExtension([string]$session.LauncherPath)
    try{
      foreach($proc in $all){
        try{
          $id=$proc.Id;$name=$proc.ProcessName
          $java=($name -match '(?i)^javaw?$')
          $launcher=($launcherName -and $name -ieq $launcherName)
          $parent=($id -eq [int]$session.ParentPID)
          if(-not ($java -or $launcher -or $parent)){continue}
          # An unreadable start time cannot be discarded as an exited process.
          $created=$proc.StartTime.ToUniversalTime()
          $image=''
          try{$image=$proc.MainModule.FileName}catch{if($launcher -and -not $parent){throw}}
          $rows.Add([pscustomobject]@{ProcessId=$id;Name=($name+'.exe');CreationDate=$created;ExecutablePath=$image;ParentProcessId=0;CommandLine='';GuardUnverifiedJava=$java;GuardUnverifiedLauncher=$launcher})
        }catch{throw ($detail+'；原生属性不完整，拒绝确认退出：PID='+$proc.Id+' :: '+$_.Exception.Message)}
      }
    }finally{foreach($proc in $all){$proc.Dispose()}}
    # Sentinel means enumeration succeeded even when it found no relevant process.
    $rows.Add([pscustomobject]@{ProcessId=0})
    return [pscustomobject]@{Processes=@($rows.ToArray());NativeFallback=$true}
  }
}
function Sync-SessionJavaPaths($state){
  if(-not $cfg.Strict){return}
  $changed=$false
  foreach($proc in @($state.ConfirmedJavaProcesses)){
    $path=[string]$proc.ExecutablePath
    if(-not $path -or -not [IO.Path]::IsPathRooted($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)){continue}
    if(@($cfg.JavaPaths|Where-Object{(Normalize-ProcessImagePath ([string]$_)) -eq (Normalize-ProcessImagePath $path)}).Count -gt 0){continue}
    # Persist exact path before rules or disabled-user-allow journal can reference it.
    $priorPaths=@($cfg.JavaPaths)
    $cfg.JavaPaths=@($cfg.JavaPaths)+@($path)
    try{Write-AtomicJson (Join-Path $cfg.StateDir 'session.json') $cfg 8}
    catch{$cfg.JavaPaths=$priorPaths;throw}
    $changed=$true
    Write-GuardLog('[java-runtime] 已核验本会话后代 + Minecraft 参数，加入精确路径；PID='+[int]$proc.ProcessId+' CreatedUtc='+([DateTime]$proc.CreationDate).ToUniversalTime().ToString('o')+' path='+$path)
  }
  if($changed){
    # Disable conflicting exact-program Allow only after write-ahead metadata.
    Audit-AndDisableProgramAllows
    Assert-NoUnmanagedActiveAllows
    if(Get-Command Rebuild-FirewallRules -ErrorAction SilentlyContinue){Rebuild-FirewallRules}
    else{Add-Firewall}
  }
}

function Normalize-ProcessImagePath([string]$path){
  if([string]::IsNullOrWhiteSpace($path)){return ''}
  try{$full=[IO.Path]::GetFullPath($path);if($full.Length -gt 3){$full=$full.TrimEnd([char[]]@([char]92,[char]47))};return $full.ToLowerInvariant()}catch{return ''}
}
function Get-GuardParentLeaseMutexState([string]$Group){
  if([string]::IsNullOrWhiteSpace($Group)){return 'Missing'}
  $name='Local\HachimiGuardParentLease-'+$Group
  $mutex=$null
  try{$mutex=[System.Threading.Mutex]::OpenExisting($name)}
  catch{
    $baseException=$_.Exception.GetBaseException()
    if($baseException -is [System.Threading.WaitHandleCannotBeOpenedException]){return 'Missing'}
    return 'Unknown'
  }
  try{
    try{
      if(-not $mutex.WaitOne(0)){return 'Held'}
      $mutex.ReleaseMutex()
      return 'Free'
    }catch{
      # WaitOne throws AbandonedMutexException after acquiring an abandoned mutex.
      # Unwrap PowerShell's MethodInvocationException before testing the type.
      $baseException=$_.Exception.GetBaseException()
      if($baseException -is [System.Threading.AbandonedMutexException]){
        try{$mutex.ReleaseMutex()}catch{}
        return 'Abandoned'
      }
      return 'Unknown'
    }
  }catch{return 'Unknown'}
  finally{if($mutex){$mutex.Dispose()}}
}
function Get-DirectParentProcessProbe([int]$ProcessId,[DateTime]$SessionStart){
  if($ProcessId -le 0){return 'NoPID'}
  $p=$null
  try{$p=[System.Diagnostics.Process]::GetProcessById($ProcessId)}
  catch{
    $baseException=$_.Exception.GetBaseException()
    if($baseException -is [System.ArgumentException]){return 'Absent'}
    return 'Unknown'
  }
  try{
    if($p.HasExited){return 'Absent'}
    try{
      $created=$p.StartTime.ToUniversalTime()
      if($created -gt $SessionStart){return 'ReusedPID'}
      return 'Alive'
    }catch{return 'UnknownAlive'}
  }catch{return 'UnknownAlive'}
  finally{if($p){$p.Dispose()}}
}
function Test-MinecraftJavaCommandLine([string]$commandLine){
  if([string]::IsNullOrWhiteSpace($commandLine)){return $false}
  $strong='(?i)(net\.minecraft\.client\.main\.Main|net\.minecraft\.server\.Main|net\.minecraft\.launchwrapper\.Launch|net\.fabricmc\.loader\.(?:impl\.)?launch\.knot\.Knot(?:Client|Server)|org\.quiltmc\.loader\.(?:impl\.)?launch\.knot\.Knot(?:Client|Server)|cpw\.mods\.modlauncher\.Launcher|net\.minecraftforge\.|net\.neoforged\.|--launchTarget(?:=|\s+)(?:forgeclient|forgeserver|neoforgeclient|neoforgeserver))'
  if($commandLine -match $strong){return $true}
  $hasGameDir=$commandLine -match '(?i)(^|\s)--gameDir(?:=|\s)'
  $hasAssets=$commandLine -match '(?i)(^|\s)--(?:assetsDir|assetIndex)(?:=|\s)'
  $hasIdentity=$commandLine -match '(?i)(^|\s)--(?:accessToken|username|uuid|version|versionType)(?:=|\s)'
  return ($hasGameDir -and $hasAssets -and $hasIdentity)
}
function Get-SessionProcessState($session){
  if([string]::IsNullOrWhiteSpace([string]$session.SessionStartUtc)){throw '会话 SessionStartUtc 缺失，无法安全判断进程归属'}
  try{$sessionStart=[DateTime]::Parse([string]$session.SessionStartUtc).ToUniversalTime()}
  catch{throw ('会话 SessionStartUtc 无法解析，拒绝猜测进程归属：'+[string]$session.SessionStartUtc)}
  $snapshot=Get-GuardProcessSnapshot $session
  $processes=@($snapshot.Processes)
  $byPid=@{}
  $creationByPid=@{}
  foreach($proc in $processes){
    try{
      $procId=[int]$proc.ProcessId
      if($procId -le 0){continue}
      $created=[DateTime]$proc.CreationDate
      if($created.Kind -eq [DateTimeKind]::Unspecified){$created=[DateTime]::SpecifyKind($created,[DateTimeKind]::Local)}
      $byPid[$procId]=$proc
      $creationByPid[$procId]=$created.ToUniversalTime()
    }catch{
      if([int]$proc.ProcessId -eq [int]$session.ParentPID -or [string]$proc.Name -match '(?i)^javaw?\.exe$' -or [string]$proc.Name -ieq [IO.Path]::GetFileName([string]$session.LauncherPath)){throw ('相关进程创建时间不可读，拒绝猜测退出：PID='+[string]$proc.ProcessId+' :: '+$_.Exception.Message)}
    }
  }

  $parentAlive=$false
  $parentPathMatchedByName=$false
  $parentIdentityUnverified=$false
  $parentId=[int]$session.ParentPID
  if($parentId -gt 0 -and $byPid.ContainsKey($parentId) -and $creationByPid.ContainsKey($parentId)){
    $parentProc=$byPid[$parentId]
    $parentCreated=$creationByPid[$parentId]
    # The GuardLauncher parent predates the session record. A later process that reuses
    # the same PID must not keep this old session artificially alive.
    if($parentCreated -le $sessionStart){
      $expectedParent=Normalize-ProcessImagePath ([string]$session.ParentPath)
      $actualParent=Normalize-ProcessImagePath ([string]$parentProc.ExecutablePath)
      if($expectedParent){
        $parentAlive=($actualParent -eq $expectedParent)
        if(-not $parentAlive){
          # Some Windows launch paths expose the same image through a different
          # path representation (for example, a device/extended path prefix).
          # PID + non-reused creation time + exact executable basename is a safe
          # compatibility fallback; a PID reused after SessionStartUtc is rejected.
          $expectedName=[IO.Path]::GetFileName([string]$session.ParentPath)
          $actualName=[IO.Path]::GetFileName([string]$parentProc.Name)
          if(-not $actualName){$actualName=[IO.Path]::GetFileName([string]$parentProc.ExecutablePath)}
          if($expectedName -and $actualName -and $expectedName -ieq $actualName){
            $parentAlive=$true
            $parentPathMatchedByName=$true
          }else{
            # The PID is present and its creation time predates SessionStartUtc,
            # so it cannot be a PID reused after this session began. If Windows
            # exposes an unexpected/empty image path, treat it as an unverified
            # but still-live parent; never restore while this PID remains.
            $parentAlive=$true
            $parentIdentityUnverified=$true
          }
        }
      }else{ 
        # Legacy metadata does not contain ParentPath. A GuardLauncher-looking
        # image is preferred, but an older PID that predates SessionStartUtc is
        # still treated conservatively if its image name cannot be read.
        $parentIdentityUnverified=$false
        # Backward compatibility for v17.3 session.json, which did not store ParentPath.
        $parentName=[IO.Path]::GetFileName([string]$parentProc.ExecutablePath)
        if($parentName -match '(?i)^(GuardLauncher|HachimiGuard).*\.exe$'){$parentAlive=$true}
        else{$parentAlive=$true;$parentIdentityUnverified=$true}
      }
    }
  }

  # A WMI snapshot can omit a live process transiently. The kernel mutex is held by
  # GuardLauncher from before UAC until the parent exits; System.Diagnostics.Process
  # is an independent fallback. A missing WMI row alone is never proof of parent exit.
  $parentLeaseState=Get-GuardParentLeaseMutexState ([string]$session.Group)
  $parentProbeState='NotNeeded'
  # A held lease is direct evidence of the GuardLauncher parent even when an
  # older/corrupt session record has no usable ParentPID. Do not ignore it.
  if($parentLeaseState -eq 'Held'){
    $parentAlive=$true
    if($parentId -le 0){$parentIdentityUnverified=$true}
  }
  if($parentId -gt 0 -and -not $parentAlive){
    $parentProbeState=Get-DirectParentProcessProbe $parentId $sessionStart
    if($parentProbeState -in @('Alive','UnknownAlive','Unknown')){
      $parentAlive=$true
      $parentIdentityUnverified=$true
    }
  }elseif($parentId -le 0 -and $parentLeaseState -eq 'Unknown'){
    # With no PID, inability to inspect the mutex is not proof of parent exit.
    $parentAlive=$true
    $parentIdentityUnverified=$true
  }

  $launcherPath=Normalize-ProcessImagePath ([string]$session.LauncherPath)
  $launcherHits=@()
  $roots=@{}
  if($parentAlive -and $parentId -gt 0){$roots[$parentId]=1}
  foreach($proc in $processes){
    $procId=[int]$proc.ProcessId
    if(-not $creationByPid.ContainsKey($procId)){continue}
    $created=$creationByPid[$procId]
    if($launcherPath -and ((Normalize-ProcessImagePath ([string]$proc.ExecutablePath)) -eq $launcherPath -or [bool]$proc.GuardUnverifiedLauncher -or (-not [string]$proc.ExecutablePath -and [string]$proc.Name -ieq [IO.Path]::GetFileName([string]$session.LauncherPath))) -and $created -ge $sessionStart){
      $launcherHits+=,$proc
      $roots[$procId]=1
    }
  }

  # Build only descendants of this exact GuardLauncher process or this session's launcher.
  # Exact creation-time ordering prevents a reused ParentProcessId from attaching an older process.
  $descendants=@{}
  foreach($rootId in $roots.Keys){$descendants[[int]$rootId]=1}
  $changed=$true
  while($changed){
    $changed=$false
    foreach($proc in $processes){
      $childId=[int]$proc.ProcessId
      $processParentId=[int]$proc.ParentProcessId
      if($childId -le 0 -or $descendants.ContainsKey($childId) -or -not $descendants.ContainsKey($processParentId)){continue}
      if(-not $creationByPid.ContainsKey($childId) -or -not $creationByPid.ContainsKey($processParentId)){continue}
      $childCreated=$creationByPid[$childId]
      $processParentCreated=$creationByPid[$processParentId]
      if($childCreated -ge $processParentCreated){
        $descendants[$childId]=1
        $changed=$true
      }
    }
  }

  $javaPathSet=@{}
  foreach($javaPath in @($session.JavaPaths)){
    $normalized=Normalize-ProcessImagePath ([string]$javaPath)
    if($normalized){$javaPathSet[$normalized]=1}
  }
  $javaHits=@()
  $confirmedJava=@()
  foreach($proc in $processes){
    $procId=[int]$proc.ProcessId
    if(-not $creationByPid.ContainsKey($procId)){continue}
    if($creationByPid[$procId] -lt $sessionStart){continue}
    $imageName=[IO.Path]::GetFileName([string]$proc.Name)
    if($imageName -notmatch '(?i)^javaw?\.exe$'){
      $imageName=[IO.Path]::GetFileName([string]$proc.ExecutablePath)
      if($imageName -notmatch '(?i)^javaw?\.exe$'){continue}
    }
    $imagePath=Normalize-ProcessImagePath ([string]$proc.ExecutablePath)
    $knownJavaPath=($imagePath -and $javaPathSet.ContainsKey($imagePath))
    $isDescendant=$descendants.ContainsKey($procId)
    $hasMinecraftArguments=Test-MinecraftJavaCommandLine ([string]$proc.CommandLine)
    # Custom runtimes absent from JavaPaths.txt are recognized by Minecraft/Fabric/Forge/Quilt
    # arguments. A configured Java binary is accepted only when it descends from this session.
    if($hasMinecraftArguments -or ($isDescendant -and $knownJavaPath) -or [bool]$proc.GuardUnverifiedJava -or -not $imagePath -or [string]::IsNullOrWhiteSpace([string]$proc.CommandLine)){$javaHits+=,$proc}
    if(-not $snapshot.NativeFallback -and $hasMinecraftArguments -and $isDescendant -and $imagePath){$confirmedJava+=,$proc}
  }

  return [pscustomobject]@{
    ParentAlive=$parentAlive
    ParentPathMatchedByName=$parentPathMatchedByName
    ParentIdentityUnverified=$parentIdentityUnverified
    ParentLeaseState=$parentLeaseState
    ParentProbeState=$parentProbeState
    LauncherProcesses=@($launcherHits)
    JavaProcesses=@($javaHits)
    ConfirmedJavaProcesses=@($confirmedJava)
    NativeFallback=[bool]$snapshot.NativeFallback
  }
}
`

const powershellEffectiveACLFunctions = `
function Test-GuardProtectionEffective($path,$sid){
  try{
    $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
    foreach($ace in $acl.Access){
      if($ace.AccessControlType -ne 'Deny' -or (($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)){continue}
      $aceSid='';try{$aceSid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$aceSid=[string]$ace.IdentityReference.Value}
      $rights=([Security.AccessControl.FileSystemRights]$ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl)
      if($aceSid -eq $sid -and $rights -eq [Security.AccessControl.FileSystemRights]::FullControl){return $true}
    }
  }catch{throw ('无法读取 ACL 保护状态：'+$path+' :: '+$_.Exception.Message)}
  return $false
}
`

const powershellSessionLifecycleFunctions = `
function Save-PendingDynamicId([string]$Id){
  if(-not $Id){return}
  $path=Join-Path $cfg.StateDir 'dynamic_keywords.json'
  $all=@{}
  if(Test-Path -LiteralPath $path){$obj=(Read-GuardUtf8Text $path)|ConvertFrom-Json -ErrorAction Stop;foreach($prop in $obj.PSObject.Properties){$all[[string]$prop.Name]=[string]$prop.Value}}
  if(@($all.Values|Where-Object{$_ -eq $Id}).Count -eq 0){$all['pending:'+ $Id]=$Id}
  Write-AtomicJson $path $all 4
}
function Remove-PendingDynamicIds([string[]]$Ids){
  $path=Join-Path $cfg.StateDir 'dynamic_keywords.json'
  foreach($id in @($Ids|Where-Object{$_}|Select-Object -Unique)){
    Save-PendingDynamicId $id
    try{
      if(-not (Get-Command Get-NetFirewallDynamicKeywordAddress -ErrorAction SilentlyContinue) -or -not (Get-Command Remove-NetFirewallDynamicKeywordAddress -ErrorAction SilentlyContinue)){throw '动态对象查询/删除命令不可用'}
      # Enumerate, then filter exact ID. -Id on an already absent object can
      # produce a provider "not found" exception on supported Windows versions.
      $matches=@(Get-NetFirewallDynamicKeywordAddress -ErrorAction Stop|Where-Object{[string]$_.Id -ieq $id})
      if($matches.Count -gt 0){Remove-NetFirewallDynamicKeywordAddress -Id $id -ErrorAction Stop|Out-Null}
      if(@(Get-NetFirewallDynamicKeywordAddress -ErrorAction Stop|Where-Object{[string]$_.Id -ieq $id}).Count -gt 0){throw ('删除后对象仍存在：'+$id)}
      $all=@{};$obj=(Read-GuardUtf8Text $path)|ConvertFrom-Json -ErrorAction Stop
      foreach($prop in $obj.PSObject.Properties){if([string]$prop.Value -ine $id){$all[[string]$prop.Name]=[string]$prop.Value}}
      Write-AtomicJson $path $all 4
    }catch{Write-GuardLog('[dynamic-cleanup] 保留待重试 ID='+$id+' :: '+$_.Exception.Message)}
  }
}
function Assert-DynamicCleanupComplete([string]$Path){
  if(-not (Test-Path -LiteralPath $Path)){return}
  $obj=(Read-GuardUtf8Text $Path)|ConvertFrom-Json -ErrorAction Stop
  $failed=New-Object System.Collections.Generic.List[string]
  foreach($prop in $obj.PSObject.Properties){
    $id=[string]$prop.Value;if(-not $id){continue}
    try{
      $existing=@(Get-NetFirewallDynamicKeywordAddress -ErrorAction Stop|Where-Object{[string]$_.Id -ieq $id})
      if($existing.Count -gt 0){Remove-NetFirewallDynamicKeywordAddress -Id $id -ErrorAction Stop|Out-Null}
      if(@(Get-NetFirewallDynamicKeywordAddress -ErrorAction Stop|Where-Object{[string]$_.Id -ieq $id}).Count -gt 0){throw ('动态对象残留：'+$id)}
    }catch{$failed.Add($id+' :: '+$_.Exception.Message)}
  }
  if($failed.Count -gt 0){throw ('动态对象恢复未完成，保留原清单：'+($failed -join '; '))}
}

function Write-Notification($obj){
  try{
    if(-not $cfg.NotificationPath){return}
    if((Test-Path -LiteralPath $cfg.NotificationPath) -and (Get-Item -LiteralPath $cfg.NotificationPath -ErrorAction Stop).Length -ge 4194304){
      Write-AtomicText $cfg.NotificationPath ''
    }
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($obj|ConvertTo-Json -Compress)+[Environment]::NewLine)
    $fs=[IO.File]::Open($cfg.NotificationPath,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
    try{$fs.Write($bytes,0,$bytes.Length);$fs.Flush($true)}finally{$fs.Dispose()}
  }catch{Write-GuardLog('[notification] 写入通知失败（持久审计日志仍保留事件）：'+$_.Exception.Message)}
}

__EFFECTIVE_ACL_FUNCTIONS__
function Get-GuardInheritanceFlags([object]$Record){
  if($null -ne $Record -and $Record.PSObject.Properties['InheritanceFlags'] -and -not [string]::IsNullOrWhiteSpace([string]$Record.InheritanceFlags)){return [string]$Record.InheritanceFlags}
  if($null -ne $Record -and $Record.PSObject.Properties['IsDirectory'] -and -not [bool]$Record.IsDirectory){return 'None'}
  return 'ContainerInherit,ObjectInherit'
}

$script:sessionLeaseStream=$null
$script:heartbeatSequence=[long]0
$script:aclJournalCache=@{}
$script:aclJournalIntegrityChecked=@{}
$script:watchdogProcessCreatedUtc=$null
function Read-GuardUtf8Text([string]$Path){
  if([string]::IsNullOrWhiteSpace($Path)){throw 'UTF-8 read path is empty'}
  $bytes=[IO.File]::ReadAllBytes($Path)
  $offset=0
  # Accept an optional UTF-8 BOM only. Do not let StreamReader silently switch
  # to UTF-16/UTF-32 based on another BOM for files whose format is UTF-8.
  if($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF){$offset=3}
  elseif(($bytes.Length -ge 2 -and (($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF))) -or ($bytes.Length -ge 4 -and (($bytes[0] -eq 0x00 -and $bytes[1] -eq 0x00 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) -or ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x00)))){
    throw ('文件带有非 UTF-8 BOM，拒绝按错误编码猜测：'+$Path)
  }
  $encoding=New-Object System.Text.UTF8Encoding($false,$true)
  try{return $encoding.GetString($bytes,$offset,$bytes.Length-$offset)}
  catch{throw ('文件不是有效 UTF-8，拒绝使用系统代码页解码：'+$Path+' :: '+$_.Exception.ToString())}
}
function Get-SessionLogMutexName{
  if([string]::IsNullOrWhiteSpace([string]$cfg.AuditLogPath)){return 'Local\HachimiGuardLog-default'}
  $full=[IO.Path]::GetFullPath([string]$cfg.AuditLogPath).ToLowerInvariant()
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$hash=(-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($full))|ForEach-Object{$_.ToString('x2')}))}
  finally{$sha.Dispose()}
  return ('Local\HachimiGuardLog-'+$hash)
}
function Write-GuardLog([string]$msg){
  $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ',[Globalization.CultureInfo]::InvariantCulture)
  $group=[string]$cfg.Group
  $line=$stamp+' [session='+$group+'] '+$msg+[Environment]::NewLine
  $written=$false
  if(-not [string]::IsNullOrWhiteSpace([string]$cfg.AuditLogPath)){
    $mutex=$null;$locked=$false;$stream=$null
    try{
      $mutex=New-Object -TypeName System.Threading.Mutex -ArgumentList @($false,(Get-SessionLogMutexName))
      try{$locked=$mutex.WaitOne(10000)}catch [System.Threading.AbandonedMutexException]{$locked=$true}
      if(-not $locked){throw '等待持久化日志互斥锁超时'}
      $stream=[IO.File]::Open([string]$cfg.AuditLogPath,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
      $bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes($line)
      $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true);$written=$true
    }catch{
      try{[Console]::Error.WriteLine('[HachimiGuard log failure] '+$_.Exception.Message)}catch{}
    }finally{
      if($stream){try{$stream.Dispose()}catch{}}
      if($locked -and $mutex){try{$mutex.ReleaseMutex()}catch{}}
      if($mutex){try{$mutex.Dispose()}catch{}}
    }
  }
  if(-not $written){
    $fallbackCandidates=@()
    if(-not [string]::IsNullOrWhiteSpace([string]$cfg.StateRoot)){$fallbackCandidates+=,(Join-Path $cfg.StateRoot 'lifecycle-emergency.log')}
    if(-not [string]::IsNullOrWhiteSpace([string]$cfg.StateDir)){$fallbackCandidates+=,(Join-Path $cfg.StateDir 'emergency-lifecycle.log')}
    foreach($fallback in $fallbackCandidates){
      try{$fs=[IO.File]::Open($fallback,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);try{$bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes($line);$fs.Write($bytes,0,$bytes.Length);$fs.Flush($true)}finally{$fs.Dispose()};break}
      catch{try{[Console]::Error.WriteLine('[HachimiGuard emergency log failure] '+$_.Exception.Message)}catch{}}
    }
  }
}
function Get-GuardFirewallRulesByGroup{
  param([Parameter(Mandatory=$true)][string]$Group,[Parameter(Mandatory=$true)][ValidateSet('PersistentStore','ActiveStore')][string]$PolicyStore)
  if([string]::IsNullOrWhiteSpace($Group)){throw '拒绝使用空 Group 查询 Guard 防火墙规则'}
  # Do not pass Group to the NetSecurity CIM query. The user's Windows 11 log confirms that a zero-match Remove-by-Group
  # operation can throw a CimJobException. Enumerate the selected store and
  # compare the Group property locally before invoking Remove-NetFirewallRule.
  $allRules=@(Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction Stop)
  $groupRules=@($allRules|Where-Object{[string]::Equals([string]$_.Group,$Group,[System.StringComparison]::OrdinalIgnoreCase)})
  return $groupRules
}
function Remove-GuardFirewallRulesByGroup{
  param([Parameter(Mandatory=$true)][string]$Group,[string]$Context='unspecified')
  if([string]::IsNullOrWhiteSpace($Group)){throw '拒绝删除空 Group 的防火墙规则'}
  # Guard creates its rules in PersistentStore. Remove only those exact local
  # objects; if any same-group ActiveStore rule remains (for example a GPO rule),
  # fail closed instead of touching policy outside Guard's ownership.
  $persistentRules=@(Get-GuardFirewallRulesByGroup -Group $Group -PolicyStore 'PersistentStore')
  $removedCount=$persistentRules.Count
  if($removedCount -gt 0){
    Remove-NetFirewallRule -InputObject $persistentRules -ErrorAction Stop|Out-Null
  }
  $remainingRules=@(Get-GuardFirewallRulesByGroup -Group $Group -PolicyStore 'ActiveStore')
  if($remainingRules.Count -gt 0){throw ('Guard firewall rules remain in ActiveStore after '+$Context+'; group='+$Group+'; remaining='+$remainingRules.Count+'; persistentBefore='+$removedCount)}
  Write-GuardLog('[firewall-cleanup] completed context='+$Context+' group='+$Group+' persistentRemoved='+$removedCount+' activeRemaining=0; no-match is an idempotent success')
  return [int]$removedCount
}
function Secure-SessionAuditFile{
  if([string]::IsNullOrWhiteSpace([string]$cfg.AuditLogPath)){return}
  if(-not (Test-Path -LiteralPath $cfg.AuditLogPath)){
    $fs=[IO.File]::Open([string]$cfg.AuditLogPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);$fs.Dispose()
  }
  if($cfg.UserSID -notmatch '^S-1-[0-9-]+$'){throw '无法为持久化审计日志设置调用用户权限'}
  $acl=Get-Acl -LiteralPath $cfg.AuditLogPath -ErrorAction Stop
  $user=New-Object System.Security.Principal.SecurityIdentifier([string]$cfg.UserSID)
  $rights=[System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write
  $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($user,$rights,'None','None','Allow')
  $acl.SetAccessRule($rule)
  Set-Acl -LiteralPath $cfg.AuditLogPath -AclObject $acl -ErrorAction Stop

  # Pre-create a durable parent-ready acknowledgement file. The unprivileged
  # GuardLauncher may write this existing file, but cannot create or modify the
  # protected session directory itself. The Watchdog will not run automatic
  # cleanup until this acknowledgement is valid or the parent has exited.
  $ackPath=[string]$cfg.AuditLogPath+'.watchdog.parent_ready.json'
  if(-not (Test-Path -LiteralPath $ackPath)){
    $ackStream=[IO.File]::Open($ackPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
    $ackStream.Dispose()
  }
  $ackAcl=Get-Acl -LiteralPath $ackPath -ErrorAction Stop
  $ackRights=[System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write
  $ackRule=New-Object System.Security.AccessControl.FileSystemAccessRule($user,$ackRights,'None','None','Allow')
  $ackAcl.SetAccessRule($ackRule)
  Set-Acl -LiteralPath $ackPath -AclObject $ackAcl -ErrorAction Stop
}
function Acquire-SessionLease([int]$TimeoutSeconds=30,[string]$Owner='Helper'){
  if($script:sessionLeaseStream){return $true}
  if([string]::IsNullOrWhiteSpace([string]$cfg.StateRoot)){throw 'StateRoot 缺失，拒绝取得会话互斥锁'}
  $lockPath=Join-Path $cfg.StateRoot 'active-session.lock'
  $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  $lastError=''
  $nextContentionLog=[DateTime]::UtcNow.AddSeconds(5)
  while([DateTime]::UtcNow -lt $deadline){
    $fs=$null
    try{
      $fs=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
      $ownerText='PID='+$PID+';Owner='+$Owner+';Group='+[string]$cfg.Group+';AcquiredUtc='+[DateTime]::UtcNow.ToString('o')
      $bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes($ownerText)
      $fs.SetLength(0);$fs.Position=0;$fs.Write($bytes,0,$bytes.Length);$fs.Flush($true)
      $script:sessionLeaseStream=$fs;$fs=$null
      Write-GuardLog('[session-lock] acquired owner='+$Owner+' pid='+$PID)
      return $true
    }catch [System.IO.IOException]{$lastError=$_.Exception.Message}
    catch{$lastError=$_.Exception.Message}
    finally{if($fs){try{$fs.Dispose()}catch{}}}
    if([DateTime]::UtcNow -ge $nextContentionLog){Write-GuardLog('[session-lock] still waiting for global lease owner='+$Owner+'; last error='+$lastError);$nextContentionLog=[DateTime]::UtcNow.AddSeconds(5)}
    Start-Sleep -Milliseconds 250
  }
  throw ('全局会话互斥锁不可用或被其他实例持有；拒绝并发修改系统状态。路径='+$lockPath+'；最后错误='+$lastError)
}
function Release-SessionLease{
  if($script:sessionLeaseStream){
    try{$script:sessionLeaseStream.Flush($true)}catch{}
    try{$script:sessionLeaseStream.Dispose()}catch{}
    $script:sessionLeaseStream=$null
    Write-GuardLog('[session-lock] released owner PID='+$PID)
  }
}
function Write-SessionHeartbeat([string]$Status,[string]$Message=''){
  if(-not $script:watchdogProcessCreatedUtc){
    $proc=Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = '+$PID) -ErrorAction Stop
    if($null -eq $proc){throw '无法取得 Watchdog 自身的 Win32_Process 身份'}
    $created=[DateTime]$proc.CreationDate
    if($created.Kind -eq [DateTimeKind]::Unspecified){$created=[DateTime]::SpecifyKind($created,[DateTimeKind]::Local)}
    $script:watchdogProcessCreatedUtc=$created.ToUniversalTime().ToString('o')
  }
  $script:heartbeatSequence++
  $obj=[pscustomobject]@{
    Schema=1;Group=[string]$cfg.Group;PID=[int]$PID;ProcessCreatedUtc=[string]$script:watchdogProcessCreatedUtc
    HeartbeatUtc=[DateTime]::UtcNow.ToString('o');Sequence=[long]$script:heartbeatSequence;Status=$Status;Message=$Message
  }
  $path=Join-Path $cfg.StateDir 'watchdog.heartbeat.json'
  Write-AtomicJson $path $obj 4 -Quiet
}
function Write-AtomicText([string]$Path,[string]$Text,[switch]$Utf8Bom){
  if([string]::IsNullOrWhiteSpace($Path)){throw '原子写入路径为空'}
  $full=[IO.Path]::GetFullPath($Path)
  $dir=[IO.Path]::GetDirectoryName($full)
  if([string]::IsNullOrWhiteSpace($dir)){throw ('原子写入目标没有有效父目录：'+$full)}
  if([IO.Directory]::Exists($full)){throw ('原子写入目标是目录而不是文件：'+$full)}
  if(-not [IO.Directory]::Exists($dir)){[IO.Directory]::CreateDirectory($dir)|Out-Null}
  $leaf=[IO.Path]::GetFileName($full)
  $temp=Join-Path $dir ($leaf+'.'+[guid]::NewGuid().ToString('N')+'.tmp')
  $backup=''
  $fs=$null
  try{
    $encoding=New-Object System.Text.UTF8Encoding([bool]$Utf8Bom)
    $bytes=$encoding.GetBytes([string]$Text)
    if($Utf8Bom){
      # UTF8Encoding.GetBytes does not include the preamble; prepend it explicitly
      # so Windows PowerShell 5.1 decodes non-ASCII script text as UTF-8.
      $preamble=$encoding.GetPreamble()
      $combined=New-Object byte[] ($preamble.Length+$bytes.Length)
      [System.Buffer]::BlockCopy($preamble,0,$combined,0,$preamble.Length)
      [System.Buffer]::BlockCopy($bytes,0,$combined,$preamble.Length,$bytes.Length)
      $bytes=$combined
    }
    $fs=New-Object System.IO.FileStream($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $fs.Write($bytes,0,$bytes.Length);$fs.Flush($true);$fs.Dispose();$fs=$null
    if([IO.File]::Exists($full)){
      # Pass an explicit same-directory backup path. This avoids PowerShell 5.1
      # overload/binder ambiguity around a null backup argument and preserves
      # the previous journal if the replace operation fails.
      $backup=Join-Path $dir ($leaf+'.'+[guid]::NewGuid().ToString('N')+'.bak')
      [IO.File]::Replace([string]$temp,[string]$full,[string]$backup,[bool]$true)
      if(-not [IO.File]::Exists($full)){throw ('原子替换返回后目标文件不存在：'+$full)}
      if([IO.File]::Exists($backup)){
        try{[IO.File]::Delete($backup);$backup=''}
        catch{Write-GuardLog('[journal] 原子替换已完成，但旧版本备份暂时无法删除：'+$backup+' :: '+$_.Exception.Message)}
      }
    }else{
      try{[IO.File]::Move($temp,$full)}catch{
        if([IO.File]::Exists($full)){
          # A concurrent creator won the first-write race. Use the same explicit
          # backup protocol rather than replacing without a recoverable old copy.
          $backup=Join-Path $dir ($leaf+'.'+[guid]::NewGuid().ToString('N')+'.bak')
          [IO.File]::Replace([string]$temp,[string]$full,[string]$backup,[bool]$true)
          if(-not [IO.File]::Exists($full)){throw ('竞争创建后的原子替换未生成目标文件：'+$full)}
          if([IO.File]::Exists($backup)){
            try{[IO.File]::Delete($backup);$backup=''}
            catch{Write-GuardLog('[journal] 并发首次写入替换已完成，但旧版本备份暂时无法删除：'+$backup+' :: '+$_.Exception.Message)}
          }
        }else{throw}
      }
    }
    if(-not [IO.File]::Exists($full)){throw ('原子写入完成后目标文件不存在：'+$full)}
  }catch{
    $atomicWriteError=$_.Exception.Message
    if($fs){try{$fs.Dispose()}catch{}}
    $sourceExists=$false;$destinationExists=$false;$backupExists=$false
    try{$sourceExists=[IO.File]::Exists($temp)}catch{}
    try{$destinationExists=[IO.File]::Exists($full)}catch{}
    if($backup){try{$backupExists=[IO.File]::Exists($backup)}catch{}}
    $details='source='+$temp+' sourceExists='+$sourceExists+' destination='+$full+' destinationExists='+$destinationExists+' backup='+$backup+' backupExists='+$backupExists
    throw ('原子写入失败：'+$full+' :: '+$atomicWriteError+' :: '+$details)
  }finally{
    if([IO.File]::Exists($temp)){try{[IO.File]::Delete($temp)}catch{Write-GuardLog('[journal] 无法清理原子写入临时文件：'+$temp)}}
    if($backup -and [IO.File]::Exists($backup)){Write-GuardLog('[journal] 备份文件保留供诊断/恢复：'+$backup)}
  }
}
function Write-AtomicJson([string]$Path,[object]$Value,[int]$Depth=8,[switch]$Quiet){
  $json=ConvertTo-Json -InputObject $Value -Depth $Depth -ErrorAction Stop
  Write-AtomicText $Path $json
  if(-not $Quiet){Write-GuardLog('[journal] atomically committed JSON: '+$Path)}
}
function Ensure-AclJournalManifest([string]$StateDir){
  $path=Join-Path $StateDir 'acl_journal_manifest.json'
  $journalDir=Join-Path $StateDir 'acl_journal'
  if(-not [IO.Directory]::Exists($journalDir)){[IO.Directory]::CreateDirectory($journalDir)|Out-Null}
  $actualCount=@(Get-ChildItem -LiteralPath $journalDir -File -Filter '*.json' -ErrorAction Stop).Count
  if(Test-Path -LiteralPath $path){
    $manifest=(Read-GuardUtf8Text $path)|ConvertFrom-Json -ErrorAction Stop
    if([int]$manifest.Schema -notin @(2,3) -or [string]$manifest.Group -ne [string]$cfg.Group){throw 'ACL journal manifest schema/session mismatch; preserve state and refuse ACL mutation'}
    if($manifest.PSObject.Properties['RecordCount']){
      $expected=[int]$manifest.RecordCount
      if($expected -lt 0){throw 'ACL journal manifest RecordCount is negative; preserve state'}
      if($actualCount -lt $expected){throw ('ACL journal record loss before mutation: expected='+$expected+' actual='+$actualCount)}
      if($actualCount -gt $expected){Write-GuardLog('[acl-journal] manifest counter lag after interrupted write; reconciling committed records expected='+$expected+' actual='+$actualCount)}
    }else{Write-GuardLog('[acl-journal] migrating legacy manifest without RecordCount; actual committed records='+$actualCount)}
    $manifest.Schema=3;$manifest.RecordCount=$actualCount
    Write-AtomicJson $path $manifest 4 -Quiet
    return $true
  }
  if($actualCount -gt 0){throw ('ACL journal records exist without manifest; refuse mutation actual='+$actualCount)}
  $manifest=[pscustomobject]@{Schema=3;Group=[string]$cfg.Group;CreatedUtc=[DateTime]::UtcNow.ToString('o');Format='per-object-atomic-json';RecordCount=0}
  Write-AtomicJson $path $manifest 4 -Quiet
  Write-GuardLog('[acl-journal] initialized schema=3 group='+[string]$cfg.Group+' RecordCount=0')
  return $true
}
function Test-AclJournalManifest([string]$StateDir,[string]$ExpectedGroup=$cfg.Group){
  $path=Join-Path $StateDir 'acl_journal_manifest.json'
  if(-not (Test-Path -LiteralPath $path)){
    $journalDir=Join-Path $StateDir 'acl_journal'
    $committed=0
    if(Test-Path -LiteralPath $journalDir){$committed=@(Get-ChildItem -LiteralPath $journalDir -File -Filter '*.json' -ErrorAction Stop).Count}
    if($committed -gt 0){throw ('ACL per-object journal exists without its manifest; cannot verify session provenance/count; retain state. committed='+$committed)}
    return $false
  }
  $manifest=(Read-GuardUtf8Text $path)|ConvertFrom-Json -ErrorAction Stop
  if([int]$manifest.Schema -notin @(2,3) -or [string]$manifest.Group -ne [string]$ExpectedGroup){throw 'ACL journal manifest schema/session mismatch'}
  $journalDir=Join-Path $StateDir 'acl_journal'
  $actualCount=0
  if(Test-Path -LiteralPath $journalDir){$actualCount=@(Get-ChildItem -LiteralPath $journalDir -File -Filter '*.json' -ErrorAction Stop).Count}
  if($manifest.PSObject.Properties['RecordCount']){
    $expected=[int]$manifest.RecordCount
    if($expected -lt 0){throw 'ACL journal manifest RecordCount is negative; retain state for recovery'}
    if($actualCount -lt $expected){throw ('ACL journal records missing: expected='+$expected+' actual='+$actualCount+'; retain state for recovery')}
    if($actualCount -gt $expected){
      Write-GuardLog('[acl-journal] manifest counter lag detected during recovery; committed records preserved expected='+$expected+' actual='+$actualCount)
      $manifest.RecordCount=$actualCount
      $manifest.Schema=3
      Write-AtomicJson $path $manifest 4 -Quiet
    }
  }else{
    Write-GuardLog('[acl-journal] legacy manifest has no RecordCount; validating all present committed files, actual='+$actualCount)
    $manifest.RecordCount=$actualCount;$manifest.Schema=3
    Write-AtomicJson $path $manifest 4 -Quiet
  }
  return $true
}
function Assert-AclJournalIntegrityOnce([string]$StateDir){
  $key=[IO.Path]::GetFullPath($StateDir).TrimEnd('\').ToLowerInvariant()
  if($script:aclJournalIntegrityChecked.ContainsKey($key)){return $true}
  if(-not (Test-AclJournalManifest $StateDir)){throw ('ACL journal manifest missing for active protected session: '+$StateDir)}
  $script:aclJournalIntegrityChecked[$key]=$true
  return $true
}
function Write-AclJournalRecord([string]$StateDir,[object]$Record){
  $manifestPath=Join-Path $StateDir 'acl_journal_manifest.json'
  if(-not (Test-Path -LiteralPath $manifestPath)){throw 'ACL journal manifest missing before write-ahead record; refuse ACL mutation'}
  $manifest=(Read-GuardUtf8Text $manifestPath)|ConvertFrom-Json -ErrorAction Stop
  if([int]$manifest.Schema -ne 3 -or [string]$manifest.Group -ne [string]$cfg.Group -or $null -eq $manifest.RecordCount){throw 'ACL journal manifest invalid before write-ahead record'}
  $journalDir=Join-Path $StateDir 'acl_journal'
  if(-not [IO.Directory]::Exists($journalDir)){[IO.Directory]::CreateDirectory($journalDir)|Out-Null}
  $name=([DateTime]::UtcNow.Ticks.ToString('D19'))+'_'+[guid]::NewGuid().ToString('N')+'.json'
  $path=Join-Path $journalDir $name
  Write-AtomicJson $path $Record 6 -Quiet
  # Only one session writer owns the lease. Increment after the record is durably committed.
  $manifest.RecordCount=([int]$manifest.RecordCount)+1
  Write-AtomicJson $manifestPath $manifest 4 -Quiet
  return $path
}
function Get-AclJournalRecords([string]$StateDir,[switch]$Refresh){
  $cacheKey=[IO.Path]::GetFullPath($StateDir).TrimEnd('\').ToLowerInvariant()
  if(-not $Refresh -and $script:aclJournalCache.ContainsKey($cacheKey)){return @($script:aclJournalCache[$cacheKey])}
  $records=New-Object System.Collections.Generic.List[object]
  $legacy=Join-Path $StateDir 'acl_state.ndjson'
  if(Test-Path -LiteralPath $legacy){
    $legacyText=Read-GuardUtf8Text $legacy
    $lines=@($legacyText -split "\r?\n")
    for($i=$lines.Length-1;$i -ge 0;$i--){
      if([string]::IsNullOrWhiteSpace($lines[$i])){continue}
      try{$records.Add(($lines[$i]|ConvertFrom-Json -ErrorAction Stop))}
      catch{throw ('旧 ACL NDJSON 恢复记录损坏，行 '+($i+1)+'；保留全部资料，不自动猜测：'+$_.Exception.Message)}
    }
  }
  $journalDir=Join-Path $StateDir 'acl_journal'
  if(Test-Path -LiteralPath $journalDir){
    $files=@(Get-ChildItem -LiteralPath $journalDir -File -Filter '*.json' -ErrorAction Stop|Sort-Object Name -Descending)
    foreach($file in $files){
      try{$records.Add(((Read-GuardUtf8Text $file.FullName)|ConvertFrom-Json -ErrorAction Stop))}
      catch{throw ('ACL 恢复记录损坏：'+$file.FullName+'；保留全部资料，不自动猜测：'+$_.Exception.Message)}
    }
    $temps=@(Get-ChildItem -LiteralPath $journalDir -File -Filter '*.tmp' -ErrorAction SilentlyContinue)
    foreach($temp in $temps){Write-GuardLog('[journal] ignored uncommitted ACL journal temp (write-ahead commit did not complete): '+$temp.FullName)}
  }
  $snapshot=@($records.ToArray())
  $script:aclJournalCache[$cacheKey]=$snapshot
  return $snapshot
}
function Get-FilteringPlatformAuditState{
  $auditpol=Join-Path $env:SystemRoot 'System32\auditpol.exe'
  if(!(Test-Path -LiteralPath $auditpol)){throw 'auditpol.exe 不存在'}
  $guid='{0CCE9226-69AE-11D9-BED3-505054503030}'
  $lines=@(& $auditpol '/get' ('/subcategory:'+ $guid) '/r' 2>&1)
  if($LASTEXITCODE -ne 0){throw ('auditpol /get exit code '+$LASTEXITCODE+'；输出='+(@($lines) -join ' | '))}
  $line=$lines|Where-Object{[string]$_ -match [regex]::Escape($guid)}|Select-Object -Last 1
  if([string]::IsNullOrWhiteSpace([string]$line)){throw 'auditpol CSV 中找不到 Filtering Platform Connection GUID'}
  $row=@(([string]$line)|ConvertFrom-Csv -Header ComputerName,PolicyTarget,Subcategory,SubcategoryGuid,InclusionSetting,ExclusionSetting)
  if($row.Count -ne 1){throw 'auditpol CSV 返回行数异常'}
  $setting=([string]$row[0].InclusionSetting).Trim()
  $normalized=($setting -replace '\s+',' ').Trim().ToLowerInvariant()
  $failure=$false;$known=$true;$kind=''
  switch -Regex ($normalized){
    '^(no auditing|无审核|aucune audit|keine überwachung|sin auditoría|監査なし|감사 안 함)$'{$failure=$false;$kind='None';break}
    '^(failure|失败|échec|fehler|error|失敗|실패)$'{$failure=$true;$kind='Failure';break}
    '^(success and failure|成功和失败|成功和失敗|success et échec|erfolg und fehler|correcto y error|成功と失敗|성공 및 실패)$'{$failure=$true;$kind='SuccessFailure';break}
    '^(success|成功|réussite|erfolg|correcto|成功のみ|성공)$'{$failure=$false;$kind='Success';break}
    default{$known=$false;$kind='Unknown'}
  }
  return [pscustomobject]@{FailureEnabled=$failure;Known=$known;RawLine=[string]$line;Setting=$setting;Kind=$kind}
}
function Get-OriginalAuditKind([string]$OriginalSetting){
  $normalized=(([string]$OriginalSetting) -replace '\s+',' ').Trim().ToLowerInvariant()
  switch -Regex ($normalized){
    '^(no auditing|无审核|aucune audit|keine überwachung|sin auditoría|監査なし|감사 안 함)$'{return 'None'}
    '^(success|成功|réussite|erfolg|correcto|成功のみ|성공)$'{return 'Success'}
    '^(failure|失败|échec|fehler|error|失敗|실패)$'{return 'Failure'}
    '^(success and failure|成功和失败|成功和失敗|success et échec|erfolg und fehler|correcto y error|成功と失敗|성공 및 실패)$'{return 'SuccessFailure'}
    default{return ''}
  }
}
function Get-ExpectedAuditSettingAfterFailureEnable([string]$OriginalSetting){
  $normalized=(([string]$OriginalSetting) -replace '\s+',' ').Trim().ToLowerInvariant()
  switch -Regex ($normalized){
    '^(no auditing|无审核|aucune audit|keine überwachung|sin auditoría|監査なし|감사 안 함)$'{return 'Failure'}
    '^(success|成功|réussite|erfolg|correcto|成功のみ|성공)$'{return 'SuccessFailure'}
    default{return ''}
  }
}
function Restore-AuditStateFromPath([string]$StatePath){
  if(-not (Test-Path -LiteralPath $StatePath)){
    $auditMarker=Join-Path (Split-Path -Parent $StatePath) 'audit_policy_apply_started'
    if(Test-Path -LiteralPath $auditMarker){throw 'audit_policy.json is missing although Guard marked a 5157 change; refuse to report false recovery success'}
    Write-GuardLog('[restore-step] SKIP audit-5157: no audit journal/apply marker')
    return
  }
  $st=(Read-GuardUtf8Text $StatePath)|ConvertFrom-Json -ErrorAction Stop
  if($st.FailureEnabled -isnot [bool]){throw '5157 恢复记录缺少有效的布尔 FailureEnabled 字段'}
  if([bool]$st.FailureEnabled){Write-GuardLog('[audit] 会话开始前已启用 5157 Failure 审计；Guard 未修改，保留当前策略');return}
  if($st.PSObject.Properties['ChangeAttempted'] -and -not [bool]$st.ChangeAttempted){Write-GuardLog('[audit] journal 表明 Guard 未尝试修改 5157；保留当前策略');return}
  $decodedOriginal=''
  if($st.PSObject.Properties['OriginalKind'] -and [string]$st.OriginalKind){$decodedOriginal=[string]$st.OriginalKind}
  if(-not $decodedOriginal){$decodedOriginal=Get-OriginalAuditKind ([string]$st.Setting)}
  if($decodedOriginal -notin @('None','Success','Failure','SuccessFailure')){throw '原始 5157 审核状态无法映射；保留恢复记录，拒绝猜测'}
  $decodedExpected=''
  if($st.PSObject.Properties['ExpectedKind'] -and [string]$st.ExpectedKind){$decodedExpected=[string]$st.ExpectedKind}
  if(-not $decodedExpected){$decodedExpected=Get-ExpectedAuditSettingAfterFailureEnable ([string]$st.Setting)}
  if($decodedExpected -notin @('Failure','SuccessFailure')){throw 'Guard 预期 5157 审核状态无法映射；保留恢复记录'}
  $current=Get-FilteringPlatformAuditState
  if(-not $current.Known){throw ('当前 5157 策略无法识别：'+$current.Setting)}
  if(-not $current.FailureEnabled){
    $originalKind='';if($st.PSObject.Properties['OriginalKind'] -and [string]$st.OriginalKind){$originalKind=[string]$st.OriginalKind};if(-not $originalKind){$originalKind=Get-OriginalAuditKind ([string]$st.Setting)}
    if($originalKind -and $current.Kind -eq $originalKind){Write-GuardLog('[audit] 5157 当前状态已经与会话开始前完全一致：'+$current.Setting)}
    else{Write-GuardLog('[audit] 5157 Failure 已关闭，但当前状态与原始状态不同；按外部修改处理并保留。original='+$originalKind+' current='+$current.Setting)}
    return
  }
  $expectedKind=''
  if($st.PSObject.Properties['ExpectedKind'] -and [string]$st.ExpectedKind){$expectedKind=[string]$st.ExpectedKind}
  if(-not $expectedKind){$expectedKind=Get-ExpectedAuditSettingAfterFailureEnable ([string]$st.Setting)}
  if(-not $expectedKind -or $current.Kind -ne $expectedKind){
    Write-GuardLog('[audit] 当前 5157 状态与 Guard 预期状态不一致；疑似用户/GPO 在会话期间修改，保留当前设置。original='+[string]$st.Setting+' current='+$current.Setting+' expectedKind='+$expectedKind)
    return
  }
  $auditpol=Join-Path $env:SystemRoot 'System32\auditpol.exe'
  $guid='{0CCE9226-69AE-11D9-BED3-505054503030}'
  $originalKind=''
  if($st.PSObject.Properties['OriginalKind'] -and [string]$st.OriginalKind){$originalKind=[string]$st.OriginalKind}
  if(-not $originalKind){$originalKind=Get-OriginalAuditKind ([string]$st.Setting)}
  if(-not $originalKind){throw '原始 5157 审核状态无法映射，拒绝执行不确定恢复'}
  Write-GuardLog('[restore-step] START audit-5157 disable failure; current='+$current.Setting+' expectedOriginal='+$originalKind)
  $output=@(& $auditpol '/set' ('/subcategory:'+ $guid) '/failure:disable' 2>&1)
  if($LASTEXITCODE -ne 0){throw ('auditpol restore exit code '+$LASTEXITCODE+'；输出='+(@($output)-join ' | '))}
  $after=Get-FilteringPlatformAuditState
  if(-not $after.Known -or $after.FailureEnabled -or $after.Kind -ne $originalKind){throw ('5157 恢复后状态与原始状态不一致：expected='+$originalKind+' actual='+$after.Setting)}
  Write-GuardLog('[audit] 5157 完整设置已恢复为会话开始前状态；current='+$after.Setting)
}
function Invoke-LoggedRecoveryStep([string]$Name,[scriptblock]$Action,[switch]$QuietSuccess){
  if(-not $QuietSuccess){Write-GuardLog('[restore-step] START '+$Name)}
  try{
    & $Action
    if(-not $QuietSuccess){Write-GuardLog('[restore-step] SUCCESS '+$Name)}
    return [pscustomobject]@{Name=$Name;Success=$true;Error=''}
  }catch{
    $detail=$_.Exception.ToString()
    if($_.ScriptStackTrace){$detail+=' | ScriptStackTrace='+$_.ScriptStackTrace}
    Write-GuardLog('[restore-step] FAILURE '+$Name+' :: '+($detail -replace '\r?\n',' | '))
    return [pscustomobject]@{Name=$Name;Success=$false;Error=$detail}
  }
}
function Write-SessionRecoverySummary([string]$Context,[object[]]$Results){
  $failed=@($Results|Where-Object{-not $_.Success})
  if($failed.Count -eq 0){Write-GuardLog('[restore-summary] '+$Context+' all='+$Results.Count+' failed=0');return $true}
  Write-GuardLog('[restore-summary] '+$Context+' all='+$Results.Count+' failed='+$failed.Count+' names='+(@($failed|ForEach-Object{$_.Name}) -join ','))
  return $false
}
`

const powershellHelperWatchdogFunctions = `function Start-SessionWatchdog{
  if($Mode -eq 'ResumeWatchdog'){Write-AtomicText (Join-Path $cfg.StateDir 'watchdog.resume_requested') ([DateTime]::UtcNow.ToString('o'))}
  $watchCode=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('__WATCHDOG_UTF16_B64__'))
  $watchCode=$watchCode.Replace('__CFG_B64__',$ConfigB64)
  $watchPath=Join-Path $cfg.StateDir 'watchdog.ps1'
  $watchStdoutPath=([string]$cfg.AuditLogPath)+'.watchdog.stdout.log'
  $watchStderrPath=([string]$cfg.AuditLogPath)+'.watchdog.stderr.log'
  $watchStartupPath=([string]$cfg.AuditLogPath)+'.watchdog.startup.log'
  Write-AtomicText $watchPath $watchCode -Utf8Bom
  Write-AtomicText $watchStdoutPath ''
  Write-AtomicText $watchStderrPath ''
  Write-AtomicText $watchStartupPath (([DateTime]::UtcNow.ToString('o'))+' [helper] prepared Watchdog launch; stateDir='+$cfg.StateDir+'; script='+$watchPath+[Environment]::NewLine)
  $systemPowerShell=Join-Path $PSHOME 'powershell.exe'
  Write-GuardLog('[watchdog] launching detached child; stdout='+$watchStdoutPath+' stderr='+$watchStderrPath+' script='+$watchPath)
  # Do not use -Wait here: Start-Process -Wait observes the complete descendant
  # process tree and can block the caller on this long-lived Watchdog. The helper
  # performs its own heartbeat handshake below, so launch asynchronously.
  $wp=Start-Process -FilePath $systemPowerShell -WindowStyle Hidden -WorkingDirectory $cfg.StateDir -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$watchPath+'"')) -PassThru -RedirectStandardOutput $watchStdoutPath -RedirectStandardError $watchStderrPath -ErrorAction Stop
  $createdUtc=''
  try{$createdUtc=$wp.StartTime.ToUniversalTime().ToString('o')}catch{}
  try{
    $watchdogPidPath=Join-Path $cfg.StateDir 'watchdog.pid'
    Write-AtomicText $watchdogPidPath ([string]$wp.Id)
    $savedWatchdogPid=[int](Get-Content -Raw -LiteralPath $watchdogPidPath -ErrorAction Stop).Trim()
    if($savedWatchdogPid -ne [int]$wp.Id){throw ('Watchdog PID metadata verification failed: expected='+$wp.Id+' actual='+$savedWatchdogPid)}
    if($createdUtc){Write-AtomicText (Join-Path $cfg.StateDir 'watchdog.process_created_utc') $createdUtc}
    Write-GuardLog('[watchdog] process launched PID='+$wp.Id+' CreatedUtc='+$createdUtc+' pidMetadata='+$watchdogPidPath)
  }catch{
    $metadataError=$_.Exception.Message
    # The child cannot own the lease yet because this Helper still holds it.
    # Stop it only after validating image, command line and creation time.
    try{
      $child=Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = '+$wp.Id) -ErrorAction Stop
      $sameChild=$child -and (Normalize-ProcessImagePath ([string]$child.ExecutablePath)) -eq (Normalize-ProcessImagePath $systemPowerShell) -and [string]$child.CommandLine -and ([string]$child.CommandLine).IndexOf($watchPath,[System.StringComparison]::OrdinalIgnoreCase) -ge 0
      if($sameChild -and $createdUtc){$childCreated=([DateTime]$child.CreationDate).ToUniversalTime();$expectedCreated=[DateTime]::Parse($createdUtc).ToUniversalTime();$sameChild=([Math]::Abs(($childCreated-$expectedCreated).TotalSeconds) -le 3)}
      if($sameChild){Stop-Process -Id $wp.Id -Force -ErrorAction Stop;Write-GuardLog('[watchdog] child terminated after startup metadata write failed PID='+$wp.Id)}
      else{Write-GuardLog('[watchdog] startup metadata write failed and child identity did not match; child not terminated PID='+$wp.Id)}
    }catch{Write-GuardLog('[watchdog] startup metadata failure cleanup could not verify/stop child PID='+$wp.Id+' :: '+$_.Exception.Message)}
    throw ('写入 Watchdog 进程身份记录失败：'+$metadataError)
  }
  Release-SessionLease
  $readyPath=Join-Path $cfg.StateDir 'watchdog.heartbeat.json'
  $watchStdoutPath=([string]$cfg.AuditLogPath)+'.watchdog.stdout.log'
  $watchStderrPath=([string]$cfg.AuditLogPath)+'.watchdog.stderr.log'
  $watchStartupPath=([string]$cfg.AuditLogPath)+'.watchdog.startup.log'
  $deadline=[DateTime]::UtcNow.AddSeconds(35)
  $nextHandshakeLog=[DateTime]::UtcNow.AddSeconds(10)
  $ready=$false
  $lastHeartbeatReadError='heartbeat file has not been created yet'
  while([DateTime]::UtcNow -lt $deadline){
    try{
      if(Test-Path -LiteralPath $readyPath){
        $hb=Get-Content -Raw -LiteralPath $readyPath -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
        $heartbeatAge=([DateTime]::UtcNow-[DateTime]::Parse([string]$hb.HeartbeatUtc).ToUniversalTime()).TotalSeconds
        $identityMatches=$true
        if($createdUtc -and $hb.ProcessCreatedUtc){try{$delta=([DateTime]::Parse($createdUtc).ToUniversalTime()-[DateTime]::Parse([string]$hb.ProcessCreatedUtc).ToUniversalTime()).TotalSeconds;if([Math]::Abs($delta) -gt 3){$identityMatches=$false}}catch{$identityMatches=$false}}
        if([int]$hb.PID -eq [int]$wp.Id -and [string]$hb.Group -eq [string]$cfg.Group -and $heartbeatAge -ge -2 -and $heartbeatAge -lt 12 -and [string]$hb.Status -in @('Starting','Monitoring') -and $identityMatches){$ready=$true;break}
        $lastHeartbeatReadError='heartbeat exists but fields/status/identity/age did not pass validation'
      }else{$lastHeartbeatReadError='heartbeat file has not been created yet'}
    }catch{$lastHeartbeatReadError=$_.Exception.ToString()}
    try{$wp.Refresh();if($wp.HasExited){
      $exitCode='unknown';try{$exitCode=[string]$wp.ExitCode}catch{}
      $startupText='';$stderrText='';$stdoutText=''
      try{if(Test-Path -LiteralPath $watchStartupPath){$startupText=(Get-Content -LiteralPath $watchStartupPath -Tail 20 -ErrorAction Stop)-join ' | '}}catch{}
      try{if(Test-Path -LiteralPath $watchStderrPath){$stderrText=(Get-Content -LiteralPath $watchStderrPath -Tail 20 -ErrorAction Stop)-join ' | '}}catch{}
      try{if(Test-Path -LiteralPath $watchStdoutPath){$stdoutText=(Get-Content -LiteralPath $watchStdoutPath -Tail 10 -ErrorAction Stop)-join ' | '}}catch{}
      Write-GuardLog('[watchdog] child exited before startup heartbeat PID='+$wp.Id+' ExitCode='+$exitCode+' LastHeartbeatError='+$lastHeartbeatReadError+' Startup='+$startupText+' STDERR='+$stderrText+' STDOUT='+$stdoutText)
      break
    }}catch{}
    if([DateTime]::UtcNow -ge $nextHandshakeLog){
      $startupText='';$stderrText=''
      try{if(Test-Path -LiteralPath $watchStartupPath){$startupText=(Get-Content -LiteralPath $watchStartupPath -Tail 12 -ErrorAction Stop)-join ' | '}}catch{}
      try{if(Test-Path -LiteralPath $watchStderrPath){$stderrText=(Get-Content -LiteralPath $watchStderrPath -Tail 12 -ErrorAction Stop)-join ' | '}}catch{}
      Write-GuardLog('[watchdog] waiting for startup heartbeat PID='+$wp.Id+' LastHeartbeatError='+$lastHeartbeatReadError+' Startup='+$startupText+' STDERR='+$stderrText)
      $nextHandshakeLog=[DateTime]::UtcNow.AddSeconds(10)
    }
    Start-Sleep -Milliseconds 350
  }
  if($ready){Write-GuardLog('[watchdog] startup handshake completed PID='+$wp.Id);return $wp}
  Write-GuardLog('[watchdog] startup handshake timed out; attempting safe lease reacquisition PID='+$wp.Id)
  try{Acquire-SessionLease -TimeoutSeconds 8 -Owner 'HelperStartupRecovery'}catch{throw ('Watchdog 启动握手失败，且无法重新取得会话锁；为避免双重清理，保护状态已保留。PID='+$wp.Id+'；'+$_.Exception.Message)}
  try{
    $check=Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = '+$wp.Id) -ErrorAction SilentlyContinue
    $sameWatchdog=$false
    if($check -and (Normalize-ProcessImagePath ([string]$check.ExecutablePath)) -eq (Normalize-ProcessImagePath $systemPowerShell) -and [string]$check.CommandLine -and ([string]$check.CommandLine).IndexOf($watchPath,[System.StringComparison]::OrdinalIgnoreCase) -ge 0){
      try{$checkCreated=([DateTime]$check.CreationDate).ToUniversalTime().ToString('o');$sameWatchdog=(-not $createdUtc) -or ([Math]::Abs(([DateTime]::Parse($checkCreated)-[DateTime]::Parse($createdUtc)).TotalSeconds) -le 3)}catch{}
    }
    if($sameWatchdog){Stop-Process -Id $wp.Id -Force -ErrorAction SilentlyContinue}
    elseif($check){Write-GuardLog('[watchdog] not terminating PID='+$wp.Id+' because the current process identity no longer matches the launched watchdog')}
  }catch{Write-GuardLog('[watchdog] failed to stop unresponsive startup process: '+$_.Exception.Message)}
  throw ('Watchdog 未能在限定时间内取得会话锁并写入心跳。PID='+$wp.Id)
}
`

const helperScript = `
param([string]$Mode,[string]$ConfigPath,[string]$ConfigExpectedHash,[string]$ScriptExpectedHash,[string]$ConfigJsonB64)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Continue'
$VerbosePreference='Continue'
function Get-Sha256Hex([byte[]]$bytes){
  $sha=[Security.Cryptography.SHA256]::Create()
  try{ return (-join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })) }
  finally { $sha.Dispose() }
}
if(-not [string]::IsNullOrWhiteSpace($ConfigJsonB64)){
  $configBytes=[Convert]::FromBase64String($ConfigJsonB64)
}else{
  if([string]::IsNullOrWhiteSpace($ConfigPath) -or -not (Test-Path -LiteralPath $ConfigPath)){ throw "配置文件不存在" }
  $configBytes=[IO.File]::ReadAllBytes($ConfigPath)
}
$configActual=Get-Sha256Hex $configBytes
if($ConfigExpectedHash -and ($configActual -ne $ConfigExpectedHash)){ throw "配置文件校验失败" }
$rawConfig=[Text.Encoding]::UTF8.GetString($configBytes)
$cfg=$rawConfig | ConvertFrom-Json
$ConfigB64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($rawConfig))

function Ensure-Dir($p){ if(!(Test-Path -LiteralPath $p)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function Expand-CallerPath([string]$path){
  if([string]::IsNullOrWhiteSpace($path)){return $path}
  $values=@{APPDATA=[string]$cfg.CallerAppData;LOCALAPPDATA=[string]$cfg.CallerLocalAppData;USERPROFILE=[string]$cfg.CallerUserProfile;PUBLIC=[string]$cfg.CallerPublic}
  foreach($name in @('APPDATA','LOCALAPPDATA','USERPROFILE','PUBLIC')){
    $value=[string]$values[$name]
    if($value){$path=[regex]::Replace($path,'%'+$name+'%',[System.Text.RegularExpressions.MatchEvaluator]{param($m) return $value},[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)}
  }
  return $path
}
__PERSISTENCE_FUNCTIONS__
__HELPER_WATCHDOG_FUNCTIONS__
__JAVA_PROCESS_FUNCTIONS__
function Get-FqdnCapability{
  $reasons=New-Object System.Collections.Generic.List[string]
  $dohWarnings=New-Object System.Collections.Generic.List[string]
  $build=0
  $productType=0
  $dynamicCommandParameters=@{
    'New-NetFirewallDynamicKeywordAddress'=@('Id','Keyword','AutoResolve')
    'Get-NetFirewallDynamicKeywordAddress'=@('Id')
    'Remove-NetFirewallDynamicKeywordAddress'=@('Id')
  }
  foreach($name in $dynamicCommandParameters.Keys){
    try{
      $dynamicCommand=Get-Command $name -ErrorAction Stop
      foreach($parameter in $dynamicCommandParameters[$name]){
        if(-not $dynamicCommand.Parameters.ContainsKey($parameter)){$reasons.Add($name+' 不支持参数 '+$parameter)}
      }
    }catch{$reasons.Add('缺少命令 '+$name)}
  }
  try{
    $cmd=Get-Command New-NetFirewallRule -ErrorAction Stop
    foreach($param in @('RemoteDynamicKeywordAddresses','Program','RemoteAddress','Protocol','RemotePort')){
      if(-not $cmd.Parameters.ContainsKey($param)){$reasons.Add('New-NetFirewallRule 不支持参数 '+$param)}
    }
  }catch{$reasons.Add('无法检查 New-NetFirewallRule 参数集')}
  try{
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $build=[int]$os.BuildNumber
    $productType=[int]$os.ProductType
    if($productType -eq 1){
      if($build -lt 19042){$reasons.Add('Windows 客户端 build '+$build+' 低于 Windows 10 20H2 FQDN 基线 19042')}
      elseif($build -le 19044){
        $cv=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $ubr=[int]$cv.UBR
        if($ubr -lt 1706){$reasons.Add('Windows 客户端 UBR '+$ubr+' 低于 KB5013942 支持基线 1706')}
      }
    }elseif($build -lt 14393){$reasons.Add('Windows Server build '+$build+' 低于 Server 2016 基线 14393')}
  }catch{$reasons.Add('无法确认 Windows build：'+$_.Exception.Message)}
  try{
    if(-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)){throw 'Get-MpComputerStatus 不可用'}
    $mp=Get-MpComputerStatus -ErrorAction Stop
    if(-not [bool]$mp.AMServiceEnabled -or -not [bool]$mp.AntivirusEnabled){$reasons.Add('Microsoft Defender Antivirus 未启用')}
    if([string]$mp.AMRunningMode -ne 'Normal'){$reasons.Add('Microsoft Defender Antivirus 不处于 Normal 活跃模式（当前：'+[string]$mp.AMRunningMode+'）')}
    if(-not [bool]$mp.RealTimeProtectionEnabled){$reasons.Add('Microsoft Defender Antivirus 实时保护未启用')}
    $platformText=[string]$mp.AMProductVersion
    if([string]::IsNullOrWhiteSpace($platformText)){throw 'AMProductVersion 为空'}
    $platform=[version]$platformText
    if($platform -lt [version]'4.18.2209.7'){$reasons.Add('Defender Antivirus 平台版本 '+$platform+' 低于 4.18.2209.7')}
  }catch{$reasons.Add('无法确认 Defender Antivirus 平台状态：'+$_.Exception.Message)}
  try{
    if(-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)){throw 'Get-MpPreference 不可用'}
    $pref=Get-MpPreference -ErrorAction Stop
    $np=[int]$pref.EnableNetworkProtection
    if($np -notin @(1,2)){$reasons.Add('Network Protection 未设置为 Block 或 Audit（当前值='+$np+'）')}
    if($productType -ne 1){
      if(-not [bool]$pref.AllowNetworkProtectionOnWinServer){$reasons.Add('Windows Server 未启用 AllowNetworkProtectionOnWinServer')}
      if($build -eq 14393 -and -not [bool]$pref.AllowNetworkProtectionDownLevel){$reasons.Add('Windows Server 2016 未启用 AllowNetworkProtectionDownLevel')}
    }
  }catch{$reasons.Add('无法确认 Network Protection 状态：'+$_.Exception.Message)}
  # Registry policies can identify known browser DoH settings, but absence of a
  # policy cannot prove that a user-level or app-managed resolver has DoH disabled.
  $policyRoots=@(
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
    'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
    'HKLM:\SOFTWARE\Policies\Google\Chrome',
    'HKCU:\SOFTWARE\Policies\Google\Chrome',
    'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS',
    'HKCU:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'
  )
  if($cfg.UserSID -match '^S-1-[0-9-]+$'){
    $callerHive='Registry::HKEY_USERS\'+[string]$cfg.UserSID+'\Software\Policies'
    $policyRoots+=@(
      ($callerHive+'\Microsoft\Edge'),
      ($callerHive+'\Google\Chrome'),
      ($callerHive+'\Mozilla\Firefox\DNSOverHTTPS')
    )
  }
  foreach($root in $policyRoots){
    if(-not (Test-Path -LiteralPath $root)){continue}
    try{
      if($root -match '\\DNSOverHTTPS$'){
        $enabled=Get-ItemProperty -LiteralPath $root -Name Enabled -ErrorAction SilentlyContinue
        if($null -ne $enabled -and [bool]$enabled.Enabled){$reasons.Add('检测到 Firefox DoH 策略启用：'+$root)}
        elseif($null -eq $enabled){$dohWarnings.Add('Firefox DoH 策略未明确关闭：'+$root)}
      }else{
        $mode=[string](Get-ItemProperty -LiteralPath $root -Name DnsOverHttpsMode -ErrorAction SilentlyContinue).DnsOverHttpsMode
        if($mode -and $mode -ine 'off'){$reasons.Add('检测到浏览器 DoH 策略启用（'+$root+'\\DnsOverHttpsMode='+$mode+'）')}
        elseif(-not $mode){$dohWarnings.Add('浏览器 DoH 未由策略明确关闭：'+$root)}
      }
    }catch{$dohWarnings.Add('无法读取浏览器 DoH 策略：'+$root)}
  }
  # Windows DNS Client may upgrade resolver traffic to DoH independently of browsers.
  try{
    if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){
      $systemDoh=@(Get-DnsClientDohServerAddress -ErrorAction Stop|Where-Object{[bool]$_.AutoUpgrade})
      if($systemDoh.Count -gt 0){$reasons.Add('检测到 Windows DNS Client DoH AutoUpgrade 已启用：'+(@($systemDoh|ForEach-Object{[string]$_.ServerAddress}) -join ', '))}
    }else{$dohWarnings.Add('Get-DnsClientDohServerAddress 不可用，无法读取 Windows DNS Client DoH 配置')}
  }catch{$dohWarnings.Add('无法读取 Windows DNS Client DoH 配置：'+$_.Exception.Message)}
  $dohWarnings.Add('浏览器/应用可能使用用户级或自带 DoH；GuardLauncher 无法完整枚举所有应用的 DNS 设置，必须人工确认 DoH 已关闭')
  $dohStatus='Unverified'
  if(@($reasons|Where-Object{$_ -match 'DoH'}).Count -gt 0){$dohStatus='Enabled'}
  return [pscustomobject]@{Available=($reasons.Count -eq 0);Reasons=@($reasons);DohStatus=$dohStatus;DohWarnings=@($dohWarnings)}
}
function Secure-StateDir($p){
  Ensure-Dir $p
  $sec=New-Object System.Security.AccessControl.DirectorySecurity
  $sec.SetAccessRuleProtection($true,$false)
  $admins=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $sec.SetOwner($admins)
  $r1=New-Object System.Security.AccessControl.FileSystemAccessRule($admins,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $r2=New-Object System.Security.AccessControl.FileSystemAccessRule($system,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $sec.AddAccessRule($r1); $sec.AddAccessRule($r2)
  if($cfg.UserSID){
    $user=New-Object System.Security.Principal.SecurityIdentifier($cfg.UserSID)
    $r3=New-Object System.Security.AccessControl.FileSystemAccessRule($user,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
    $sec.AddAccessRule($r3)
  }
  [IO.Directory]::SetAccessControl($p,$sec)
}
function Save-ProfileState($p){
  $s=@{}
  Get-NetFirewallProfile | ForEach-Object { $s[$_.Name]=[pscustomobject]@{DefaultOutboundAction=$_.DefaultOutboundAction.ToString();Enabled=$_.Enabled.ToString()} }
  Write-AtomicJson $p $s 4
}
function Restore-ProfileState($p,[bool]$Required=$false){
  if(!(Test-Path -LiteralPath $p)){
    if($Required){throw ('防火墙配置基线丢失，但存在修改/恢复标记；拒绝猜测原始 Profile：'+$p)}
    Write-GuardLog('[restore-step] SKIP firewall profiles: no profile baseline and no apply marker')
    return
  }
  $s=Get-Content -Raw -LiteralPath $p -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
  foreach($name in @('Domain','Private','Public')){
    $entry=$s.$name
    if($null -eq $entry){continue}
    # Backward compatibility: v16/v17 profiles.json stored only the outbound action string.
    if($entry -is [string]){$expectedAction=[string]$entry;$expectedEnabled=$null}
    else{$expectedAction=[string]$entry.DefaultOutboundAction;$expectedEnabled=[string]$entry.Enabled}
    if(-not $expectedAction){continue}
    $current=Get-NetFirewallProfile -Profile $name -ErrorAction Stop
    $stillGuardState=($current.DefaultOutboundAction.ToString() -eq 'Block')
    if($null -ne $expectedEnabled){$stillGuardState=$stillGuardState -and ($current.Enabled.ToString() -eq 'True')}
    if(-not $stillGuardState){
      Write-GuardLog('[firewall] profile changed outside Guard expected state; preserving current user/GPO state: '+$name+' action='+$current.DefaultOutboundAction+' enabled='+$current.Enabled)
      continue
    }
    if($null -ne $expectedEnabled){
      # NetSecurity exposes Enabled as the generated GpoBoolean enum, not
      # System.Boolean. Passing [bool] works on some PowerShell/module builds
      # but fails on Windows PowerShell 5.1 (observed on Windows 11 26100).
      $enabledParameter=(Get-Command Set-NetFirewallProfile -ErrorAction Stop).Parameters['Enabled']
      if($null -eq $enabledParameter){throw 'Set-NetFirewallProfile has no Enabled parameter; preserve profile journal'}
      $enabledType=$enabledParameter.ParameterType
      if($enabledType.IsEnum){
        try{$enabledValue=[Enum]::Parse($enabledType,[string]$expectedEnabled,$true)}catch{throw ('Firewall profile Enabled baseline is not a valid '+$enabledType.FullName+' value: '+$expectedEnabled)}
      }else{
        # Some NetSecurity versions expose a converter-backed parameter type;
        # pass the validated textual literal rather than a System.Boolean.
        if([string]$expectedEnabled -notin @('True','False','NotConfigured')){throw ('Unsupported firewall Enabled baseline: '+$expectedEnabled)}
        $enabledValue=[string]$expectedEnabled
      }
      Set-NetFirewallProfile -Profile $name -DefaultOutboundAction $expectedAction -Enabled $enabledValue -ErrorAction Stop
    }else{
      Set-NetFirewallProfile -Profile $name -DefaultOutboundAction $expectedAction -ErrorAction Stop
    }
    $after=Get-NetFirewallProfile -Profile $name -ErrorAction Stop
    if($after.DefaultOutboundAction.ToString() -ne $expectedAction){throw ('防火墙出站策略未恢复：'+$name+' expected='+$expectedAction+' actual='+$after.DefaultOutboundAction)}
    if($null -ne $expectedEnabled -and $after.Enabled.ToString() -ne $expectedEnabled){throw ('Windows Firewall 启用状态未恢复：'+$name+' expected='+$expectedEnabled+' actual='+$after.Enabled)}
  }
}
function Read-QQIniText([string]$Path){
  $bytes=[IO.File]::ReadAllBytes($Path)
  $offset=0;$decoder=New-Object Text.UTF8Encoding($false,$true);$kind='UTF-8'
  if($bytes.Length -ge 4 -and (($bytes[0] -eq 0xff -and $bytes[1] -eq 0xfe -and $bytes[2] -eq 0 -and $bytes[3] -eq 0) -or ($bytes[0] -eq 0 -and $bytes[1] -eq 0 -and $bytes[2] -eq 0xfe -and $bytes[3] -eq 0xff))){throw '不支持 UTF-32 INI；请显式另存为 UTF-8'}
  if($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf){$offset=3}
  elseif($bytes.Length -ge 2 -and $bytes[0] -eq 0xff -and $bytes[1] -eq 0xfe){$offset=2;$decoder=New-Object Text.UnicodeEncoding($false,$true,$true);$kind='UTF-16LE BOM'}
  elseif($bytes.Length -ge 2 -and $bytes[0] -eq 0xfe -and $bytes[1] -eq 0xff){$offset=2;$decoder=New-Object Text.UnicodeEncoding($true,$true,$true);$kind='UTF-16BE BOM'}
  try{$text=$decoder.GetString($bytes,$offset,($bytes.Length-$offset))}
  catch{
    if($offset -ne 0){throw}
    $codepage=[Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage
    if($codepage -ne 936){throw ('INI 无 BOM 且不是 UTF-8；当前 ANSI 代码页不是 QQ 常用的 936，拒绝猜测：'+$Path+'；请另存为 UTF-8')}
    $decoder=[Text.Encoding]::GetEncoding(936,[Text.EncoderFallback]::ExceptionFallback,[Text.DecoderFallback]::ExceptionFallback)
    $text=$decoder.GetString($bytes);$kind='Windows ANSI CP936'
  }
  if($text.IndexOf([char]0) -ge 0){throw ('INI 含 NUL，编码不明确：'+$Path)}
  Write-GuardLog('[qq-ini] encoding='+$kind+' source='+$Path)
  return $text
}
# Descriptive resolution only: Target is link metadata, not a verified final path.
# Never call Get-Acl/Set-Acl on the link or its target from this diagnostic.
function Write-ReparseDiagnostic([string]$Path,[string]$Root){
  $target='';$resolved='Unknown';$allowed='Unknown';$exists='Unknown'
  try{
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $targets=@($item.Target|Where-Object{$_})
    if($targets.Count -eq 1){
      $target=[string]$targets[0]
      $candidate=$target
      if($candidate.StartsWith('\??\')){$candidate=$candidate.Substring(4)}
      if(-not [IO.Path]::IsPathRooted($candidate)){$candidate=Join-Path (Split-Path -Parent $Path) $candidate}
      $candidate=[IO.Path]::GetFullPath($candidate)
      $exists=[string](Test-Path -LiteralPath $candidate -ErrorAction Stop)
      $allowed='False'
      foreach($configured in @($cfg.ProtectedPaths)){
        $boundary=[IO.Path]::GetFullPath((Expand-CallerPath ([string]$configured))).TrimEnd([char]92)+[char]92
        if(($candidate+[char]92).StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)){$allowed='True';break}
      }
      $resolved=$candidate+' (metadata only; final target not verified)'
    }else{$target=($targets -join '; ')}
  }catch{$resolved='Unknown: '+$_.Exception.Message}
  Write-GuardLog('[acl-reparse] link='+$Path+' root='+$Root+' target='+$target+' resolved='+$resolved+' within_configured_range='+$allowed+' target_exists='+$exists+' action=REFUSE; final path/file identity not verified; no target ACL modified. 请检查链接布局；只有将实际数据目录写入 ProtectedPaths.txt 并消除原树的链接边界后，才可重新验证完整覆盖。')
}
function Find-QQSavePaths{
  $found=New-Object System.Collections.Generic.List[string]
  $invalid=New-Object System.Collections.Generic.List[string]
  $scanErrors=New-Object System.Collections.Generic.List[string]
  # Use the environment of the user who launched GuardLauncher, not the
  # elevated helper's profile (which may belong to alternate UAC credentials).
  $callerPublic=[string]$cfg.CallerPublic
  $callerAppData=[string]$cfg.CallerAppData
  $callerProfile=[string]$cfg.CallerUserProfile
  $roots=@(
    (Join-Path $callerPublic 'Documents\Tencent'),
    (Join-Path $callerAppData 'Tencent'),
    (Join-Path $callerProfile 'Documents\Tencent Files'),
    (Join-Path $callerProfile 'Documents\Tencent')
  ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }
  $candidates=New-Object System.Collections.Generic.List[string]
  foreach($r in $roots){
    try{
      $rootItem=Get-Item -LiteralPath $r -Force -ErrorAction Stop
      if(($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Write-ReparseDiagnostic $r $r;throw ('QQ 扫描根目录为链接，未跟随：'+$r)}
      $stack=New-Object Collections.Generic.Stack[string];$stack.Push($r)
      while($stack.Count -gt 0){
        $current=$stack.Pop()
        foreach($entry in [IO.Directory]::GetFileSystemEntries($current)){
          $attributes=[IO.File]::GetAttributes($entry)
          if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Write-ReparseDiagnostic $entry $r;$scanErrors.Add('QQ 扫描未跟随 reparse point：'+$entry);continue}
          if(($attributes -band [IO.FileAttributes]::Directory) -ne 0){$stack.Push($entry)}
          elseif([IO.Path]::GetFileName($entry) -ieq 'UserDataInfo.ini'){$candidates.Add($entry)}
        }
      }
    }catch{$scanErrors.Add($r+' :: '+$_.Exception.Message)}
  }
  foreach($f in ($candidates | Select-Object -Unique)){
    try{
      $text=Read-QQIniText $f
      foreach($m in [regex]::Matches($text,'(?im)^\s*UserDataSavePath\s*=\s*(.+?)\s*$')){
        $v=$m.Groups[1].Value.Trim().Trim('"').Trim()
        if(-not $v){continue}
        $v=Expand-CallerPath $v
        if($v -match '%[^%]+%'){$invalid.Add($f+' -> '+$v);continue}
        $full=[IO.Path]::GetFullPath($v)
        if(Test-Path -LiteralPath $full -PathType Container){$found.Add($full)}
        else{Write-GuardLog('[qq] UserDataSavePath 当前不存在，暂不添加 ACL：'+$full+' (source '+$f+')')}
      }
    }catch{ $scanErrors.Add($f+' :: '+$_.Exception.Message) }
  }
  if($scanErrors.Count -gt 0){throw ('QQ 自定义目录扫描不完整，拒绝宣称保护完整：'+($scanErrors -join '; '))}
  if($invalid.Count -gt 0){throw ('UserDataInfo.ini 包含无法解析的环境变量，无法确认全部 QQ 数据目录：'+($invalid -join '; '))}
  return @($found | Select-Object -Unique)
}

function Test-GuardDeny($path,$sid,[string]$InheritanceFlags='ContainerInherit,ObjectInherit'){
  if([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($sid)){return $false}
  try{
    $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
    $expected=[System.Security.AccessControl.InheritanceFlags]([Enum]::Parse([System.Security.AccessControl.InheritanceFlags],$InheritanceFlags,$true))
    foreach($ace in $acl.Access){
      if($ace.IsInherited -or $ace.AccessControlType -ne 'Deny'){continue}
      $aceSid='';try{$aceSid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$aceSid=[string]$ace.IdentityReference.Value}
      $rights=([Security.AccessControl.FileSystemRights]$ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl)
      if($aceSid -eq $sid -and $rights -eq [Security.AccessControl.FileSystemRights]::FullControl -and [System.Security.AccessControl.InheritanceFlags]$ace.InheritanceFlags -eq $expected -and $ace.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None){return $true}
    }
  }catch{}
  return $false
}

function Add-GuardDeny($path,$sid,[string]$InheritanceFlags='ContainerInherit,ObjectInherit'){
  if(Test-GuardDeny $path $sid $InheritanceFlags){return $true}
  try{
    $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
    $flags=[System.Security.AccessControl.InheritanceFlags]([Enum]::Parse([System.Security.AccessControl.InheritanceFlags],$InheritanceFlags,$true))
    $rule=New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($sid)),[System.Security.AccessControl.FileSystemRights]::FullControl,$flags,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Deny)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
    return (Test-GuardDeny $path $sid $InheritanceFlags)
  }catch{Write-GuardLog('[acl] Add Deny failed: '+$path+' flags='+$InheritanceFlags+' :: '+$_.Exception.Message);return $false}
}
function Remove-GuardDeny($path,$sid,[string]$InheritanceFlags='ContainerInherit,ObjectInherit'){
  if(-not (Test-Path -LiteralPath $path)){Write-GuardLog('[restore-step] ACL path already absent; no ACE remains to remove: '+$path);return $true}
  try{
    $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
    if(-not (Test-GuardDeny $path $sid $InheritanceFlags)){
      # An absent exact ACE is already restored. A different explicit Deny for the same
      # SID may be a user change; do not delete it by guessing.
      foreach($ace in $acl.Access){
        if($ace.IsInherited -or $ace.AccessControlType -ne 'Deny'){continue}
        $aceSid='';try{$aceSid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$aceSid=[string]$ace.IdentityReference.Value}
        $rights=([Security.AccessControl.FileSystemRights]$ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl)
        if($aceSid -eq $sid -and $rights -eq [Security.AccessControl.FileSystemRights]::FullControl){throw '发现同一 SID 的显式 Deny ACE 与 Guard journal 标记不一致；为避免删除外部 ACE，停止自动移除'}
      }
      return $true
    }
    $flags=[System.Security.AccessControl.InheritanceFlags]([Enum]::Parse([System.Security.AccessControl.InheritanceFlags],$InheritanceFlags,$true))
    $exact=@($acl.Access|Where-Object{
      if($_.IsInherited -or $_.AccessControlType -ne 'Deny'){return $false}
      $aceSid='';try{$aceSid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$aceSid=[string]$_.IdentityReference.Value}
      $rights=([Security.AccessControl.FileSystemRights]$_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl)
      return ($aceSid -eq $sid -and $rights -eq [Security.AccessControl.FileSystemRights]::FullControl -and [System.Security.AccessControl.InheritanceFlags]$_.InheritanceFlags -eq $flags -and $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None)
    })
    if($exact.Count -gt 1){throw '发现多个完全相同的显式 Deny ACE；无法区分 Guard 与外部新增项，为避免误删而保留 ACL'}
    if($exact.Count -eq 0){return $true}
    $rule=New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($sid)),[System.Security.AccessControl.FileSystemRights]::FullControl,$flags,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Deny)
    $acl.RemoveAccessRuleSpecific($rule)|Out-Null
    Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
    if(Test-GuardDeny $path $sid $InheritanceFlags){throw 'Guard Deny ACE remains after removal'}
    return $true
  }catch{Write-GuardLog('[acl] 无法移除 Guard Deny：'+$path+' flags='+$InheritanceFlags+' :: '+$_.Exception.Message);return $false}
}
function Protect-PathIfNeeded([string]$Path,[string]$SID,[bool]$IsDirectory){
  if(Test-GuardProtectionEffective $Path $SID){return $false}
  $flags='None';if($IsDirectory){$flags='ContainerInherit,ObjectInherit'}
  $record=[pscustomobject]@{JournalVersion=2;Path=$Path;UserSID=$SID;Added=$true;Preexisting=$false;IsDirectory=$IsDirectory;InheritanceFlags=$flags;PropagationFlags='None';CreatedUtc=[DateTime]::UtcNow.ToString('o')}
  # Commit the write-ahead record atomically before touching the DACL.
  Write-AclJournalRecord $cfg.StateDir $record|Out-Null
  if(-not (Add-GuardDeny $Path $SID $flags)){throw ('写入或验证 Deny ACE 失败：'+$Path)}
  if(-not (Test-GuardProtectionEffective $Path $SID)){throw ('ACL 写入后有效 Deny 检查失败：'+$Path)}
  return $true
}
function Protect-One($path,$index){
  if(!(Test-Path -LiteralPath $path -PathType Container)){return $false}
  try{
    $full=[IO.Path]::GetFullPath($path)
    $rootItem=Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if(($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Write-ReparseDiagnostic $full $full;throw ('保护根目录是 reparse point，最终目标身份未确认；拒绝修改链接目标：'+$full)}
    $sid=$cfg.UserSID
    $inspected=0;$covered=0;$added=0;$skippedReparse=0
    if(Protect-PathIfNeeded $full $sid $true){$added++}else{$covered++}
    $stack=New-Object System.Collections.Generic.Stack[string]
    $stack.Push($full)
    while($stack.Count -gt 0){
      $current=$stack.Pop()
      $items=[IO.Directory]::GetFileSystemEntries($current)
      foreach($itemPath in $items){
        $inspected++
        try{$attributes=[IO.File]::GetAttributes($itemPath)}catch{throw ('无法读取子对象属性，不能确认 ACL 覆盖：'+$itemPath+' :: '+$_.Exception.Message)}
        if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$skippedReparse++;Write-ReparseDiagnostic $itemPath $full;continue}
        $isDirectory=(($attributes -band [IO.FileAttributes]::Directory) -ne 0)
        if(Protect-PathIfNeeded $itemPath $sid $isDirectory){$added++}else{$covered++}
        if($isDirectory){$stack.Push($itemPath)}
        if(($inspected % 500) -eq 0){Write-GuardLog('[acl-tree] progress root='+$full+' inspected='+$inspected+' added='+$added+' skipped_reparse='+$skippedReparse)}
      }
    }
    $coverageComplete=($skippedReparse -eq 0)
    $summaryState='COVERAGE_VERIFIED';if(-not $coverageComplete){$summaryState='COVERAGE_INCOMPLETE'}
    Write-GuardLog('[acl-tree] '+$summaryState+' root='+$full+' inspected='+$inspected+' covered='+$covered+' explicit_added='+$added+' skipped_reparse='+$skippedReparse)
    if($skippedReparse -gt 0){Write-GuardLog('[acl-tree] WARNING root='+$full+' contains '+$skippedReparse+' reparse point(s); they were intentionally not followed. Refusing to claim full coverage; inspect each target separately.')}
    $pathList=Join-Path $cfg.StateDir 'protected_paths.txt'
    $knownPaths=@()
    if(Test-Path -LiteralPath $pathList){$knownPaths=@([IO.File]::ReadAllLines($pathList,[Text.Encoding]::UTF8)|Where-Object{$_})}
    if(@($knownPaths|Where-Object{[string]::Equals([string]$_,$full,[System.StringComparison]::OrdinalIgnoreCase)}).Count -eq 0){$knownPaths+=,$full;Write-AtomicText $pathList (($knownPaths -join [Environment]::NewLine)+[Environment]::NewLine)}
    return $coverageComplete
  }catch{Write-GuardLog('[acl] 保护目录树失败：'+$path+' :: '+$_.Exception.ToString()+' | ScriptStackTrace='+$_.ScriptStackTrace);return $false}
}
function Protect-Files{
  Ensure-AclJournalManifest $cfg.StateDir|Out-Null
  $paths=New-Object System.Collections.Generic.List[string]
  foreach($p in $cfg.ProtectedPaths){if($p){$paths.Add((Expand-CallerPath $p))}}
  foreach($p in (Find-QQSavePaths)){$paths.Add($p)}
  $seen=@{};$i=0;$failed=New-Object System.Collections.Generic.List[string];$existing=0
  foreach($p in ($paths|Select-Object -Unique)){
    if([string]::IsNullOrWhiteSpace($p)){continue}
    if($p -match '%[^%]+%'){$failed.Add('未解析的环境变量: '+$p);continue}
    $full=$p;try{$full=[IO.Path]::GetFullPath($p)}catch{$failed.Add($p);continue}
    $key=$full.ToLowerInvariant();if($seen.ContainsKey($key)){continue};$seen[$key]=1
    if(Test-Path -LiteralPath $full){$existing++;if(-not (Protect-One $full $i)){$failed.Add($full)}else{$i++}}
  }
  if($failed.Count -gt 0){throw ('以下 QQ/Tencent 目录树未能完整保护：'+($failed -join '; '))}
  Write-GuardLog('[acl] QQ/Tencent tree protection verified: roots='+$i+' existing='+$existing)
}
function Restore-Files{
  $legacy=Join-Path $cfg.StateDir 'protected_paths.txt'
  $records=@(Get-AclJournalRecords $cfg.StateDir -Refresh)
  $hasManifest=Test-AclJournalManifest $cfg.StateDir
  if($records.Count -eq 0 -and (Test-Path -LiteralPath $legacy) -and -not $hasManifest){
    Write-GuardLog('[acl] legacy path-only records have no ACE provenance; automatic removal skipped')
    throw '旧会话 ACL 记录缺少来源信息；为避免误删用户原有 ACL，保留恢复记录并停止自动清理'
  }
  if($records.Count -eq 0 -and $hasManifest){Write-GuardLog('[acl] current schema manifest confirms an empty write-ahead journal; no Guard-added ACEs require removal')}
  $results=New-Object System.Collections.Generic.List[object]
  $processed=0
  foreach($r in $records){
    if(-not [bool]$r.Added){continue}
    $record=$r;$flags=Get-GuardInheritanceFlags $record
    $results.Add((Invoke-LoggedRecoveryStep ('ACL remove '+[string]$record.Path) {if(-not (Remove-GuardDeny ([string]$record.Path) ([string]$record.UserSID) $flags)){throw ('无法验证 ACL 已恢复：'+[string]$record.Path)}} -QuietSuccess))
    $processed++
    if(($processed % 500) -eq 0){Write-GuardLog('[acl-restore] progress processed='+$processed+' total_journal_records='+$records.Count)}
  }
  if(-not (Write-SessionRecoverySummary 'Tencent ACL restoration' @($results.ToArray()))){throw '一个或多个 Tencent ACL 恢复步骤失败；保留恢复记录供重试'}
}
function Reapply-GuardACLs{
  Assert-AclJournalIntegrityOnce $cfg.StateDir|Out-Null
  $records=@(Get-AclJournalRecords $cfg.StateDir)
  [array]::Reverse($records)
  foreach($r in $records){
    if(-not [bool]$r.Added){continue}
    $path=[string]$r.Path;$sid=[string]$r.UserSID;$flags=Get-GuardInheritanceFlags $r
    if(-not (Test-Path -LiteralPath $path)){Write-GuardLog('[acl] journal target no longer exists; no ACE can be enforced: '+$path);continue}
    if(-not (Test-GuardProtectionEffective $path $sid)){
      if(-not (Add-GuardDeny $path $sid $flags)){throw ('无法重新施加 QQ/Tencent Deny ACL：'+$path)}
      if(-not (Test-GuardProtectionEffective $path $sid)){throw ('重新施加 ACL 后验证失败：'+$path)}
      Write-GuardLog('[acl] repaired missing QQ/Tencent deny: '+$path+' flags='+$flags)
    }
  }
}
function Normalize-ProgramPath($p){
  if([string]::IsNullOrWhiteSpace($p)){ return '' }
  try{ return [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($p)).ToLowerInvariant() }catch{ return $p.ToLowerInvariant() }
}
function Get-FirewallRuleRecoveryFingerprint($rule){
  # Enabled is omitted because Guard itself changes it. Compare the rule's
  # identity and filtering conditions before restoring the user's Allow rule.
  $app=$rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
  $addr=$rule | Get-NetFirewallAddressFilter -ErrorAction Stop
  $port=$rule | Get-NetFirewallPortFilter -ErrorAction Stop
  $service=$rule | Get-NetFirewallServiceFilter -ErrorAction Stop
  $iface=$rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
  $security=$rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
  $dynamic=@()
  foreach($source in @($rule,$addr)){
    $property=$source.PSObject.Properties['RemoteDynamicKeywordAddresses']
    if($null -ne $property -and $null -ne $property.Value){$dynamic+=@($property.Value | ForEach-Object{[string]$_})}
  }
  $value=[ordered]@{
    Name=[string]$rule.Name; DisplayName=[string]$rule.DisplayName; Group=[string]$rule.Group
    Direction=[string]$rule.Direction; Action=[string]$rule.Action; Profile=[string]$rule.Profile
    EdgeTraversalPolicy=[string]$rule.EdgeTraversalPolicy; OverrideBlockRules=[string]$rule.OverrideBlockRules
    PolicyStoreSourceType=[string]$rule.PolicyStoreSourceType; PolicyStoreSource=[string]$rule.PolicyStoreSource
    Program=[string]$app.Program; Package=[string]$app.Package
    LocalAddress=@($addr.LocalAddress|ForEach-Object{[string]$_}|Sort-Object)
    RemoteAddress=@($addr.RemoteAddress|ForEach-Object{[string]$_}|Sort-Object)
    RemoteDynamicKeywordAddresses=@($dynamic|Sort-Object -Unique)
    Protocol=[string]$port.Protocol
    LocalPort=@($port.LocalPort|ForEach-Object{[string]$_}|Sort-Object)
    RemotePort=@($port.RemotePort|ForEach-Object{[string]$_}|Sort-Object)
    Service=[string]$service.Service
    InterfaceAlias=@($iface.InterfaceAlias|ForEach-Object{[string]$_}|Sort-Object)
    InterfaceType=@($iface.InterfaceType|ForEach-Object{[string]$_}|Sort-Object)
    Authentication=[string]$security.Authentication; Encryption=[string]$security.Encryption
    LocalUser=[string]$security.LocalUser; RemoteUser=[string]$security.RemoteUser
    RemoteMachine=[string]$security.RemoteMachine; SecureFlags=[string]$security.SecureFlags
  }
  return ($value|ConvertTo-Json -Compress -Depth 6)
}
function Repair-DisabledAllowsFingerprintEscapes([string]$json){
  # v17.7-era journals can contain a Fingerprint JSON string with one or more
  # unescaped quotes. Repair only that final string property; never rewrite
  # names, Group values, booleans, or any other journal fields.
  $text=$json
  $repairCount=0
  $searchFrom=0
  while($true){
    $propertyAt=$text.IndexOf('"Fingerprint"',$searchFrom,[StringComparison]::OrdinalIgnoreCase)
    if($propertyAt -lt 0){break}
    $colonAt=$text.IndexOf(':',$propertyAt+13)
    if($colonAt -lt 0){throw 'disabled_allows.json has a malformed Fingerprint property'}
    $openAt=$text.IndexOf('"',$colonAt+1)
    if($openAt -lt 0){throw 'disabled_allows.json has no opening quote for Fingerprint'}
    $startAt=$openAt+1
    $closeAt=-1
    for($i=$startAt;$i -lt $text.Length;$i++){
      if($text[$i] -ne '"'){continue}
      $slashes=0
      for($k=$i-1;$k -ge $startAt -and $text[$k] -eq '\';$k--){$slashes++}
      if(($slashes % 2) -ne 0){continue}
      $j=$i+1
      while($j -lt $text.Length -and [char]::IsWhiteSpace($text[$j])){$j++}
      if($j -ge $text.Length -or $text[$j] -ne '}'){continue}
      $j++
      while($j -lt $text.Length -and [char]::IsWhiteSpace($text[$j])){$j++}
      if($j -eq $text.Length -or $text[$j] -eq ',' -or $text[$j] -eq ']'){$closeAt=$i;break}
    }
    if($closeAt -lt 0){throw 'disabled_allows.json Fingerprint is not the final property or has no safe string terminator; preserve journal'}
    $segment=$text.Substring($startAt,$closeAt-$startAt)
    $builder=New-Object System.Text.StringBuilder
    for($i=0;$i -lt $segment.Length;$i++){
      $ch=$segment[$i]
      if($ch -eq '"'){
        $slashes=0
        for($k=$i-1;$k -ge 0 -and $segment[$k] -eq '\';$k--){$slashes++}
        if(($slashes % 2) -eq 0){[void]$builder.Append('\');$repairCount++}
      }
      [void]$builder.Append($ch)
    }
    $escaped=$builder.ToString()
    if($escaped -cne $segment){$text=$text.Substring(0,$startAt)+$escaped+$text.Substring($closeAt)}
    $searchFrom=$startAt+$escaped.Length+1
  }
  return [pscustomobject]@{Json=$text;RepairCount=$repairCount}
}
function Read-DisabledAllowsJournal([string]$path){
  # Write-AtomicText writes UTF-8 without a BOM. Get-Content in Windows
  # PowerShell 5.1 defaults to the active ANSI code page, corrupting non-ASCII
  # rule display names and making fingerprint comparisons unreliable.
  $raw=[IO.File]::ReadAllText($path,[Text.Encoding]::UTF8)
  try{
    $parsed=ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    return ,@($parsed)
  }catch{
    $originalError=$_.Exception.Message
    $repair=Repair-DisabledAllowsFingerprintEscapes $raw
    if($repair.RepairCount -le 0){throw ('disabled_allows.json JSON parse failed and no safe Fingerprint-only repair applied: '+$originalError)}
    try{$parsed=ConvertFrom-Json -InputObject $repair.Json -ErrorAction Stop}
    catch{throw ('disabled_allows.json remains invalid after Fingerprint-only escape repair: '+$_.Exception.Message+'; original='+$originalError)}
    Write-GuardLog('[firewall-recovery] repaired legacy disabled_allows.json Fingerprint escaping only; insertedEscapes='+$repair.RepairCount+'; UTF-8 decoding used')
    return ,@($parsed)
  }
}
function Restore-DisabledAllowsFrom([string]$path){
  if(!(Test-Path -LiteralPath $path)){
    $marker=Join-Path (Split-Path -Parent $path) 'disabled_allows_apply_started'
    if(Test-Path -LiteralPath $marker){throw 'disabled_allows.json is missing although Guard marked user Allow changes; refuse to report false recovery success'}
    Write-GuardLog('[restore-step] SKIP disabled user Allows: no journal/apply marker')
    return
  }
  foreach($x in @(Read-DisabledAllowsJournal $path)){
    if(-not $x.Name){continue}
    if($x.PSObject.Properties['WasEnabled'] -and -not [bool]$x.WasEnabled){Write-GuardLog('[firewall] journal says original Allow rule was not enabled; do not enable: '+$x.Name);continue}
    $existing=@(Get-NetFirewallRule -Name ([string]$x.Name) -ErrorAction Stop)
    if($existing.Count -eq 0){Write-GuardLog('[firewall] 原 Allow 规则已被用户/系统删除，不重建：'+$x.Name);continue}
    if($existing.Count -ne 1){Write-GuardLog('[firewall] 原 Allow 规则名称不再唯一，跳过自动恢复：'+$x.Name);continue}
    $rule=$existing[0]
    if($rule.Enabled -eq 'True'){Write-GuardLog('[firewall] 原 Allow 规则已启用，无需恢复：'+$x.Name);continue}
    if([string]::IsNullOrWhiteSpace([string]$x.Fingerprint)){
      Write-GuardLog('[firewall] 旧恢复记录缺少规则指纹，为避免覆盖外部更改，不自动重新启用：'+$x.Name)
      continue
    }
    $currentFingerprint=Get-FirewallRuleRecoveryFingerprint $rule
    if($currentFingerprint -cne [string]$x.Fingerprint){
      Write-GuardLog('[firewall] 原 Allow 规则在保护期间被外部修改；保留当前禁用状态，不覆盖：'+$x.Name)
      continue
    }
    Enable-NetFirewallRule -Name ([string]$x.Name) -ErrorAction Stop|Out-Null
    if(@(Get-NetFirewallRule -Name ([string]$x.Name) -ErrorAction Stop|Where-Object{$_.Enabled -eq 'True'}).Count -eq 0){throw ('无法恢复原 Allow 规则：'+$x.Name)}
    Write-GuardLog('[firewall] 已恢复规则条件未变化的 Guard 临时禁用 Allow：'+$x.Name)
  }
}
function Save-DisabledAllows($items){
  $path=Join-Path $cfg.StateDir 'disabled_allows.json'
  $all=New-Object System.Collections.Generic.List[object]
  if(Test-Path -LiteralPath $path){
    foreach($x in @(Read-DisabledAllowsJournal $path)){ if($x.Name){$all.Add($x)} }
  }
  $seen=@{}; foreach($x in $all){$seen[[string]$x.Name]=1}
  foreach($x in @($items)){ if($x.Name -and -not $seen.ContainsKey([string]$x.Name)){ $all.Add($x); $seen[[string]$x.Name]=1 } }
  Write-AtomicJson $path @($all.ToArray()) 6
  $marker=Join-Path $cfg.StateDir 'disabled_allows_apply_started'
  if(-not (Test-Path -LiteralPath $marker)){Write-AtomicText $marker ([DateTime]::UtcNow.ToString('o'))}
}
function Restore-DisabledAllows{
  Restore-DisabledAllowsFrom (Join-Path $cfg.StateDir 'disabled_allows.json')
}
function Is-BroadAllow($rule){
  try{
    $app=$rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $program=[string]$app.Program
    $package=[string]$app.Package
    $programAny=[string]::IsNullOrWhiteSpace($program) -or $program -in @('Any','<All>')
    $packageAny=[string]::IsNullOrWhiteSpace($package) -or $package -in @('Any','<All>')
    # An unrestricted Program+Package Allow can grant every desktop app access
    # to its matching destination/port, even if RemoteAddress is not Any.
    return ($programAny -and $packageAny)
  }catch{ return $false }
}
function Save-DisabledAllow([object]$item){$p=Join-Path $cfg.StateDir 'disabled_allows.json';$all=New-Object System.Collections.Generic.List[object];if(Test-Path -LiteralPath $p){foreach($x in @(Read-DisabledAllowsJournal $p)){if($x.Name){$all.Add($x)}}};$seen=@{};foreach($x in $all){$seen[[string]$x.Name]=1};if($item.Name -and -not $seen.ContainsKey([string]$item.Name)){$all.Add($item)};Write-AtomicJson $p @($all.ToArray()) 6}
function Audit-AndDisableProgramAllows{
  $targets=@($cfg.LauncherPath)+@($cfg.JavaPaths) | Where-Object { $_ } | ForEach-Object { Normalize-ProgramPath $_ } | Select-Object -Unique
  $rules=@(Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction Stop)
  foreach($r in $rules){
    # Never audit or disable this session's exact allowlist rules.
    if([string]$r.Group -eq [string]$cfg.Group){ continue }
    if(Is-BroadAllow $r){
      $fingerprint=Get-FirewallRuleRecoveryFingerprint $r
      $item=[pscustomobject]@{ Name=$r.Name; DisplayName=$r.DisplayName; Group=$r.Group; WasEnabled=$true; Fingerprint=$fingerprint }
      Save-DisabledAllows @($item)
      try{ Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop | Out-Null }
      catch{ throw "Cannot disable broad outbound Allow rule '$($r.DisplayName)': $($_.Exception.Message)" }
      Write-GuardLog('[firewall] disabled unscoped outbound Allow during strict session: '+$r.DisplayName)
      continue
    }
    $app=$r | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $program=[string]$app.Program
    if([string]::IsNullOrWhiteSpace($program)){ continue }
    $np=Normalize-ProgramPath $program
    if($targets -contains $np){
      $fingerprint=Get-FirewallRuleRecoveryFingerprint $r
      $item=[pscustomobject]@{ Name=$r.Name; DisplayName=$r.DisplayName; Group=$r.Group; WasEnabled=$true; Fingerprint=$fingerprint }
      # Persist recovery information before changing the user's rule.
      Save-DisabledAllows @($item)
      try{ Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop | Out-Null }
      catch{ throw "Cannot disable/persist conflicting outbound Allow rule '$($r.DisplayName)': $($_.Exception.Message)" }
    }
  }
}
function Assert-NoUnmanagedActiveAllows{
  $targets=@($cfg.LauncherPath)+@($cfg.JavaPaths) | Where-Object { $_ } | ForEach-Object { Normalize-ProgramPath $_ } | Select-Object -Unique
  $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction Stop)
  foreach($r in $rules){
    if([string]$r.Group -eq [string]$cfg.Group){continue}
    if(Is-BroadAllow $r){throw ('ActiveStore contains an unmanaged broad outbound Allow rule: '+$r.DisplayName+'; strict mode cannot guarantee the requested allowlist')}
    $app=$r|Get-NetFirewallApplicationFilter -ErrorAction Stop
    $program=[string]$app.Program
    if([string]::IsNullOrWhiteSpace($program)){continue}
    if($targets -contains (Normalize-ProgramPath $program)){
      throw ('ActiveStore contains an unmanaged Allow rule for a protected launcher/Java executable: '+$r.DisplayName)
    }
  }
}
function Add-Firewall{
  $profilesFile=Join-Path $cfg.StateDir 'profiles.json'
  if(!(Test-Path -LiteralPath $profilesFile)){ Save-ProfileState $profilesFile }
  Write-AtomicText (Join-Path $cfg.StateDir 'firewall_profile_apply_started') ([DateTime]::UtcNow.ToString('o'))
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block -ErrorAction Stop
  Audit-AndDisableProgramAllows
  Assert-NoUnmanagedActiveAllows
  Remove-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -Context 'Apply pre-clean' | Out-Null

  $programs=New-Object System.Collections.Generic.List[string]
  if($cfg.LauncherPath){$programs.Add($cfg.LauncherPath)}
  foreach($p in $cfg.JavaPaths){if($p){$programs.Add($p)}}
  $programs=@($programs | Select-Object -Unique)

  $active=New-Object System.Collections.Generic.List[object]
  $dynamic=@{}
  $fqdnCapability=Get-FqdnCapability
  $dynamicCmd=$null
  if($fqdnCapability.Available){
    $dynamicCmd=Get-Command New-NetFirewallDynamicKeywordAddress -ErrorAction Stop
    if($fqdnCapability.DohStatus -eq 'Unverified'){
      Write-GuardLog('[compat] Defender/Network Protection/系统版本前置条件通过，但 DoH 状态未能完全核实；请人工确认实际使用的浏览器和应用已关闭 DoH。')
      foreach($warning in @($fqdnCapability.DohWarnings)){Write-GuardLog('[compat] DoH 检查提示：'+[string]$warning)}
    }
  }else{
    Write-GuardLog('[compat] FQDN 动态白名单不可用；仅使用已解析的静态 IP，未解析域名跳过，默认出站 BLOCK 保持。原因：'+(@($fqdnCapability.Reasons) -join '; '))
  }
  foreach($e in @($cfg.Endpoints)){
    $key=([string]$e.Host).ToLowerInvariant()+':'+([int]$e.Port)
    if(@($e.IPs).Count -gt 0){
      $active.Add([pscustomobject]@{Host=$e.Host;Port=$e.Port;Mode='IP';DynamicId='';IPs=@($e.IPs)})
      continue
    }
    if($dynamicCmd -and $e.Host -and ($e.Host -notmatch '^[0-9a-fA-F:.]+$')){
      $id='{'+([guid]::NewGuid().ToString())+'}'
      try{
        # Journal the ID before creating the persistent object. A crash between
        # these operations leaves a recoverable ID instead of an untracked object.
        Save-PendingDynamicId $id
        $dynamic[$key]=$id
        New-NetFirewallDynamicKeywordAddress -Id $id -Keyword $e.Host -AutoResolve $true -ErrorAction Stop | Out-Null
        $active.Add([pscustomobject]@{Host=$e.Host;Port=$e.Port;Mode='FQDN';DynamicId=$id;IPs=@()})
        Write-GuardLog(('[firewall] FQDN 动态白名单对象已建立：'+$e.Host+':'+$e.Port+'（Windows 仍需实际 DNS 查询才能填充地址）'))
      }catch{
        $createError=$_.Exception.Message
        $dynamic.Remove($key)
        Remove-PendingDynamicIds @($id)
        Write-GuardLog(('[compat] 无法建立 FQDN 动态白名单，跳过该域名且不扩大放行范围：'+$e.Host+':'+$e.Port+' :: '+$createError))
      }
    }else{
      Write-GuardLog(('[firewall] 跳过未解析的白名单目标：'+$e.Host+':'+$e.Port+'；当前继续保持默认 BLOCK'))
    }
  }

  # Required static IP rules are created independently from optional FQDN rules.
  foreach($prog in $programs){
    foreach($e in @($active | Where-Object {$_.Mode -eq 'IP'})){
      $ruleName="$($cfg.Group) ALLOW $([IO.Path]::GetFileName($prog)) $($e.Host):$($e.Port)"
      New-NetFirewallRule -DisplayName $ruleName -Group $cfg.Group -Direction Outbound -Action Allow -Program $prog -RemoteAddress $e.IPs -Protocol TCP -RemotePort $e.Port -Profile Any -ErrorAction Stop | Out-Null
    }
  }
  $fqdnRuleFailure=$false
  try{
    foreach($prog in $programs){
      foreach($e in @($active | Where-Object {$_.Mode -eq 'FQDN'})){
        $ruleName="$($cfg.Group) ALLOW $([IO.Path]::GetFileName($prog)) $($e.Host):$($e.Port)"
        $ruleId='HachimiGuard_FQDN_'+([guid]::NewGuid().ToString('N'))
        New-NetFirewallRule -Name $ruleId -DisplayName $ruleName -Group $cfg.Group -Direction Outbound -Action Allow -Program $prog -RemoteDynamicKeywordAddresses $e.DynamicId -Protocol TCP -RemotePort $e.Port -Profile Any -ErrorAction Stop | Out-Null
      }
    }
  }catch{
    $fqdnRuleFailure=$true
    Write-GuardLog('[compat] 动态 FQDN 防火墙规则创建失败；移除本轮 Guard 规则并重建静态 IP 放行项。默认出站 BLOCK 保持。原因：'+$_.Exception.Message)
  }
  if($fqdnRuleFailure){
    $failedDynamicIds=@($active | Where-Object {$_.Mode -eq 'FQDN'} | ForEach-Object {[string]$_.DynamicId} | Where-Object {$_} | Select-Object -Unique)
    Remove-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -Context 'FQDN downgrade cleanup' | Out-Null
    if(@(Get-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -PolicyStore 'ActiveStore').Count -ne 0){throw 'FQDN 降级时无法清除本轮 Guard 规则；拒绝继续启动，默认出站 BLOCK 不作放宽'}
    $active=New-Object System.Collections.Generic.List[object]
    foreach($e in @($cfg.Endpoints)){
      if(@($e.IPs).Count -gt 0){$active.Add([pscustomobject]@{Host=$e.Host;Port=$e.Port;Mode='IP';DynamicId='';IPs=@($e.IPs)})}
    }
    # Rebuild the static-IP allowlist from scratch after removing all partial
    # FQDN rules, preserving only explicitly resolved IP destinations.
    foreach($prog in $programs){
      foreach($e in @($active)){
        $ruleName="$($cfg.Group) ALLOW $([IO.Path]::GetFileName($prog)) $($e.Host):$($e.Port)"
        New-NetFirewallRule -DisplayName $ruleName -Group $cfg.Group -Direction Outbound -Action Allow -Program $prog -RemoteAddress $e.IPs -Protocol TCP -RemotePort $e.Port -Profile Any -ErrorAction Stop | Out-Null
      }
    }
    Remove-PendingDynamicIds $failedDynamicIds
    $dynamic=@{}
  }
  $activeArray=[object[]]$active.ToArray()
  Write-AtomicJson (Join-Path $cfg.StateDir 'active_endpoints.json') $activeArray 6
  foreach($id in $dynamic.Values){Save-PendingDynamicId ([string]$id)}
  Write-GuardLog(('[firewall] active allow targets='+$active.Count+' / configured='+@($cfg.Endpoints).Count))
  if($active.Count -eq 0 -and @($cfg.Endpoints).Count -gt 0){ Write-GuardLog('[firewall] 警告：没有可用的静态 IP 或 FQDN 目标；Guard 将保持 BLOCK-only，不授予任何外部连接') }
  if(-not (Firewall-Lock-Healthy)){ throw '防火墙规则语义自检失败：ActiveStore 生效策略、规则数量、应用路径、远端地址或 TCP 端口与白名单不一致' }
}
function Expected-RuleCount{
  $programs=@(@($cfg.LauncherPath)+@($cfg.JavaPaths) | Where-Object { $_ } | ForEach-Object { Normalize-ProgramPath $_ } | Select-Object -Unique)
  $programCount=$programs.Count
  $activeCount=0
  $p=Join-Path $cfg.StateDir 'active_endpoints.json'
  if(Test-Path -LiteralPath $p){ try{ $activeCount=@(Get-Content -Raw -LiteralPath $p | ConvertFrom-Json).Count }catch{} }
  return ($programCount * $activeCount)
}
function Test-ExactGuardAllowRule($rule,$program,$endpoint){
  try{
    if($rule.Direction.ToString() -ne 'Outbound' -or $rule.Action.ToString() -ne 'Allow' -or $rule.Enabled.ToString() -ne 'True'){return $false}
    if($rule.Profile.ToString() -ne 'Any'){return $false}
    if([bool]$rule.OverrideBlockRules){return $false}
    $app=$rule|Get-NetFirewallApplicationFilter -ErrorAction Stop
    if((Normalize-ProgramPath ([string]$app.Program)) -ne (Normalize-ProgramPath $program)){return $false}
    if(-not [string]::IsNullOrWhiteSpace([string]$app.Package) -and [string]$app.Package -notin @('Any','<All>')){return $false}
    $ports=$rule|Get-NetFirewallPortFilter -ErrorAction Stop
    if([string]$ports.Protocol -ne 'TCP'){return $false}
    $remotePorts=@($ports.RemotePort|ForEach-Object{[string]$_})
    if($remotePorts.Count -ne 1 -or $remotePorts[0] -ne [string]$endpoint.Port){return $false}
    $addresses=$rule|Get-NetFirewallAddressFilter -ErrorAction Stop
    $localAddresses=@($addresses.LocalAddress|ForEach-Object{[string]$_})
    if($localAddresses.Count -ne 1 -or $localAddresses[0] -ne 'Any'){return $false}
    if($endpoint.Mode -eq 'IP'){
      $actual=@($addresses.RemoteAddress|ForEach-Object{[string]$_}|Sort-Object -Unique)
      $expected=@($endpoint.IPs|ForEach-Object{[string]$_}|Sort-Object -Unique)
      if($actual.Count -ne $expected.Count){return $false}
      for($i=0;$i -lt $actual.Count;$i++){if($actual[$i] -ne $expected[$i]){return $false}}
    }elseif($endpoint.Mode -eq 'FQDN'){
      $remote=@($addresses.RemoteAddress|ForEach-Object{[string]$_})
      # NetSecurity exposes rule conditions through associated filter objects;
      # read both the rule and address filter because the surfaced property can vary by build.
      $remoteDynamic=@()
      foreach($source in @($rule,$addresses)){
        $property=$source.PSObject.Properties['RemoteDynamicKeywordAddresses']
        if($null -ne $property -and $null -ne $property.Value){$remoteDynamic+=@($property.Value|ForEach-Object{[string]$_})}
      }
      $remoteDynamic=@($remoteDynamic|Where-Object{$_}|Select-Object -Unique)
      if($remote.Count -ne 1 -or $remote[0] -ne 'Any'){return $false}
      if($remoteDynamic.Count -ne 1 -or $remoteDynamic[0] -ine [string]$endpoint.DynamicId){return $false}
      $dynObjects=@(Get-NetFirewallDynamicKeywordAddress -Id ([string]$endpoint.DynamicId) -ErrorAction Stop)
      if($dynObjects.Count -ne 1 -or [string]$dynObjects[0].Keyword -ine [string]$endpoint.Host -or -not [bool]$dynObjects[0].AutoResolve){return $false}
    }else{return $false}
    return $true
  }catch{return $false}
}
function Firewall-Lock-Healthy{
  try{
    if(@(Get-NetFirewallProfile -PolicyStore ActiveStore|Where-Object{$_.DefaultOutboundAction.ToString() -ne 'Block' -or $_.Enabled.ToString() -ne 'True'}).Count -ne 0){return $false}
    $activePath=Join-Path $cfg.StateDir 'active_endpoints.json'
    if(!(Test-Path -LiteralPath $activePath)){return $false}
    $active=@(Get-Content -Raw -LiteralPath $activePath -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop)
    $programs=@(@($cfg.LauncherPath)+@($cfg.JavaPaths)|Where-Object{$_}|Select-Object -Unique)
    $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Group $cfg.Group -ErrorAction SilentlyContinue)
    $expected=$programs.Count*$active.Count
    if($expected -lt 0 -or $rules.Count -ne $expected){return $false}
    if($active.Count -eq 0){return ($rules.Count -eq 0)}
    foreach($program in $programs){foreach($endpoint in $active){
      $matches=@($rules|Where-Object{Test-ExactGuardAllowRule $_ $program $endpoint})
      if($matches.Count -ne 1){return $false}
    }}
    return $true
  }catch{return $false}
}
function Ensure-FirewallLock{
  if(-not (Firewall-Lock-Healthy)){ Add-Firewall; Write-GuardLog('[watchdog] firewall containment repaired') }
  else { Audit-AndDisableProgramAllows }
}
function Remove-DynamicKeywordAddresses{
  Assert-DynamicCleanupComplete (Join-Path $cfg.StateDir 'dynamic_keywords.json')
}
function Remove-Firewall{
  Write-AtomicText (Join-Path $cfg.StateDir 'firewall_cleanup_started') ([DateTime]::UtcNow.ToString('o'))
  $results=New-Object System.Collections.Generic.List[object]
  $rulesResult=Invoke-LoggedRecoveryStep 'firewall-rules-remove' {
    Remove-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -Context 'Helper firewall restore' | Out-Null
    $remaining=@(Get-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -PolicyStore 'ActiveStore')
    if($remaining.Count -ne 0){throw ('Guard ActiveStore firewall rules remain after removal: '+$remaining.Count)}
  }
  $results.Add($rulesResult)
  if($rulesResult.Success){
    $results.Add((Invoke-LoggedRecoveryStep 'firewall-dynamic-keywords-remove' {Remove-DynamicKeywordAddresses}))
    $results.Add((Invoke-LoggedRecoveryStep 'firewall-disabled-user-allows-restore' {Restore-DisabledAllows}))
    $profilePath=Join-Path $cfg.StateDir 'profiles.json';$profileRequired=Test-Path -LiteralPath (Join-Path $cfg.StateDir 'firewall_profile_apply_started');$results.Add((Invoke-LoggedRecoveryStep 'firewall-profiles-restore' {Restore-ProfileState $profilePath $profileRequired}))
  }else{
    foreach($deferred in @('firewall-dynamic-keywords-remove','firewall-disabled-user-allows-restore','firewall-profiles-restore')){
      Write-GuardLog('[restore-step] DEFERRED '+$deferred+' because Guard firewall rules remain; default outbound BLOCK/profile state will not be relaxed')
      $results.Add([pscustomobject]@{Name=$deferred;Success=$false;Error='依赖 Guard firewall rules 完全移除；为保持 BLOCK，本轮延后'})
    }
  }
  $results.Add((Invoke-LoggedRecoveryStep 'audit-5157-restore' {Restore-FilteringPlatformConnectionAudit}))
  if(-not (Write-SessionRecoverySummary 'firewall restoration' @($results.ToArray()))){throw '防火墙部分恢复未全部完成；保留会话状态供后续重试'}
}
function Enable-FilteringPlatformConnectionAudit{
  $statePath=Join-Path $cfg.StateDir 'audit_policy.json'
  if(Test-Path -LiteralPath $statePath){ return $true }
  try{$st=Get-FilteringPlatformAuditState}catch{Write-GuardLog('[audit] 读取 5157 初始状态失败；不修改审计策略，防护主流程继续：'+$_.Exception.ToString()+' | ScriptStackTrace='+$_.ScriptStackTrace);return $false}
  if($null -eq $st -or -not $st.Known){
    Write-GuardLog('[audit] 无法可靠读取“Filtering Platform Connection”原始审核状态；为避免覆盖用户设置，本会话不启用 5157 审计')
    return $false
  }
  $expectedKind=Get-ExpectedAuditSettingAfterFailureEnable ([string]$st.Setting)
  $auditRecord=[pscustomobject]@{Schema=3;FailureEnabled=[bool]$st.FailureEnabled;Setting=[string]$st.Setting;OriginalKind=[string]$st.Kind;ExpectedKind=$expectedKind;ChangeAttempted=$false;SavedUtc=[DateTime]::UtcNow.ToString('o')}
  Write-AtomicJson $statePath $auditRecord 5
  if($st.FailureEnabled){
    Write-GuardLog('[audit] 5157 失败审计本来已启用，保持不变')
    return $true
  }
  try{
    if(-not $expectedKind){Write-GuardLog('[audit] 原始审核状态无法映射为可安全恢复的目标；本会话不修改 5157');return $false}
    $auditRecord.ChangeAttempted=$true
    Write-AtomicJson $statePath $auditRecord 5
    Write-AtomicText (Join-Path $cfg.StateDir 'audit_policy_apply_started') ([DateTime]::UtcNow.ToString('o'))
    $auditOutput=@(& (Join-Path $env:SystemRoot 'System32\auditpol.exe') '/set' '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' '/failure:enable' 2>&1)
    if($LASTEXITCODE -ne 0){throw ("auditpol exit code $LASTEXITCODE；输出="+(@($auditOutput)-join ' | '))}
    $enabledState=Get-FilteringPlatformAuditState
    if(-not $enabledState.Known -or $enabledState.Kind -ne $expectedKind){throw ('启用 5157 后状态与预期不一致：expected='+$expectedKind+' actual='+$enabledState.Setting)}
    Write-GuardLog('[audit] 已临时启用 Windows WFP 5157 连接阻断审计；expected='+$expectedKind)
    return $true
  }catch{
    $detail=$_.Exception.ToString();if($_.ScriptStackTrace){$detail+=' | ScriptStackTrace='+$_.ScriptStackTrace}
    Write-GuardLog('[audit] 无法启用 5157 审计；会话日志保留完整异常：'+($detail -replace '\r?\n',' | '))
    return $false
  }
}
function Restore-FilteringPlatformConnectionAudit{
  Restore-AuditStateFromPath (Join-Path $cfg.StateDir 'audit_policy.json')
}

function Wait-ProtectedProcesses{
  $deadline=(Get-Date).AddHours(24)
  do{
    # Wait only for this session's launcher or attributed Minecraft Java.
    # The GuardLauncher parent itself remains alive while it waits for restoration and is not a game target.
    $state=Get-SessionProcessState $cfg
    Sync-SessionJavaPaths $state
    $alive=@($state.LauncherProcesses).Count -gt 0 -or @($state.JavaProcesses).Count -gt 0
    if(!$alive){break}
    Start-Sleep -Seconds 2
  }while((Get-Date) -lt $deadline)
}
function Is-AdminOrSystemOwned($path){
  try{
    $owner=(Get-Acl -LiteralPath $path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    return ($owner -eq 'S-1-5-32-544' -or $owner -eq 'S-1-5-18')
  }catch{ return $false }
}
function FirewallGroupExists($group){
  if([string]::IsNullOrWhiteSpace([string]$group)){return $false}
  return (@(Get-GuardFirewallRulesByGroup -Group ([string]$group) -PolicyStore 'ActiveStore').Count -gt 0)
}
function FirewallAllBlock{
  try{ return (@(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { $_.DefaultOutboundAction.ToString() -ne 'Block' -or $_.Enabled.ToString() -ne 'True' }).Count -eq 0) }catch{ return $false }
}
function Remove-LegacyHostBlock($hostPath,$group){
  if([string]::IsNullOrWhiteSpace($hostPath) -or -not (Test-Path -LiteralPath $hostPath)){ return }
  try{
    $text=[IO.File]::ReadAllText($hostPath)
    $a=[regex]::Escape("# HachimiGuard BEGIN $group")
    $b=[regex]::Escape("# HachimiGuard END $group")
    $pattern="(?ms)^\s*$a.*?^\s*$b\s*\r?\n?"
    $new=[regex]::Replace($text,$pattern,'')
    if($new -ne $text){ [IO.File]::WriteAllText($hostPath,$new,[Text.Encoding]::ASCII) }
  }catch{}
}
function Recover-StaleSessions{
  if([string]::IsNullOrWhiteSpace($cfg.StateRoot) -or !(Test-Path -LiteralPath $cfg.StateRoot)){ return }
  try{$staleDirs=@(Get-ChildItem -LiteralPath $cfg.StateRoot -Directory -Filter 'session-*' -Force -ErrorAction Stop)}
  catch{$detail=$_.Exception.ToString();if($_.ScriptStackTrace){$detail+=' | ScriptStackTrace='+$_.ScriptStackTrace};Write-GuardLog('[recovery] cannot enumerate stale session directories; abort recovery and retain state: '+($detail -replace '\r?\n',' | '));throw}
  Write-GuardLog('[recovery-inventory] StateRoot='+$cfg.StateRoot+' staleSessionDirectoryCount='+$staleDirs.Count)
  try{
    $rootOther=@(Get-ChildItem -LiteralPath $cfg.StateRoot -Force -ErrorAction Stop|Where-Object{$_.Name -notlike 'session-*'}|ForEach-Object{$_.Name})
    Write-GuardLog('[recovery-inventory] non-session StateRoot entries='+(@($rootOther) -join ',')+'; active-session.lock file presence alone is not treated as an active lock; audit logs are retained and are not session recovery inputs')
  }catch{Write-GuardLog('[recovery-inventory] StateRoot non-session entry enumeration failed: '+$_.Exception.Message)}
  foreach($dir in $staleDirs){
    $meta=Join-Path $dir.FullName 'session.json'
    $evidenceNames=@('firewall_profile_apply_started','firewall_cleanup_started','audit_policy_apply_started','disabled_allows_apply_started','profiles.json','audit_policy.json','disabled_allows.json','dynamic_keywords.json','active_endpoints.json','acl_journal_manifest.json','acl_journal','acl_state.ndjson','protected_paths.txt','watchdog.pid','watchdog.ps1','watchdog.heartbeat.json','watchdog.process_created_utc','watchdog.resume_requested','hosts.original')
    $mutationEvidence=@($evidenceNames|Where-Object{Test-Path -LiteralPath (Join-Path $dir.FullName $_)})
    if(-not (Is-AdminOrSystemOwned $dir.FullName)){
      Write-GuardLog('[recovery] BLOCKED: stale session directory owner is not Administrators/SYSTEM; refusing to modify or ignore possible recovery state. evidence='+($mutationEvidence -join ',')+' path='+$dir.FullName)
      throw ('旧会话目录所有者不可信，无法安全读取/恢复；保留原目录并暂停新会话：'+$dir.FullName)
    }
    if(!(Test-Path -LiteralPath $meta)){
      $orphanEntries=@(Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction Stop)
      if($orphanEntries.Count -eq 0 -and $mutationEvidence.Count -eq 0){
        Write-GuardLog('[recovery-inventory] EMPTY_ORPHAN_DELETE_BEGIN path='+$dir.FullName+' evidence=none entries=0')
        Remove-Item -LiteralPath $dir.FullName -Force -ErrorAction Stop
        Write-GuardLog('[recovery-inventory] EMPTY_ORPHAN_DELETE_COMPLETE path='+$dir.FullName)
        continue
      }
      $orphanNames=@($orphanEntries|ForEach-Object{$_.Name})
      Write-GuardLog('[recovery] BLOCKED: non-empty orphan session directory has no session.json; entries='+($orphanNames -join ',')+'; mutationEvidence='+($mutationEvidence -join ',')+'; preserving all files and refusing a new session: '+$dir.FullName)
      throw ('发现非空旧会话目录但缺少 session.json，无法证明是否存在待恢复的防火墙/ACL 状态；目录内容='+($orphanNames -join ',')+'；保留原目录并暂停新会话：'+$dir.FullName)
    }
    try{ $old=(Read-GuardUtf8Text $meta) | ConvertFrom-Json -ErrorAction Stop }catch{
      $detail=$_.Exception.ToString();if($_.ScriptStackTrace){$detail+=' | ScriptStackTrace='+$_.ScriptStackTrace}
      Write-GuardLog('[recovery] BLOCKED: corrupt stale-session metadata retained; evidence='+($mutationEvidence -join ',')+' path='+$dir.FullName+' :: '+($detail -replace '\r?\n',' | '))
      throw ('旧会话元数据损坏，无法确认是否需要恢复；保留原目录并暂停新会话：'+$dir.FullName)
    }
    $staleVersion=[string]$old.Version
    $staleSchema=[int]$old.Schema
    $supportedStale=@{
      'v17.1'=6; 'v17.2'=7; 'v17.3'=7; 'v17.4'=7; 'v17.5'=8;
      'v17.6'=10; 'v17.7'=10; 'v17.8'=10; 'v17.9'=10; 'v17.10'=11; 'v17.11'=11; 'v17.12'=11; 'v17.13'=11; 'v17.14'=11; 'v17.15'=11; 'v17.16'=11
    }
    if(-not $supportedStale.ContainsKey($staleVersion) -or [int]$supportedStale[$staleVersion] -ne $staleSchema){
      Write-GuardLog('[recovery] BLOCKED: unsupported stale session version/schema retained version='+$staleVersion+' schema='+$staleSchema+' evidence='+($mutationEvidence -join ',')+' path='+$dir.FullName)
      throw ('发现无法自动迁移的旧会话版本/Schema；无论已知标记是否存在，都不能猜测恢复状态；保留目录并暂停新会话：'+$dir.FullName)
    }
    if([string]::IsNullOrWhiteSpace([string]$old.Group) -or [string]::IsNullOrWhiteSpace([string]$old.SessionStartUtc)){
      Write-GuardLog('[recovery] BLOCKED: stale session metadata lacks mandatory Group/SessionStartUtc; evidence='+($mutationEvidence -join ',')+' path='+$dir.FullName)
      throw ('旧会话元数据缺少 Group 或 SessionStartUtc；保留现场并暂停新会话：'+$dir.FullName)
    }
    Write-GuardLog('[recovery-inventory] recognized stale session version='+$staleVersion+' schema='+$staleSchema+' group='+[string]$old.Group+' evidence='+($mutationEvidence -join ',')+' path='+$dir.FullName)
    # v17.4 Watchdogs do not own the new global file lease. Do not race a still-running
    # legacy Watchdog while it may be completing its own restoration sequence.
    $legacyPidPath=Join-Path $dir.FullName 'watchdog.pid'
    if(Test-Path -LiteralPath $legacyPidPath){
      $legacyPid=0
      try{
        $legacyPid=[int](Read-GuardUtf8Text $legacyPidPath).Trim()
        if($legacyPid -le 0){throw 'Watchdog PID 无效'}
        $legacyProc=Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = '+$legacyPid) -OperationTimeoutSec 8 -ErrorAction Stop
        if($legacyProc){
          $expectedWatchPath=Join-Path $dir.FullName 'watchdog.ps1'
          if(-not [string]$legacyProc.CommandLine){throw 'Watchdog PID 存在但命令行不可读'}
          if(([string]$legacyProc.CommandLine).IndexOf($expectedWatchPath,[System.StringComparison]::OrdinalIgnoreCase) -ge 0){throw ('legacy Watchdog is still running PID='+$legacyPid)}
        }else{
          $direct=Get-DirectParentProcessProbe $legacyPid ([DateTime]::UtcNow)
          if($direct -ne 'Absent'){throw ('CIM 未返回 Watchdog PID，但独立核验不能证明退出：'+$direct)}
        }
      }catch{
        $identityError=$_.Exception.Message
        if($legacyPid -le 0){throw ('旧 Watchdog PID 记录损坏，保留会话：'+$identityError)}
        $direct=Get-DirectParentProcessProbe $legacyPid ([DateTime]::UtcNow)
        if($direct -ne 'Absent'){throw ('旧 Watchdog 身份检查未能证明不存在/属于其他进程；保留会话，拒绝并发恢复：'+$identityError+' native='+$direct)}
        Write-GuardLog('[recovery] CIM Watchdog check unavailable; independent process probe proved PID absent: '+$legacyPid+' :: '+$identityError)
      }
    }
    # Use the same PID + image path + creation time + command-line attribution as Watchdog.
    # For v17.3 metadata without ParentPath, the shared matcher accepts only a GuardLauncher image.
    $processState=Get-SessionProcessState $old
    $active=[bool]$processState.ParentAlive -or @($processState.LauncherProcesses).Count -gt 0 -or @($processState.JavaProcesses).Count -gt 0
    if($active){ throw "An active HachimiGuard session is already running: $($dir.FullName)" }

    Write-GuardLog('[recovery] BEGIN stale-session restoration dir='+$dir.FullName+' group='+[string]$old.Group)
    $results=New-Object System.Collections.Generic.List[object]
    $staleFirewallGroupPresent=$false
    if($old.Group){$staleFirewallGroupPresent=FirewallGroupExists $old.Group}
    $rulesResult=Invoke-LoggedRecoveryStep ('stale-firewall-rules-remove '+[string]$old.Group) {
      if($old.Group){Remove-GuardFirewallRulesByGroup -Group ([string]$old.Group) -Context 'stale-session recovery' | Out-Null}
      if($old.Group -and @(Get-GuardFirewallRulesByGroup -Group ([string]$old.Group) -PolicyStore 'ActiveStore').Count -ne 0){throw 'stale Guard ActiveStore firewall rules remain after removal'}
    }
    $results.Add($rulesResult)
    if($rulesResult.Success){
      $dynPath=Join-Path $dir.FullName 'dynamic_keywords.json'
      $results.Add((Invoke-LoggedRecoveryStep 'stale-dynamic-keywords-remove' {
        Assert-DynamicCleanupComplete $dynPath
      }))
      $results.Add((Invoke-LoggedRecoveryStep 'stale-disabled-user-allows-restore' {Restore-DisabledAllowsFrom (Join-Path $dir.FullName 'disabled_allows.json')}))
      $cleanupMarker=Join-Path $dir.FullName 'firewall_cleanup_started'
      $oldProfileApplyMarker=Test-Path -LiteralPath (Join-Path $dir.FullName 'firewall_profile_apply_started')
      if($staleFirewallGroupPresent -or $oldProfileApplyMarker -or (Test-Path -LiteralPath $cleanupMarker)){
        $oldProfilePath=Join-Path $dir.FullName 'profiles.json'
        $profileRestoreRequired=($oldProfileApplyMarker -or $staleFirewallGroupPresent -or (Test-Path -LiteralPath $cleanupMarker))
        $results.Add((Invoke-LoggedRecoveryStep 'stale-firewall-profiles-restore' {Restore-ProfileState $oldProfilePath $profileRestoreRequired}))
      }else{
        Write-GuardLog('[restore-step] SKIP stale-firewall-profiles-restore: no Guard firewall group and no cleanup marker')
      }
    }else{
      foreach($deferred in @('stale-dynamic-keywords-remove','stale-disabled-user-allows-restore','stale-firewall-profiles-restore')){
        Write-GuardLog('[restore-step] DEFERRED '+$deferred+' because stale Guard firewall rules remain; do not restore broad user Allow/profile state')
        $results.Add([pscustomobject]@{Name=$deferred;Success=$false;Error='Guard firewall rules remain; unsafe to relax'} )
      }
    }
    $results.Add((Invoke-LoggedRecoveryStep 'stale-audit-5157-restore' {Restore-AuditStateFromPath (Join-Path $dir.FullName 'audit_policy.json')}))
    $results.Add((Invoke-LoggedRecoveryStep 'stale-tencent-acl-restore' {
      $legacyList=Join-Path $dir.FullName 'protected_paths.txt'
      $journalRecords=@(Get-AclJournalRecords $dir.FullName -Refresh)
      $hasManifest=Test-AclJournalManifest $dir.FullName ([string]$old.Group)
      if($journalRecords.Count -eq 0 -and (Test-Path -LiteralPath $legacyList) -and -not $hasManifest){throw '旧会话缺少 ACL 来源记录；为保护用户原有权限，不能自动删除不明 Deny ACE'}
      if($journalRecords.Count -eq 0 -and $hasManifest){Write-GuardLog('[recovery] stale ACL manifest confirms empty journal; no Guard-added ACEs require removal')}
      $aclResults=New-Object System.Collections.Generic.List[object]
      $aclProcessed=0
      foreach($r in $journalRecords){if(-not [bool]$r.Added){continue};$record=$r;$flags=Get-GuardInheritanceFlags $record;$aclResults.Add((Invoke-LoggedRecoveryStep ('stale-ACL-remove '+[string]$record.Path) {if(-not (Remove-GuardDeny ([string]$record.Path) ([string]$record.UserSID) $flags)){throw ('stale ACL restore failed: '+[string]$record.Path)}} -QuietSuccess));$aclProcessed++;if(($aclProcessed % 500) -eq 0){Write-GuardLog('[acl-restore] stale progress processed='+$aclProcessed+' total_journal_records='+$journalRecords.Count)}}
      if(-not (Write-SessionRecoverySummary 'stale Tencent ACL restoration' @($aclResults.ToArray()))){throw 'one or more stale ACL entries failed'}
    }))
    $legacyHosts=Join-Path $dir.FullName 'hosts.original'
    if((Test-Path -LiteralPath $legacyHosts) -and $old.Group){
      $results.Add((Invoke-LoggedRecoveryStep 'stale-legacy-hosts-cleanup' {Remove-LegacyHostBlock (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') $old.Group}))
    }
    if(-not (Write-SessionRecoverySummary ('stale session '+$dir.FullName) @($results.ToArray()))){
      throw ('遗留会话恢复不完整，恢复记录已保留供重试：'+$dir.FullName)
    }
    Write-GuardLog('[recovery] SUCCESS stale-session restoration dir='+$dir.FullName+'; removing state directory')
    Write-GuardLog('[recovery] STALE_STATE_DIR_DELETE_BEGIN path='+$dir.FullName+' group='+[string]$old.Group+' version='+$staleVersion+' schema='+$staleSchema)
    $removeState=Invoke-LoggedRecoveryStep ('stale-session-state-remove '+$dir.FullName) {Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction Stop}
    if($removeState.Success){Write-GuardLog('[recovery] STALE_STATE_DIR_DELETE_COMPLETE path='+$dir.FullName+' group='+[string]$old.Group)}
    if(-not $removeState.Success){throw ('stale-session state directory could not be removed; preserve for retry: '+$dir.FullName)}
  }
}
function Save-SessionMeta{
  try{
    Write-AtomicJson (Join-Path $cfg.StateDir 'session.json') $cfg 8
  }catch{ throw }
}
function Format-HelperError([object]$err){
  $lines=@()
  try{$lines += ('ExceptionType='+$err.Exception.GetType().FullName)}catch{}
  try{$lines += ('Message='+$err.Exception.Message)}catch{}
  try{$lines += ('HResult='+$err.Exception.HResult)}catch{}
  try{$lines += ('FullyQualifiedErrorId='+$err.FullyQualifiedErrorId)}catch{}
  try{$lines += ('CategoryInfo='+$err.CategoryInfo)}catch{}
  try{$lines += ('ScriptLineNumber='+$err.InvocationInfo.ScriptLineNumber)}catch{}
  try{$lines += ('OffsetInLine='+$err.InvocationInfo.OffsetInLine)}catch{}
  try{$lines += ('PositionMessage='+$err.InvocationInfo.PositionMessage)}catch{}
  try{$lines += ('Invocation='+$err.InvocationInfo.Line)}catch{}
  try{$lines += ('ScriptStackTrace='+$err.ScriptStackTrace)}catch{}
  try{$lines += ('ExceptionToString='+$err.Exception.ToString())}catch{}
  return ($lines -join [Environment]::NewLine)
}
function Emit-HelperError([object]$err){
  $detail=Format-HelperError $err
  try{ Write-GuardLog('[elevated-error] '+($detail -replace '\r?\n', ' | ')) }catch{}
  [Console]::Error.WriteLine('HACHIMIGUARD_HELPER_ERROR_BEGIN')
  [Console]::Error.WriteLine($detail)
  [Console]::Error.WriteLine('HACHIMIGUARD_HELPER_ERROR_END')
}

$stateRootExisted=Test-Path -LiteralPath $cfg.StateRoot
if($stateRootExisted){
  # Existing StateRoot may belong to an active session. Acquire its lease before
  # changing any shared StateRoot/audit ACL, so a losing second instance has no side effects.
  Acquire-SessionLease -TimeoutSeconds 20 -Owner ('Helper:'+ $Mode)
  Secure-StateDir $cfg.StateRoot
}else{
  # First-run creation is serialized separately. The first initializer secures the
  # directory and obtains the session lease before releasing this bootstrap mutex.
  $bootstrapMutex=$null;$bootstrapLocked=$false
  try{
    $bootstrapMutex=New-Object -TypeName System.Threading.Mutex -ArgumentList @($false,'Global\HachimiGuardStateRootBootstrap')
    try{$bootstrapLocked=$bootstrapMutex.WaitOne(20000)}catch [System.Threading.AbandonedMutexException]{$bootstrapLocked=$true}
    if(-not $bootstrapLocked){throw '等待 StateRoot 首次初始化互斥锁超时'}
    if(-not (Test-Path -LiteralPath $cfg.StateRoot)){
      Ensure-Dir $cfg.StateRoot
      Secure-StateDir $cfg.StateRoot
      Acquire-SessionLease -TimeoutSeconds 20 -Owner ('Helper:'+ $Mode)
    }else{
      # Another initializer won the race; it may already own the session lease.
      Acquire-SessionLease -TimeoutSeconds 20 -Owner ('Helper:'+ $Mode)
      Secure-StateDir $cfg.StateRoot
    }
  }finally{
    if($bootstrapLocked -and $bootstrapMutex){try{$bootstrapMutex.ReleaseMutex()}catch{}}
    if($bootstrapMutex){try{$bootstrapMutex.Dispose()}catch{}}
  }
}
if($cfg.AuditLogPath){ Ensure-Dir (Split-Path -Parent $cfg.AuditLogPath); Secure-StateDir (Split-Path -Parent $cfg.AuditLogPath); Secure-SessionAuditFile }
Write-GuardLog('[lifecycle] privileged helper entered mode='+$Mode)
if($Mode -eq 'Apply'){
  Write-GuardLog('[recovery-inventory] BEGIN StateRoot='+$cfg.StateRoot+' currentStateDir='+$cfg.StateDir+' currentStateDirExists='+(Test-Path -LiteralPath $cfg.StateDir))
  Recover-StaleSessions
  Write-GuardLog('[recovery-inventory] completed stale-session pass; new session directory will now be created: '+$cfg.StateDir)

  try{
    Write-GuardLog('[elevated] applying session '+$cfg.Group)
    Secure-StateDir $cfg.StateDir
    if(-not (Test-Path -LiteralPath $cfg.StateDir -PathType Container)){throw ('StateDir creation verification failed: '+$cfg.StateDir)}
    Save-SessionMeta
    if(-not (Test-Path -LiteralPath (Join-Path $cfg.StateDir 'session.json') -PathType Leaf)){throw ('session.json write verification failed in StateDir: '+$cfg.StateDir)}
    Write-GuardLog('[elevated] session directory secured and verified; path='+$cfg.StateDir+' schema='+$cfg.Schema+' version='+$cfg.Version)
    Protect-Files
    Write-GuardLog('[elevated] QQ/Tencent ACL protection applied using user SID '+$cfg.UserSID)
    if($cfg.Strict){
      Add-Firewall
      Write-GuardLog('[elevated] firewall lock applied')
      if(Enable-FilteringPlatformConnectionAudit){ Write-GuardLog('[elevated] firewall block feedback audit ready') } else { Write-GuardLog('[elevated] firewall block feedback unavailable; containment remains active') }
    }
  # The helper owns the global lease until the Watchdog acquires it and writes a fresh heartbeat.
  $wp=Start-SessionWatchdog
    foreach($requiredStateFile in @('session.json','watchdog.pid','watchdog.heartbeat.json')){
      $requiredPath=Join-Path $cfg.StateDir $requiredStateFile
      if(-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)){throw ('Watchdog startup postcondition failed: required state file missing: '+$requiredPath)}
    }
    $confirmedPid=[int](Get-Content -Raw -LiteralPath (Join-Path $cfg.StateDir 'watchdog.pid') -ErrorAction Stop).Trim()
    if($confirmedPid -ne [int]$wp.Id){throw ('Watchdog startup postcondition PID mismatch: expected='+$wp.Id+' actual='+$confirmedPid)}
    $confirmedHeartbeat=Get-Content -Raw -LiteralPath (Join-Path $cfg.StateDir 'watchdog.heartbeat.json') -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
    if([int]$confirmedHeartbeat.PID -ne [int]$wp.Id -or [string]$confirmedHeartbeat.Group -ne [string]$cfg.Group){throw 'Watchdog startup postcondition heartbeat identity mismatch'}
    Write-GuardLog('[watchdog] helper startup postconditions verified; StateDir='+$cfg.StateDir+' PID='+$wp.Id)
  } catch {
    $rollbackOK=$true
    if(-not $script:sessionLeaseStream){
      try{Acquire-SessionLease -TimeoutSeconds 8 -Owner 'HelperRollback'}
      catch{
        $rollbackOK=$false
        Write-GuardLog('[rollback] could not reacquire global session lease; no rollback is attempted concurrently. State retained: '+$_.Exception.Message)
      }
    }
    if($rollbackOK){try{ if($cfg.Strict){ Remove-Firewall } }catch{ $rollbackOK=$false; Write-GuardLog('[rollback] firewall cleanup failed; retaining state: '+$_.Exception.Message) }}
    if($script:sessionLeaseStream){try{ Restore-Files }catch{ $rollbackOK=$false; Write-GuardLog('[rollback] ACL cleanup failed; retaining state: '+$_.Exception.Message) }}
    try{ Emit-HelperError $_ }catch{}
    if($rollbackOK){
      try{
        Write-GuardLog('[rollback] STATE_DIR_DELETE_BEGIN path='+$cfg.StateDir+' group='+$cfg.Group+' rollbackOK='+$rollbackOK)
        Remove-Item -LiteralPath $cfg.StateDir -Recurse -Force -ErrorAction Stop
        Write-GuardLog('[rollback] STATE_DIR_DELETE_COMPLETE path='+$cfg.StateDir+' group='+$cfg.Group)
      }catch{ Write-GuardLog('[rollback] restored but could not remove state directory: '+$_.Exception.Message) }
    }
    else{ Write-GuardLog('[rollback] IMPORTANT: incomplete; recovery state retained at '+$cfg.StateDir) }
    throw
  }
  Release-SessionLease
  Write-Output 'HACHIMIGUARD_OK'
  return
}
if($Mode -eq 'ResumeWatchdog'){
  $metaPath=Join-Path $cfg.StateDir 'session.json'
  if(-not (Test-Path -LiteralPath $metaPath)){throw '无法重启 Watchdog：会话元数据不存在'}
  $meta=(Read-GuardUtf8Text $metaPath)|ConvertFrom-Json -ErrorAction Stop
  if([string]$meta.Group -ne [string]$cfg.Group){throw '无法重启 Watchdog：会话组标识不匹配'}
  $cfg=$meta
  $ConfigB64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($cfg|ConvertTo-Json -Depth 8 -Compress)))
  Write-GuardLog('[watchdog] lifecycle supervisor requested restart; existing protection state retained')
  $wp=Start-SessionWatchdog
  Write-GuardLog('[watchdog] lifecycle supervisor restart completed PID='+$wp.Id)
  Release-SessionLease
  Write-Output 'HACHIMIGUARD_OK'
  return
}
if($Mode -eq 'Watchdog'){
  try{
    Wait-ProtectedProcesses
    $restoreResults=New-Object System.Collections.Generic.List[object]
    if($cfg.Strict){$restoreResults.Add((Invoke-LoggedRecoveryStep 'firewall-all' {Remove-Firewall}))}
    $restoreResults.Add((Invoke-LoggedRecoveryStep 'tencent-acl-all' {Restore-Files}))
    if(-not (Write-SessionRecoverySummary 'Helper watchdog restoration' @($restoreResults.ToArray()))){throw '一个或多个恢复分组失败；会话记录保留，等待 Watchdog/下一次遗留恢复重试'}
    Write-GuardLog('[restore] STATE_DIR_DELETE_BEGIN mode=HelperWatchdog path='+$cfg.StateDir+' group='+$cfg.Group)
    Remove-Item -LiteralPath $cfg.StateDir -Recurse -Force -ErrorAction Stop
    Write-GuardLog('[restore] Helper Watchdog completed all independent restoration groups; state directory removed')
    Release-SessionLease
    Write-Output 'HACHIMIGUARD_OK'
    return
  } catch {
    Emit-HelperError $_
    throw
  }
}
if($Mode -eq 'Restore'){
  try{
    # A parent-side timeout or Watchdog failure is not proof that Minecraft exited.
    # Query the attributed launcher/Java processes again while holding the global lease.
    # Unknown WMI state throws and therefore preserves all protection state.
    $restoreMeta=(Read-GuardUtf8Text (Join-Path $cfg.StateDir 'session.json'))|ConvertFrom-Json -ErrorAction Stop
    if([string]$restoreMeta.Group -ne [string]$cfg.Group){throw 'Restore 会话身份不匹配'}
    $cfg=$restoreMeta
    $restoreProcessState=Get-SessionProcessState $cfg
    $activeLaunchers=@($restoreProcessState.LauncherProcesses).Count
    $activeJava=@($restoreProcessState.JavaProcesses).Count
    if($activeLaunchers -gt 0 -or $activeJava -gt 0){throw ('拒绝最终恢复：仍检测到受保护进程（Launcher='+$activeLaunchers+'，Minecraft Java='+$activeJava+'）')}
    Write-GuardLog('[restore] final helper independently confirmed no attributed launcher or Minecraft Java process remains')
    $restoreResults=New-Object System.Collections.Generic.List[object]
    if($cfg.Strict){$restoreResults.Add((Invoke-LoggedRecoveryStep 'firewall-all' {Remove-Firewall}))}
    $restoreResults.Add((Invoke-LoggedRecoveryStep 'tencent-acl-all' {Restore-Files}))
    if(-not (Write-SessionRecoverySummary 'Final Helper restoration' @($restoreResults.ToArray()))){throw '一个或多个恢复分组失败；会话记录保留，等待遗留恢复重试'}
    Write-GuardLog('[restore] STATE_DIR_DELETE_BEGIN mode=Restore path='+$cfg.StateDir+' group='+$cfg.Group+' launcherCount='+$activeLaunchers+' javaCount='+$activeJava+' parentAlive='+[bool]$restoreProcessState.ParentAlive+' parentLeaseState='+[string]$restoreProcessState.ParentLeaseState+' parentProbeState='+[string]$restoreProcessState.ParentProbeState)
    Remove-Item -LiteralPath $cfg.StateDir -Recurse -Force -ErrorAction Stop
    Write-GuardLog('[restore] STATE_DIR_DELETE_COMPLETE mode=Restore path='+$cfg.StateDir+' group='+$cfg.Group)
    Write-GuardLog('[restore] final Helper completed all independent restoration groups; state directory removed')
    Release-SessionLease
    Write-Output 'HACHIMIGUARD_OK'
    return
  } catch {
    Emit-HelperError $_
    throw
  }
}
throw "未知的保护组件模式：$Mode"
`

const watchdogScript = `
param()
$ErrorActionPreference='Stop'
$cfg=( [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CFG_B64__')) | ConvertFrom-Json )
$script:watchdogStartupPath=([string]$cfg.AuditLogPath)+'.watchdog.startup.log'
function Write-WatchdogStartupDiagnostic([string]$Message){
  $line=[DateTime]::UtcNow.ToString('o')+' [watchdog PID='+$PID+'] '+$Message+[Environment]::NewLine
  try{
    $bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes($line)
    $fs=[IO.File]::Open($script:watchdogStartupPath,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
    try{$fs.Write($bytes,0,$bytes.Length);$fs.Flush($true)}finally{$fs.Dispose()}
  }catch{try{[Console]::Error.WriteLine('WATCHDOG_STARTUP_DIAGNOSTIC_FAILURE '+$_.Exception.ToString())}catch{}}
}
Write-WatchdogStartupDiagnostic ('script entered; StateDir='+[string]$cfg.StateDir+'; StateRoot='+[string]$cfg.StateRoot+'; Group='+[string]$cfg.Group+'; ParentPID='+[string]$cfg.ParentPID+'; ParentPath='+[string]$cfg.ParentPath+'; PowerShell='+$PSVersionTable.PSVersion.ToString()+'; PSHOME='+$PSHOME)

function Test-WatchdogParentReadyAcknowledgement{
  $ackPath=[string]$cfg.AuditLogPath+'.watchdog.parent_ready.json'
  if(-not (Test-Path -LiteralPath $ackPath)){return $false}
  try{
    $ack=Get-Content -Raw -LiteralPath $ackPath -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
    if([int]$ack.Schema -ne 1){return $false}
    if([string]$ack.Group -ne [string]$cfg.Group){return $false}
    if([int]$ack.ParentPID -ne [int]$cfg.ParentPID){return $false}
    if([string]::IsNullOrWhiteSpace([string]$cfg.WatchdogReadyToken) -or [string]$ack.Token -cne [string]$cfg.WatchdogReadyToken){return $false}
    $readyUtc=[DateTime]::Parse([string]$ack.ReadyUtc).ToUniversalTime()
    if($readyUtc -gt [DateTime]::UtcNow.AddSeconds(5) -or $readyUtc -lt [DateTime]::Parse([string]$cfg.SessionStartUtc).ToUniversalTime()){return $false}
    return $true
  }catch{
    Write-WatchdogStartupDiagnostic ('parent-ready acknowledgement is not valid yet: '+$_.Exception.Message)
    return $false
  }
}

__PERSISTENCE_FUNCTIONS__
__JAVA_PROCESS_FUNCTIONS__
function Get-FqdnCapability{
  $reasons=New-Object System.Collections.Generic.List[string]
  $dohWarnings=New-Object System.Collections.Generic.List[string]
  $build=0
  $productType=0
  $dynamicCommandParameters=@{
    'New-NetFirewallDynamicKeywordAddress'=@('Id','Keyword','AutoResolve')
    'Get-NetFirewallDynamicKeywordAddress'=@('Id')
    'Remove-NetFirewallDynamicKeywordAddress'=@('Id')
  }
  foreach($name in $dynamicCommandParameters.Keys){
    try{
      $dynamicCommand=Get-Command $name -ErrorAction Stop
      foreach($parameter in $dynamicCommandParameters[$name]){
        if(-not $dynamicCommand.Parameters.ContainsKey($parameter)){$reasons.Add($name+' 不支持参数 '+$parameter)}
      }
    }catch{$reasons.Add('缺少命令 '+$name)}
  }
  try{
    $cmd=Get-Command New-NetFirewallRule -ErrorAction Stop
    foreach($param in @('RemoteDynamicKeywordAddresses','Program','RemoteAddress','Protocol','RemotePort')){
      if(-not $cmd.Parameters.ContainsKey($param)){$reasons.Add('New-NetFirewallRule 不支持参数 '+$param)}
    }
  }catch{$reasons.Add('无法检查 New-NetFirewallRule 参数集')}
  try{
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $build=[int]$os.BuildNumber
    $productType=[int]$os.ProductType
    if($productType -eq 1){
      if($build -lt 19042){$reasons.Add('Windows 客户端 build '+$build+' 低于 Windows 10 20H2 FQDN 基线 19042')}
      elseif($build -le 19044){
        $cv=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $ubr=[int]$cv.UBR
        if($ubr -lt 1706){$reasons.Add('Windows 客户端 UBR '+$ubr+' 低于 KB5013942 支持基线 1706')}
      }
    }elseif($build -lt 14393){$reasons.Add('Windows Server build '+$build+' 低于 Server 2016 基线 14393')}
  }catch{$reasons.Add('无法确认 Windows build：'+$_.Exception.Message)}
  try{
    if(-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)){throw 'Get-MpComputerStatus 不可用'}
    $mp=Get-MpComputerStatus -ErrorAction Stop
    if(-not [bool]$mp.AMServiceEnabled -or -not [bool]$mp.AntivirusEnabled){$reasons.Add('Microsoft Defender Antivirus 未启用')}
    if([string]$mp.AMRunningMode -ne 'Normal'){$reasons.Add('Microsoft Defender Antivirus 不处于 Normal 活跃模式（当前：'+[string]$mp.AMRunningMode+'）')}
    if(-not [bool]$mp.RealTimeProtectionEnabled){$reasons.Add('Microsoft Defender Antivirus 实时保护未启用')}
    $platformText=[string]$mp.AMProductVersion
    if([string]::IsNullOrWhiteSpace($platformText)){throw 'AMProductVersion 为空'}
    $platform=[version]$platformText
    if($platform -lt [version]'4.18.2209.7'){$reasons.Add('Defender Antivirus 平台版本 '+$platform+' 低于 4.18.2209.7')}
  }catch{$reasons.Add('无法确认 Defender Antivirus 平台状态：'+$_.Exception.Message)}
  try{
    if(-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)){throw 'Get-MpPreference 不可用'}
    $pref=Get-MpPreference -ErrorAction Stop
    $np=[int]$pref.EnableNetworkProtection
    if($np -notin @(1,2)){$reasons.Add('Network Protection 未设置为 Block 或 Audit（当前值='+$np+'）')}
    if($productType -ne 1){
      if(-not [bool]$pref.AllowNetworkProtectionOnWinServer){$reasons.Add('Windows Server 未启用 AllowNetworkProtectionOnWinServer')}
      if($build -eq 14393 -and -not [bool]$pref.AllowNetworkProtectionDownLevel){$reasons.Add('Windows Server 2016 未启用 AllowNetworkProtectionDownLevel')}
    }
  }catch{$reasons.Add('无法确认 Network Protection 状态：'+$_.Exception.Message)}
  # Registry policies can identify known browser DoH settings, but absence of a
  # policy cannot prove that a user-level or app-managed resolver has DoH disabled.
  $policyRoots=@(
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
    'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
    'HKLM:\SOFTWARE\Policies\Google\Chrome',
    'HKCU:\SOFTWARE\Policies\Google\Chrome',
    'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS',
    'HKCU:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'
  )
  if($cfg.UserSID -match '^S-1-[0-9-]+$'){
    $callerHive='Registry::HKEY_USERS\'+[string]$cfg.UserSID+'\Software\Policies'
    $policyRoots+=@(
      ($callerHive+'\Microsoft\Edge'),
      ($callerHive+'\Google\Chrome'),
      ($callerHive+'\Mozilla\Firefox\DNSOverHTTPS')
    )
  }
  foreach($root in $policyRoots){
    if(-not (Test-Path -LiteralPath $root)){continue}
    try{
      if($root -match '\\DNSOverHTTPS$'){
        $enabled=Get-ItemProperty -LiteralPath $root -Name Enabled -ErrorAction SilentlyContinue
        if($null -ne $enabled -and [bool]$enabled.Enabled){$reasons.Add('检测到 Firefox DoH 策略启用：'+$root)}
        elseif($null -eq $enabled){$dohWarnings.Add('Firefox DoH 策略未明确关闭：'+$root)}
      }else{
        $mode=[string](Get-ItemProperty -LiteralPath $root -Name DnsOverHttpsMode -ErrorAction SilentlyContinue).DnsOverHttpsMode
        if($mode -and $mode -ine 'off'){$reasons.Add('检测到浏览器 DoH 策略启用（'+$root+'\\DnsOverHttpsMode='+$mode+'）')}
        elseif(-not $mode){$dohWarnings.Add('浏览器 DoH 未由策略明确关闭：'+$root)}
      }
    }catch{$dohWarnings.Add('无法读取浏览器 DoH 策略：'+$root)}
  }
  # Windows DNS Client may upgrade resolver traffic to DoH independently of browsers.
  try{
    if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){
      $systemDoh=@(Get-DnsClientDohServerAddress -ErrorAction Stop|Where-Object{[bool]$_.AutoUpgrade})
      if($systemDoh.Count -gt 0){$reasons.Add('检测到 Windows DNS Client DoH AutoUpgrade 已启用：'+(@($systemDoh|ForEach-Object{[string]$_.ServerAddress}) -join ', '))}
    }else{$dohWarnings.Add('Get-DnsClientDohServerAddress 不可用，无法读取 Windows DNS Client DoH 配置')}
  }catch{$dohWarnings.Add('无法读取 Windows DNS Client DoH 配置：'+$_.Exception.Message)}
  $dohWarnings.Add('浏览器/应用可能使用用户级或自带 DoH；GuardLauncher 无法完整枚举所有应用的 DNS 设置，必须人工确认 DoH 已关闭')
  $dohStatus='Unverified'
  if(@($reasons|Where-Object{$_ -match 'DoH'}).Count -gt 0){$dohStatus='Enabled'}
  return [pscustomobject]@{Available=($reasons.Count -eq 0);Reasons=@($reasons);DohStatus=$dohStatus;DohWarnings=@($dohWarnings)}
}
function Test-GuardDeny($path,$sid,[string]$InheritanceFlags='ContainerInherit,ObjectInherit'){
  try{$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$expected=[System.Security.AccessControl.InheritanceFlags]([Enum]::Parse([System.Security.AccessControl.InheritanceFlags],$InheritanceFlags,$true));foreach($ace in $acl.Access){if($ace.IsInherited -or $ace.AccessControlType -ne 'Deny'){continue};$aceSid='';try{$aceSid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$aceSid=[string]$ace.IdentityReference.Value};$rights=([Security.AccessControl.FileSystemRights]$ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl);if($aceSid -eq $sid -and $rights -eq [Security.AccessControl.FileSystemRights]::FullControl -and [System.Security.AccessControl.InheritanceFlags]$ace.InheritanceFlags -eq $expected -and $ace.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None){return $true}}}catch{};return $false
}

function Remove-GuardDeny($path,$sid,[string]$InheritanceFlags='ContainerInherit,ObjectInherit'){
  if(-not (Test-Path -LiteralPath $path)){Write-GuardLog('[restore-step] ACL path already absent; no ACE remains to remove: '+$path);return $true}
  try{
    $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
    if(-not (Test-GuardDeny $path $sid $InheritanceFlags)){
      # An absent exact ACE is already restored. A different explicit Deny for the same
      # SID may be a user change; do not delete it by guessing.
      foreach($ace in $acl.Access){
        if($ace.IsInherited -or $ace.AccessControlType -ne 'Deny'){continue}
        $aceSid='';try{$aceSid=$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$aceSid=[string]$ace.IdentityReference.Value}
        $rights=([Security.AccessControl.FileSystemRights]$ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl)
        if($aceSid -eq $sid -and $rights -eq [Security.AccessControl.FileSystemRights]::FullControl){throw '发现同一 SID 的显式 Deny ACE 与 Guard journal 标记不一致；为避免删除外部 ACE，停止自动移除'}
      }
      return $true
    }
    $flags=[System.Security.AccessControl.InheritanceFlags]([Enum]::Parse([System.Security.AccessControl.InheritanceFlags],$InheritanceFlags,$true))
    $exact=@($acl.Access|Where-Object{
      if($_.IsInherited -or $_.AccessControlType -ne 'Deny'){return $false}
      $aceSid='';try{$aceSid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{$aceSid=[string]$_.IdentityReference.Value}
      $rights=([Security.AccessControl.FileSystemRights]$_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl)
      return ($aceSid -eq $sid -and $rights -eq [Security.AccessControl.FileSystemRights]::FullControl -and [System.Security.AccessControl.InheritanceFlags]$_.InheritanceFlags -eq $flags -and $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None)
    })
    if($exact.Count -gt 1){throw '发现多个完全相同的显式 Deny ACE；无法区分 Guard 与外部新增项，为避免误删而保留 ACL'}
    if($exact.Count -eq 0){return $true}
    $rule=New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($sid)),[System.Security.AccessControl.FileSystemRights]::FullControl,$flags,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Deny)
    $acl.RemoveAccessRuleSpecific($rule)|Out-Null
    Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
    if(Test-GuardDeny $path $sid $InheritanceFlags){throw 'Guard Deny ACE remains after removal'}
    return $true
  }catch{Write-GuardLog('[acl] 无法移除 Guard Deny：'+$path+' flags='+$InheritanceFlags+' :: '+$_.Exception.Message);return $false}
}
function Add-GuardDeny($path,$sid,[string]$InheritanceFlags='ContainerInherit,ObjectInherit'){
  if(Test-GuardDeny $path $sid $InheritanceFlags){return $true}
  try{$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$flags=[System.Security.AccessControl.InheritanceFlags]([Enum]::Parse([System.Security.AccessControl.InheritanceFlags],$InheritanceFlags,$true));$rule=New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($sid)),[System.Security.AccessControl.FileSystemRights]::FullControl,$flags,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AccessControlType]::Deny);$acl.AddAccessRule($rule);Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop;return (Test-GuardDeny $path $sid $InheritanceFlags)}catch{Write-GuardLog('[acl] add failed path='+$path+' :: '+$_.Exception.ToString());return $false}
}
function Reapply-GuardACLs{
  Assert-AclJournalIntegrityOnce $cfg.StateDir|Out-Null
  $records=@(Get-AclJournalRecords $cfg.StateDir);[array]::Reverse($records)
  foreach($r in $records){if(-not [bool]$r.Added){continue};$path=[string]$r.Path;$sid=[string]$r.UserSID;$flags=Get-GuardInheritanceFlags $r;if(-not (Test-Path -LiteralPath $path)){Write-GuardLog('[acl] enforcement target disappeared: '+$path);continue};if(-not (Test-GuardProtectionEffective $path $sid)){if(-not (Add-GuardDeny $path $sid $flags)){throw ('无法重新施加 QQ/Tencent Deny ACL：'+$path)};if(-not (Test-GuardProtectionEffective $path $sid)){throw ('重新施加 ACL 后验证失败：'+$path)};Write-GuardLog('[acl] repaired missing QQ/Tencent deny: '+$path+' flags='+$flags)}}
}
function Get-ExpectedRuleCount{
  $programs=@(@($cfg.LauncherPath)+@($cfg.JavaPaths)|Where-Object{$_}|Select-Object -Unique)
  $activePath=Join-Path $cfg.StateDir 'active_endpoints.json'
  if(!(Test-Path -LiteralPath $activePath)){return -1}
  try{$active=@(Get-Content -Raw -LiteralPath $activePath -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop)}catch{return -1}
  return ($programs.Count*$active.Count)
}
function Test-ExactGuardAllowRule($rule,$program,$endpoint){
  try{
    if($rule.Direction.ToString() -ne 'Outbound' -or $rule.Action.ToString() -ne 'Allow' -or $rule.Enabled.ToString() -ne 'True' -or $rule.Profile.ToString() -ne 'Any'){return $false}
    if([bool]$rule.OverrideBlockRules){return $false}
    $app=$rule|Get-NetFirewallApplicationFilter -ErrorAction Stop
    $q=[string]$app.Program;try{$q=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($q)).ToLowerInvariant()}catch{$q=$q.ToLowerInvariant()}
    $wanted=[string]$program;try{$wanted=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($wanted)).ToLowerInvariant()}catch{$wanted=$wanted.ToLowerInvariant()}
    if($q -ne $wanted){return $false}
    if(-not [string]::IsNullOrWhiteSpace([string]$app.Package) -and [string]$app.Package -notin @('Any','<All>')){return $false}
    $ports=$rule|Get-NetFirewallPortFilter -ErrorAction Stop
    if([string]$ports.Protocol -ne 'TCP'){return $false}
    $rp=@($ports.RemotePort|ForEach-Object{[string]$_})
    if($rp.Count -ne 1 -or $rp[0] -ne [string]$endpoint.Port){return $false}
    $addr=$rule|Get-NetFirewallAddressFilter -ErrorAction Stop
    $la=@($addr.LocalAddress|ForEach-Object{[string]$_})
    if($la.Count -ne 1 -or $la[0] -ne 'Any'){return $false}
    if($endpoint.Mode -eq 'IP'){
      $actual=@($addr.RemoteAddress|ForEach-Object{[string]$_}|Sort-Object -Unique)
      $expected=@($endpoint.IPs|ForEach-Object{[string]$_}|Sort-Object -Unique)
      if($actual.Count -ne $expected.Count){return $false}
      for($i=0;$i -lt $actual.Count;$i++){if($actual[$i] -ne $expected[$i]){return $false}}
    }elseif($endpoint.Mode -eq 'FQDN'){
      $remote=@($addr.RemoteAddress|ForEach-Object{[string]$_})
      $remoteDynamic=@()
      foreach($source in @($rule,$addr)){
        $property=$source.PSObject.Properties['RemoteDynamicKeywordAddresses']
        if($null -ne $property -and $null -ne $property.Value){$remoteDynamic+=@($property.Value|ForEach-Object{[string]$_})}
      }
      $remoteDynamic=@($remoteDynamic|Where-Object{$_}|Select-Object -Unique)
      if($remote.Count -ne 1 -or $remote[0] -ne 'Any'){return $false}
      if($remoteDynamic.Count -ne 1 -or $remoteDynamic[0] -ine [string]$endpoint.DynamicId){return $false}
      $dynObjects=@(Get-NetFirewallDynamicKeywordAddress -Id ([string]$endpoint.DynamicId) -ErrorAction Stop)
      if($dynObjects.Count -ne 1 -or [string]$dynObjects[0].Keyword -ine [string]$endpoint.Host -or -not [bool]$dynObjects[0].AutoResolve){return $false}
    }else{return $false}
    return $true
  }catch{return $false}
}
function Firewall-Lock-Healthy{
  try{
    if(@(Get-NetFirewallProfile -PolicyStore ActiveStore|Where-Object{$_.DefaultOutboundAction.ToString() -ne 'Block' -or $_.Enabled.ToString() -ne 'True'}).Count -ne 0){return $false}
    $activePath=Join-Path $cfg.StateDir 'active_endpoints.json'
    if(!(Test-Path -LiteralPath $activePath)){return $false}
    $active=@(Get-Content -Raw -LiteralPath $activePath -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop)
    $programs=@(@($cfg.LauncherPath)+@($cfg.JavaPaths)|Where-Object{$_}|Select-Object -Unique)
    $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Group $cfg.Group -ErrorAction SilentlyContinue)
    $expected=$programs.Count*$active.Count
    if($expected -lt 0 -or $rules.Count -ne $expected){return $false}
    if($active.Count -eq 0){return ($rules.Count -eq 0)}
    foreach($program in $programs){foreach($endpoint in $active){if(@($rules|Where-Object{Test-ExactGuardAllowRule $_ $program $endpoint}).Count -ne 1){return $false}}}
    return $true
  }catch{return $false}
}
function Rebuild-FirewallRules{
  $activePath=Join-Path $cfg.StateDir 'active_endpoints.json'
  if(!(Test-Path -LiteralPath $activePath)){throw 'active_endpoints.json missing; cannot reconstruct exact allowlist'}
  $active=@(Get-Content -Raw -LiteralPath $activePath -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop)
  $programs=@(@($cfg.LauncherPath)+@($cfg.JavaPaths)|Where-Object{$_}|Select-Object -Unique)
  $dynPath=Join-Path $cfg.StateDir 'dynamic_keywords.json'
  $dyn=@{}
  if(Test-Path -LiteralPath $dynPath){
    $dynObject=Get-Content -Raw -LiteralPath $dynPath -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
    foreach($prop in $dynObject.PSObject.Properties){$dyn[[string]$prop.Name]=[string]$prop.Value}
  }
  $discardedDynamicIds=@($active|Where-Object{$_.Mode -eq 'FQDN'}|ForEach-Object{[string]$_.DynamicId})+@($dyn.Values)
  $discardedDynamicIds=@($discardedDynamicIds|Where-Object{$_}|Select-Object -Unique)
  $cap=Get-FqdnCapability
  if(-not $cap.Available){
    $active=@($active|Where-Object{$_.Mode -eq 'IP'})
    Write-GuardLog('[compat] Watchdog 重建前发现 FQDN 条件不可用；仅重建静态 IP 规则。默认 BLOCK 保持不变。原因：'+(@($cap.Reasons) -join '; '))
  }else{
    foreach($e in $active){
      if($e.Mode -eq 'FQDN'){
        $id=[string]$e.DynamicId
        $exists=$false
        if($id){
          try{
            $found=@(Get-NetFirewallDynamicKeywordAddress -Id $id -ErrorAction Stop)
            $exists=($found.Count -eq 1 -and [string]$found[0].Keyword -ieq [string]$e.Host -and [bool]$found[0].AutoResolve)
          }catch{}
        }
        if(-not $exists){
          if($id -and (Get-Command Remove-NetFirewallDynamicKeywordAddress -ErrorAction SilentlyContinue)){
            try{Remove-NetFirewallDynamicKeywordAddress -Id $id -ErrorAction Stop|Out-Null}catch{Write-GuardLog('[compat] 无法删除不匹配的旧 FQDN 对象：'+$id+' :: '+$_.Exception.Message)}
          }
          $id='{'+([guid]::NewGuid().ToString())+'}'
          $discardedDynamicIds+= $id
          $key=([string]$e.Host).ToLowerInvariant()+':'+([int]$e.Port)
          Save-PendingDynamicId $id
          $dyn[$key]=$id
          try{New-NetFirewallDynamicKeywordAddress -Id $id -Keyword ([string]$e.Host) -AutoResolve $true -ErrorAction Stop|Out-Null}
          catch{
            $dyn.Remove($key)
            Write-GuardLog('[compat] Watchdog 无法重建 FQDN 对象；将退回静态 IP 白名单：'+$e.Host+' :: '+$_.Exception.Message);$cap.Available=$false;break
          }
          $e.DynamicId=$id
        }
      }
    }
    if(-not $cap.Available){$active=@($active|Where-Object{$_.Mode -eq 'IP'})}
  }
  Write-AtomicJson $activePath ([object[]]$active) 6
  foreach($id in $dyn.Values){Save-PendingDynamicId ([string]$id)}
  Remove-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -Context 'Watchdog firewall rebuild' | Out-Null
  if(@(Get-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -PolicyStore 'ActiveStore').Count -ne 0){throw '无法清理旧 Guard 规则；停止 FQDN/静态 IP 重建以避免重复或残留 Allow'}
  $activeIds=@($active|Where-Object{$_.Mode -eq 'FQDN'}|ForEach-Object{[string]$_.DynamicId})
  Remove-PendingDynamicIds @($discardedDynamicIds|Where-Object{$_ -and $_ -notin $activeIds})
  foreach($program in $programs){
    foreach($e in @($active|Where-Object{$_.Mode -eq 'IP'})){
      $name="$($cfg.Group) ALLOW $([IO.Path]::GetFileName($program)) $($e.Host):$($e.Port)"
      New-NetFirewallRule -DisplayName $name -Group $cfg.Group -Direction Outbound -Action Allow -Program $program -RemoteAddress @($e.IPs) -Protocol TCP -RemotePort ([int]$e.Port) -Profile Any -ErrorAction Stop|Out-Null
    }
  }
  $fqdnFailure=$false
  try{
    foreach($program in $programs){
      foreach($e in @($active|Where-Object{$_.Mode -eq 'FQDN'})){
        $name="$($cfg.Group) ALLOW $([IO.Path]::GetFileName($program)) $($e.Host):$($e.Port)"
        New-NetFirewallRule -DisplayName $name -Group $cfg.Group -Direction Outbound -Action Allow -Program $program -RemoteDynamicKeywordAddresses ([string]$e.DynamicId) -Protocol TCP -RemotePort ([int]$e.Port) -Profile Any -ErrorAction Stop|Out-Null
      }
    }
  }catch{$fqdnFailure=$true;Write-GuardLog('[compat] Watchdog FQDN 规则重建失败；仅保留静态 IP 白名单。默认 BLOCK 保持不变。原因：'+$_.Exception.Message)}
  if($fqdnFailure){
    $failedIds=@($discardedDynamicIds|Where-Object{$_}|Select-Object -Unique)
    Remove-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -Context 'Watchdog firewall rebuild' | Out-Null
    if(@(Get-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -PolicyStore 'ActiveStore').Count -ne 0){throw 'FQDN 降级时无法清除 Guard 规则；保留原会话记录并停止重建'}
    $active=@($active|Where-Object{$_.Mode -eq 'IP'})
    Write-AtomicJson $activePath ([object[]]$active) 6
    Remove-PendingDynamicIds $failedIds
    foreach($program in $programs){foreach($e in $active){$name="$($cfg.Group) ALLOW $([IO.Path]::GetFileName($program)) $($e.Host):$($e.Port)";New-NetFirewallRule -DisplayName $name -Group $cfg.Group -Direction Outbound -Action Allow -Program $program -RemoteAddress @($e.IPs) -Protocol TCP -RemotePort ([int]$e.Port) -Profile Any -ErrorAction Stop|Out-Null}}
  }
  $expected=Get-ExpectedRuleCount
  $actual=@(Get-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -PolicyStore 'PersistentStore').Count
  if($expected -lt 0 -or $actual -ne $expected){throw "allowlist rebuild incomplete: expected=$expected actual=$actual"}
}
function Repair-DisabledAllowsFingerprintEscapes([string]$json){
  # v17.7-era journals can contain a Fingerprint JSON string with one or more
  # unescaped quotes. Repair only that final string property; never rewrite
  # names, Group values, booleans, or any other journal fields.
  $text=$json
  $repairCount=0
  $searchFrom=0
  while($true){
    $propertyAt=$text.IndexOf('"Fingerprint"',$searchFrom,[StringComparison]::OrdinalIgnoreCase)
    if($propertyAt -lt 0){break}
    $colonAt=$text.IndexOf(':',$propertyAt+13)
    if($colonAt -lt 0){throw 'disabled_allows.json has a malformed Fingerprint property'}
    $openAt=$text.IndexOf('"',$colonAt+1)
    if($openAt -lt 0){throw 'disabled_allows.json has no opening quote for Fingerprint'}
    $startAt=$openAt+1
    $closeAt=-1
    for($i=$startAt;$i -lt $text.Length;$i++){
      if($text[$i] -ne '"'){continue}
      $slashes=0
      for($k=$i-1;$k -ge $startAt -and $text[$k] -eq '\';$k--){$slashes++}
      if(($slashes % 2) -ne 0){continue}
      $j=$i+1
      while($j -lt $text.Length -and [char]::IsWhiteSpace($text[$j])){$j++}
      if($j -ge $text.Length -or $text[$j] -ne '}'){continue}
      $j++
      while($j -lt $text.Length -and [char]::IsWhiteSpace($text[$j])){$j++}
      if($j -eq $text.Length -or $text[$j] -eq ',' -or $text[$j] -eq ']'){$closeAt=$i;break}
    }
    if($closeAt -lt 0){throw 'disabled_allows.json Fingerprint is not the final property or has no safe string terminator; preserve journal'}
    $segment=$text.Substring($startAt,$closeAt-$startAt)
    $builder=New-Object System.Text.StringBuilder
    for($i=0;$i -lt $segment.Length;$i++){
      $ch=$segment[$i]
      if($ch -eq '"'){
        $slashes=0
        for($k=$i-1;$k -ge 0 -and $segment[$k] -eq '\';$k--){$slashes++}
        if(($slashes % 2) -eq 0){[void]$builder.Append('\');$repairCount++}
      }
      [void]$builder.Append($ch)
    }
    $escaped=$builder.ToString()
    if($escaped -cne $segment){$text=$text.Substring(0,$startAt)+$escaped+$text.Substring($closeAt)}
    $searchFrom=$startAt+$escaped.Length+1
  }
  return [pscustomobject]@{Json=$text;RepairCount=$repairCount}
}
function Read-DisabledAllowsJournal([string]$path){
  # Write-AtomicText writes UTF-8 without a BOM. Get-Content in Windows
  # PowerShell 5.1 defaults to the active ANSI code page, corrupting non-ASCII
  # rule display names and making fingerprint comparisons unreliable.
  $raw=[IO.File]::ReadAllText($path,[Text.Encoding]::UTF8)
  try{
    $parsed=ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    return ,@($parsed)
  }catch{
    $originalError=$_.Exception.Message
    $repair=Repair-DisabledAllowsFingerprintEscapes $raw
    if($repair.RepairCount -le 0){throw ('disabled_allows.json JSON parse failed and no safe Fingerprint-only repair applied: '+$originalError)}
    try{$parsed=ConvertFrom-Json -InputObject $repair.Json -ErrorAction Stop}
    catch{throw ('disabled_allows.json remains invalid after Fingerprint-only escape repair: '+$_.Exception.Message+'; original='+$originalError)}
    Write-GuardLog('[firewall-recovery] repaired legacy disabled_allows.json Fingerprint escaping only; insertedEscapes='+$repair.RepairCount+'; UTF-8 decoding used')
    return ,@($parsed)
  }
}
function Get-FirewallRuleRecoveryFingerprint($rule){
  $app=$rule|Get-NetFirewallApplicationFilter -ErrorAction Stop
  $addr=$rule|Get-NetFirewallAddressFilter -ErrorAction Stop
  $port=$rule|Get-NetFirewallPortFilter -ErrorAction Stop
  $service=$rule|Get-NetFirewallServiceFilter -ErrorAction Stop
  $iface=$rule|Get-NetFirewallInterfaceFilter -ErrorAction Stop
  $security=$rule|Get-NetFirewallSecurityFilter -ErrorAction Stop
  $dynamic=@()
  foreach($source in @($rule,$addr)){$property=$source.PSObject.Properties['RemoteDynamicKeywordAddresses'];if($null -ne $property -and $null -ne $property.Value){$dynamic+=@($property.Value|ForEach-Object{[string]$_})}}
  $value=[ordered]@{
    Name=[string]$rule.Name;DisplayName=[string]$rule.DisplayName;Group=[string]$rule.Group
    Direction=[string]$rule.Direction;Action=[string]$rule.Action;Profile=[string]$rule.Profile
    EdgeTraversalPolicy=[string]$rule.EdgeTraversalPolicy;OverrideBlockRules=[string]$rule.OverrideBlockRules
    PolicyStoreSourceType=[string]$rule.PolicyStoreSourceType;PolicyStoreSource=[string]$rule.PolicyStoreSource
    Program=[string]$app.Program;Package=[string]$app.Package
    LocalAddress=@($addr.LocalAddress|ForEach-Object{[string]$_}|Sort-Object)
    RemoteAddress=@($addr.RemoteAddress|ForEach-Object{[string]$_}|Sort-Object)
    RemoteDynamicKeywordAddresses=@($dynamic|Sort-Object -Unique)
    Protocol=[string]$port.Protocol
    LocalPort=@($port.LocalPort|ForEach-Object{[string]$_}|Sort-Object)
    RemotePort=@($port.RemotePort|ForEach-Object{[string]$_}|Sort-Object)
    Service=[string]$service.Service
    InterfaceAlias=@($iface.InterfaceAlias|ForEach-Object{[string]$_}|Sort-Object)
    InterfaceType=@($iface.InterfaceType|ForEach-Object{[string]$_}|Sort-Object)
    Authentication=[string]$security.Authentication;Encryption=[string]$security.Encryption
    LocalUser=[string]$security.LocalUser;RemoteUser=[string]$security.RemoteUser
    RemoteMachine=[string]$security.RemoteMachine;SecureFlags=[string]$security.SecureFlags
  }
  return ($value|ConvertTo-Json -Compress -Depth 6)
}
function Restore-DisabledAllows{
  $p=Join-Path $cfg.StateDir 'disabled_allows.json'
  if(!(Test-Path -LiteralPath $p)){
    if(Test-Path -LiteralPath (Join-Path $cfg.StateDir 'disabled_allows_apply_started')){throw 'disabled_allows.json is missing although user Allow changes were marked'}
    Write-GuardLog('[restore-step] SKIP Watchdog disabled user Allows: no journal/apply marker')
    return
  }
  foreach($x in @(Read-DisabledAllowsJournal $p)){
    if(-not $x.Name){continue}
    if($x.PSObject.Properties['WasEnabled'] -and -not [bool]$x.WasEnabled){Write-GuardLog('[watchdog] journal says original Allow rule was not enabled; do not enable: '+$x.Name);continue}
    $existing=@(Get-NetFirewallRule -Name ([string]$x.Name) -ErrorAction Stop)
    if($existing.Count -eq 0){Write-GuardLog('[watchdog] original Allow rule was deleted; not recreating: '+$x.Name);continue}
    if($existing.Count -ne 1){Write-GuardLog('[watchdog] original Allow rule name is no longer unique; skipping restore: '+$x.Name);continue}
    $rule=$existing[0]
    if($rule.Enabled -eq 'True'){Write-GuardLog('[watchdog] original Allow rule is already enabled: '+$x.Name);continue}
    if([string]::IsNullOrWhiteSpace([string]$x.Fingerprint)){
      Write-GuardLog('[watchdog] legacy Allow journal has no fingerprint; preserving disabled state: '+$x.Name)
      continue
    }
    if((Get-FirewallRuleRecoveryFingerprint $rule) -cne [string]$x.Fingerprint){
      Write-GuardLog('[watchdog] original Allow rule changed externally; preserving current disabled state: '+$x.Name)
      continue
    }
    Enable-NetFirewallRule -Name ([string]$x.Name) -ErrorAction Stop|Out-Null
    if(@(Get-NetFirewallRule -Name ([string]$x.Name) -ErrorAction Stop|Where-Object{$_.Enabled -eq 'True'}).Count -eq 0){throw ('failed to restore original Allow '+$x.Name)}
  }
}
function Is-BroadAllow($rule){
  try{
    $app=$rule|Get-NetFirewallApplicationFilter -ErrorAction Stop
    $program=[string]$app.Program; $package=[string]$app.Package
    $programAny=[string]::IsNullOrWhiteSpace($program) -or $program -in @('Any','<All>')
    $packageAny=[string]::IsNullOrWhiteSpace($package) -or $package -in @('Any','<All>')
    return ($programAny -and $packageAny)
  }catch{return $false}
}
function Save-DisabledAllow([object]$item){
  $p=Join-Path $cfg.StateDir 'disabled_allows.json'
  $all=New-Object System.Collections.Generic.List[object]
  if(Test-Path -LiteralPath $p){foreach($x in @(Read-DisabledAllowsJournal $p)){if($x.Name){$all.Add($x)}}}
  $seen=@{};foreach($x in $all){$seen[[string]$x.Name]=1}
  if($item.Name -and -not $seen.ContainsKey([string]$item.Name)){$all.Add($item)}
  Write-AtomicJson $p @($all.ToArray()) 6
  $marker=Join-Path $cfg.StateDir 'disabled_allows_apply_started'
  if(-not (Test-Path -LiteralPath $marker)){Write-AtomicText $marker ([DateTime]::UtcNow.ToString('o'))}
}
function Audit-AndDisableProgramAllows{
  $targets=@($cfg.LauncherPath)+@($cfg.JavaPaths)|Where-Object{$_}|ForEach-Object{$q=$_;try{[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($q)).ToLowerInvariant()}catch{$q.ToLowerInvariant()}}|Select-Object -Unique
  $rules=@(Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction Stop)
  foreach($r in $rules){
    if([string]$r.Group -eq [string]$cfg.Group){continue}
    try{
      if(Is-BroadAllow $r){
        $fingerprint=Get-FirewallRuleRecoveryFingerprint $r
        $item=[pscustomobject]@{Name=$r.Name;DisplayName=$r.DisplayName;Group=$r.Group;WasEnabled=$true;Fingerprint=$fingerprint}
        Save-DisabledAllow $item
        Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop|Out-Null
        Write-GuardLog('[watchdog] disabled broad outbound Allow: '+$r.DisplayName)
        continue
      }
      $app=$r|Get-NetFirewallApplicationFilter -ErrorAction Stop
      $program=[string]$app.Program
      if([string]::IsNullOrWhiteSpace($program)){continue}
      $np=$program.ToLowerInvariant();try{$np=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($program)).ToLowerInvariant()}catch{}
      if($targets -contains $np){
        $fingerprint=Get-FirewallRuleRecoveryFingerprint $r
        $item=[pscustomobject]@{Name=$r.Name;DisplayName=$r.DisplayName;Group=$r.Group;WasEnabled=$true;Fingerprint=$fingerprint}
        Save-DisabledAllow $item
        Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop|Out-Null
        Write-GuardLog('[watchdog] disabled conflicting Allow: '+$r.DisplayName)
      }
    }catch{throw ('unable to audit/disable outbound Allow rule '+$r.DisplayName+' :: '+$_.Exception.Message)}
  }
}
function Assert-NoUnmanagedActiveAllows{
  $targets=@($cfg.LauncherPath)+@($cfg.JavaPaths)|Where-Object{$_}|ForEach-Object{$q=$_;try{[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($q)).ToLowerInvariant()}catch{$q.ToLowerInvariant()}}|Select-Object -Unique
  $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow -Enabled True -ErrorAction Stop)
  foreach($r in $rules){
    if([string]$r.Group -eq [string]$cfg.Group){continue}
    if(Is-BroadAllow $r){throw ('ActiveStore contains unmanaged broad outbound Allow: '+$r.DisplayName)}
    $app=$r|Get-NetFirewallApplicationFilter -ErrorAction Stop
    $program=[string]$app.Program
    if([string]::IsNullOrWhiteSpace($program)){continue}
    $np=$program.ToLowerInvariant();try{$np=[IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($program)).ToLowerInvariant()}catch{}
    if($targets -contains $np){throw ('ActiveStore contains unmanaged Allow for launcher/Java: '+$r.DisplayName)}
  }
}
function Remove-UnavailableFqdnTargets{
  $activePath=Join-Path $cfg.StateDir 'active_endpoints.json'
  if(!(Test-Path -LiteralPath $activePath)){return}
  $active=@(Get-Content -Raw -LiteralPath $activePath -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop)
  $fqdn=@($active|Where-Object{$_.Mode -eq 'FQDN'})
  if($fqdn.Count -eq 0){return}
  $cap=Get-FqdnCapability
  if($cap.Available){return}
  $ipOnly=@($active|Where-Object{$_.Mode -eq 'IP'})
  $ids=@($fqdn|ForEach-Object{[string]$_.DynamicId}|Where-Object{$_})
  $dynPath=Join-Path $cfg.StateDir 'dynamic_keywords.json'
  if(Test-Path -LiteralPath $dynPath){
    try{$dyn=Get-Content -Raw -LiteralPath $dynPath -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop;foreach($prop in $dyn.PSObject.Properties){if($prop.Value){$ids+=([string]$prop.Value)}}}catch{Write-GuardLog('[compat] 无法读取待清理的动态 FQDN 对象清单：'+$_.Exception.Message)}
  }
  Remove-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -Context 'Watchdog firewall rebuild' | Out-Null
  if(@(Get-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -PolicyStore 'ActiveStore').Count -ne 0){throw 'FQDN 前置条件变化后仍有 Guard 规则残留；保留会话记录并停止降级'}
  Write-AtomicJson $activePath ([object[]]$ipOnly) 6
  Remove-PendingDynamicIds $ids
  Write-GuardLog('[compat] FQDN 前置条件在会话期间不再满足；已移除 FQDN 放行项，仅保留静态 IP 白名单。默认出站 BLOCK 保持不变。原因：'+(@($cap.Reasons) -join '; '))
}
function Ensure-Firewall{
  Remove-UnavailableFqdnTargets
  Audit-AndDisableProgramAllows
  Assert-NoUnmanagedActiveAllows
  if(@(Get-NetFirewallProfile|Where-Object{$_.DefaultOutboundAction.ToString() -ne 'Block' -or $_.Enabled.ToString() -ne 'True'}).Count -ne 0){
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultOutboundAction Block -ErrorAction Stop
    Write-GuardLog('[watchdog] local Windows Firewall profile state was reasserted')
  }
  $effectiveProfiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
  if($effectiveProfiles.Count -lt 3 -or @($effectiveProfiles|Where-Object{$_.DefaultOutboundAction.ToString() -ne 'Block' -or $_.Enabled.ToString() -ne 'True'}).Count -ne 0){
    throw 'ActiveStore effective firewall profile is not enabled with default outbound BLOCK; an external policy may override local settings'
  }
  if(-not (Firewall-Lock-Healthy)){
    Rebuild-FirewallRules
    if(-not (Firewall-Lock-Healthy)){throw 'ActiveStore still does not enforce the exact Guard allowlist after reconstruction; local rules may be ignored by policy merge'}
    Write-GuardLog('[watchdog] exact outbound allow rules were reconstructed and verified in ActiveStore')
  }
}
function Restore-Profiles{
  $p=Join-Path $cfg.StateDir 'profiles.json'
  if(!(Test-Path -LiteralPath $p)){
    if(Test-Path -LiteralPath (Join-Path $cfg.StateDir 'firewall_profile_apply_started')){throw 'profiles.json is missing although firewall_profile_apply_started exists'}
    Write-GuardLog('[restore-step] SKIP Watchdog firewall profiles: no baseline/apply marker')
    return
  }
  $s=Get-Content -Raw -LiteralPath $p -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
  foreach($n in @('Domain','Private','Public')){
    $entry=$s.$n
    if($null -eq $entry){continue}
    if($entry -is [string]){$expectedAction=[string]$entry;$expectedEnabled=$null}
    else{$expectedAction=[string]$entry.DefaultOutboundAction;$expectedEnabled=[string]$entry.Enabled}
    if(-not $expectedAction){continue}
    $current=Get-NetFirewallProfile -Profile $n -ErrorAction Stop
    $stillGuardState=($current.DefaultOutboundAction.ToString() -eq 'Block')
    if($null -ne $expectedEnabled){$stillGuardState=$stillGuardState -and ($current.Enabled.ToString() -eq 'True')}
    if(-not $stillGuardState){
      Write-GuardLog('[watchdog] preserving profile changed outside Guard state: '+$n+' action='+$current.DefaultOutboundAction+' enabled='+$current.Enabled)
      continue
    }
    if($null -ne $expectedEnabled){
      $enabledParameter=(Get-Command Set-NetFirewallProfile -ErrorAction Stop).Parameters['Enabled']
      if($null -eq $enabledParameter){throw 'Set-NetFirewallProfile has no Enabled parameter; preserve profile journal'}
      $enabledType=$enabledParameter.ParameterType
      if($enabledType.IsEnum){try{$enabledValue=[Enum]::Parse($enabledType,[string]$expectedEnabled,$true)}catch{throw ('Firewall profile Enabled baseline is not a valid '+$enabledType.FullName+' value: '+$expectedEnabled)}}
      else{if([string]$expectedEnabled -notin @('True','False','NotConfigured')){throw ('Unsupported firewall Enabled baseline: '+$expectedEnabled)};$enabledValue=[string]$expectedEnabled}
      Set-NetFirewallProfile -Profile $n -DefaultOutboundAction $expectedAction -Enabled $enabledValue -ErrorAction Stop
    }
    else{Set-NetFirewallProfile -Profile $n -DefaultOutboundAction $expectedAction -ErrorAction Stop}
    $after=Get-NetFirewallProfile -Profile $n -ErrorAction Stop
    if($after.DefaultOutboundAction.ToString() -ne $expectedAction){throw ('profile restore mismatch: '+$n+' expected='+$expectedAction+' actual='+$after.DefaultOutboundAction)}
    if($null -ne $expectedEnabled -and $after.Enabled.ToString() -ne $expectedEnabled){throw ('firewall enable-state restore mismatch: '+$n+' expected='+$expectedEnabled+' actual='+$after.Enabled)}
  }
}
function Restore-Audit{
  Restore-AuditStateFromPath (Join-Path $cfg.StateDir 'audit_policy.json')
}
function Remove-DynamicKeywords{
  Assert-DynamicCleanupComplete (Join-Path $cfg.StateDir 'dynamic_keywords.json')
}
function Restore-GuardACLs{
  $records=@(Get-AclJournalRecords $cfg.StateDir -Refresh)
  $legacy=Join-Path $cfg.StateDir 'protected_paths.txt'
  $hasManifest=Test-AclJournalManifest $cfg.StateDir
  if($records.Count -eq 0 -and (Test-Path -LiteralPath $legacy) -and -not $hasManifest){throw 'legacy ACL path list has no ACE provenance; automatic removal is unsafe'}
  if($records.Count -eq 0 -and $hasManifest){Write-GuardLog('[acl] current schema manifest confirms empty journal; no Guard-added ACEs require removal')}
  $results=New-Object System.Collections.Generic.List[object]
  $processed=0
  foreach($r in $records){
    if(-not [bool]$r.Added){continue}
    $record=$r;$flags=Get-GuardInheritanceFlags $record
    $results.Add((Invoke-LoggedRecoveryStep ('ACL remove '+[string]$record.Path) {if(-not (Remove-GuardDeny ([string]$record.Path) ([string]$record.UserSID) $flags)){throw ('ACL restore failed: '+[string]$record.Path)}} -QuietSuccess))
    $processed++
    if(($processed % 500) -eq 0){Write-GuardLog('[acl-restore] Watchdog progress processed='+$processed+' total_journal_records='+$records.Count)}
  }
  if(-not (Write-SessionRecoverySummary 'Tencent ACL restoration' @($results.ToArray()))){throw 'one or more Tencent ACL restore steps failed'}
}
function Remove-Fw{
  Write-AtomicText (Join-Path $cfg.StateDir 'firewall_cleanup_started') ([DateTime]::UtcNow.ToString('o'))
  $results=New-Object System.Collections.Generic.List[object]
  $rulesResult=Invoke-LoggedRecoveryStep 'firewall-rules-remove' {
    Remove-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -Context 'Watchdog firewall restore' | Out-Null
    $remaining=@(Get-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -PolicyStore 'ActiveStore')
    if($remaining.Count -ne 0){throw ('Guard ActiveStore firewall rules remain after removal: '+$remaining.Count)}
  }
  $results.Add($rulesResult)
  if($rulesResult.Success){
    $results.Add((Invoke-LoggedRecoveryStep 'firewall-dynamic-keywords-remove' {Remove-DynamicKeywords}))
    $results.Add((Invoke-LoggedRecoveryStep 'firewall-disabled-user-allows-restore' {Restore-DisabledAllows}))
    $results.Add((Invoke-LoggedRecoveryStep 'firewall-profiles-restore' {Restore-Profiles}))
  }else{
    foreach($deferred in @('firewall-dynamic-keywords-remove','firewall-disabled-user-allows-restore','firewall-profiles-restore')){
      Write-GuardLog('[restore-step] DEFERRED '+$deferred+' because Guard rules remain; preserving BLOCK state')
      $results.Add([pscustomobject]@{Name=$deferred;Success=$false;Error='Guard firewall rules remain; unsafe to relax'})
    }
  }
  $results.Add((Invoke-LoggedRecoveryStep 'audit-5157-restore' {Restore-Audit}))
  if(-not (Write-SessionRecoverySummary 'firewall restoration' @($results.ToArray()))){throw 'firewall restoration incomplete; state retained for retry'}
}
function Get-ProtectedPids{
  $state=Get-SessionProcessState $cfg
  $hits=@(@($state.LauncherProcesses | ForEach-Object {[int]$_.ProcessId}) + @($state.JavaProcesses | ForEach-Object {[int]$_.ProcessId}))
  return @($hits | Sort-Object -Unique)
}
function Parse-EventPid([string]$s){
  $s=([string]$s).Trim()
  [int64]$n=0
  if([int64]::TryParse($s,[Globalization.NumberStyles]::Integer,[Globalization.CultureInfo]::InvariantCulture,[ref]$n)){ return $n }
  if($s.StartsWith('0x',[System.StringComparison]::OrdinalIgnoreCase)){$s=$s.Substring(2)}
  try{return [Convert]::ToInt64($s,16)}catch{return -1}
}
function ProtocolName([string]$p){ switch($p){ '6'{'TCP';break}; '17'{'UDP';break}; '1'{'ICMP';break}; '58'{'ICMPv6';break}; default { '协议 '+$p } } }
$script:lastWfpRecordId=0
function Read-BlockedOutboundConnections{
  if(-not (Test-Path -LiteralPath (Join-Path $cfg.StateDir 'audit_policy.json'))){ return }
  try{
    $tracked=@{}; foreach($trackedProcessId in (Get-ProtectedPids)){ $tracked[[int64]$trackedProcessId]=1 }
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=5157;StartTime=(Get-Date).AddSeconds(-3)} -MaxEvents 64 -ErrorAction SilentlyContinue | Sort-Object RecordId)
    foreach($ev in $events){
      [int64]$rid=$ev.RecordId
      if($rid -le $script:lastWfpRecordId){ continue }
      $script:lastWfpRecordId=$rid
      [xml]$xml=$ev.ToXml(); $d=@{}
      foreach($x in $xml.Event.EventData.Data){ $d[[string]$x.Name]=[string]$x.'#text' }
      if($d['Direction'] -ne '%%14593'){ continue }
      [int64]$eventProcessId=Parse-EventPid([string]$d['ProcessID'])
      if($eventProcessId -lt 0 -or -not $tracked.ContainsKey($eventProcessId)){ continue }
      $app=[string]$d['Application']; $appName=$app
      if($appName -match '\\([^\\]+)$'){ $appName=$Matches[1] }
      $obj=[pscustomobject]@{ type='firewall_block'; time=$ev.TimeCreated.ToString('o'); recordId=$rid; pid=$eventProcessId; application=$appName; destination=[string]$d['DestAddress']; destPort=[string]$d['DestPort']; protocol=(ProtocolName ([string]$d['Protocol'])); filterRtId=[string]$d['FilterRTID'] }
      Write-GuardLog('[firewall-block] '+$appName+' PID='+$eventProcessId+' -> '+$d['DestAddress']+':'+$d['DestPort']+' '+(ProtocolName ([string]$d['Protocol'])) )
      Write-Notification $obj
    }
  }catch{ Write-GuardLog('[audit] 读取 5157 事件失败：'+$_.Exception.Message) }
}
try{
  Write-WatchdogStartupDiagnostic 'attempting to acquire global session lease'
  Acquire-SessionLease -TimeoutSeconds 45 -Owner 'Watchdog'
  Write-WatchdogStartupDiagnostic 'global session lease acquired'
  Write-GuardLog('[watchdog] session lease acquired; process ownership confirmed PID='+$PID)
  Write-WatchdogStartupDiagnostic 'attempting first durable heartbeat write'
  Write-SessionHeartbeat 'Starting' 'Watchdog acquired the global session lease'
  Write-WatchdogStartupDiagnostic 'first durable heartbeat committed successfully'
$resumeRequestedPath=Join-Path $cfg.StateDir 'watchdog.resume_requested'
if(Test-Path -LiteralPath $resumeRequestedPath){$noTargetGraceSeconds=5;Remove-Item -LiteralPath $resumeRequestedPath -Force -ErrorAction SilentlyContinue;Write-GuardLog('[watchdog] restart mode: no-target recovery grace after parent exit is 5 seconds')}else{$noTargetGraceSeconds=60}
$sessionDeadline=[DateTime]::UtcNow.AddSeconds($noTargetGraceSeconds)
$lastJavaIdentitySignature=''; $lastAudit=(Get-Date).AddSeconds(-30)
$targetSeen=$false; $lastTargetActivity=Get-Date
$lastParentAlive=$null
$parentFallbackLogged=$false
$parentExitGraceStarted=$false
$parentReadyAcknowledged=$false
$parentReadyLogged=$false
$finalParentState=$null
:WatchdogLoop while($true){
  Write-SessionHeartbeat 'Monitoring' 'Watchdog loop active; collecting process state'
  # One attributed process snapshot; unrelated Java/Gradle/IDE processes are excluded.
  # If WMI cannot provide a reliable snapshot, retain protection and retry instead of cleaning up.
  $processState=$null
  try{$processState=Get-SessionProcessState $cfg}
  catch{Write-GuardLog('[watchdog] 无法可靠识别本会话进程；不执行退出清理，稍后重试：'+$_.Exception.Message)}
  $lpids=@(); $javaPids=@(); $javaAlive=$false; $parentAlive=$false
  if($null -ne $processState){
    $parentAlive=[bool]$processState.ParentAlive
    if([bool]$processState.ParentIdentityUnverified){
      if(-not $script:parentIdentityUnverifiedLogged){Write-GuardLog('[process] GuardLauncher parent PID exists with creation time before session, but image path could not be verified; conservatively treating parent as alive. ParentPID='+[int]$cfg.ParentPID+' ExpectedPath='+[string]$cfg.ParentPath);$script:parentIdentityUnverifiedLogged=$true}
    }else{$script:parentIdentityUnverifiedLogged=$false}
    if([bool]$processState.ParentPathMatchedByName){
      if(-not $parentFallbackLogged){Write-GuardLog('[process] GuardLauncher parent accepted by PID + creation-time + exact basename compatibility fallback; ParentPID='+[int]$cfg.ParentPID);$parentFallbackLogged=$true}
    }else{$parentFallbackLogged=$false}
    if($null -eq $lastParentAlive -or $lastParentAlive -ne $parentAlive){
      Write-GuardLog('[process] GuardLauncher parent identity state changed ParentAlive='+$parentAlive+' ParentPID='+[int]$cfg.ParentPID+' ParentPath='+[string]$cfg.ParentPath+' ParentLeaseState='+[string]$processState.ParentLeaseState+' ParentProbeState='+[string]$processState.ParentProbeState)
      $lastParentAlive=$parentAlive
    }
    $lpids=@($processState.LauncherProcesses | ForEach-Object {[int]$_.ProcessId} | Select-Object -Unique)
    $javaPids=@($processState.JavaProcesses | ForEach-Object {[int]$_.ProcessId} | Select-Object -Unique)
    $javaAlive=($javaPids.Count -gt 0)
    $javaIdentitySignature=@($processState.JavaProcesses | Sort-Object ProcessId | ForEach-Object {
      $created=[DateTime]$_.CreationDate
      ('PID='+[int]$_.ProcessId+';CreatedUtc='+$created.ToUniversalTime().ToString('o')+';Image='+[string]$_.ExecutablePath)
    }) -join ' || '
    if($javaIdentitySignature -ne $lastJavaIdentitySignature){
      if($javaIdentitySignature){Write-GuardLog('[process] attributed Minecraft Java process(es): '+$javaIdentitySignature)}
      elseif($lastJavaIdentitySignature){Write-GuardLog('[process] all attributed Minecraft Java processes exited')}
      $lastJavaIdentitySignature=$javaIdentitySignature
    }
  }
  if($null -ne $processState){try{Sync-SessionJavaPaths $processState}catch{Write-GuardLog('[java-runtime] 精确规则同步失败，继续 BLOCK 并重试：'+$_.Exception.Message)}}
  if($cfg.Strict){ Read-BlockedOutboundConnections }
  if(((Get-Date)-$lastAudit).TotalSeconds -ge 5){
    try{if($cfg.Strict){Ensure-Firewall};Reapply-GuardACLs}
    catch{$detail=$_.Exception.ToString();if($_.ScriptStackTrace){$detail+=' | ScriptStackTrace='+$_.ScriptStackTrace};Write-GuardLog('[watchdog] periodic enforcement failed; will retry: '+($detail -replace '\r?\n',' | '))}
    $lastAudit=Get-Date
  }
  # Keep periodic enforcement running above, but never infer that all targets exited
  # from an unavailable WMI snapshot.
  if($null -eq $processState){Write-SessionHeartbeat 'Monitoring' 'Process attribution unavailable; protection retained and retrying';Start-Sleep -Seconds 5;continue}
  Write-SessionHeartbeat 'Monitoring' 'Process attribution completed; protection active'
  if($lpids.Count -gt 0 -or $javaAlive){$targetSeen=$true;$lastTargetActivity=Get-Date}

  # Explicit startup hand-off: before the Go parent verifies the heartbeat and
  # writes this acknowledgement, the Watchdog must not restore or delete StateDir.
  # This closes the race where an incorrect/temporarily missing parent identity
  # could make a new session look abandoned before initial readiness is checked.
  if(-not $parentReadyAcknowledged){
    $parentReadyAcknowledged=Test-WatchdogParentReadyAcknowledgement
    if($parentReadyAcknowledged){
      if(-not $parentReadyLogged){Write-GuardLog('[watchdog] parent startup acknowledgement verified; normal lifecycle cleanup is now permitted');$parentReadyLogged=$true}
    }else{
      if($parentAlive){
        if($parentExitGraceStarted){Write-GuardLog('[watchdog] parent returned before startup acknowledgement; canceling orphan grace');$parentExitGraceStarted=$false}
        Write-SessionHeartbeat 'Monitoring' 'Waiting for GuardLauncher parent-ready acknowledgement; protection retained'
        Start-Sleep -Seconds 1
        continue
      }
      if(-not $parentExitGraceStarted){
        $sessionDeadline=[DateTime]::UtcNow.AddSeconds([double]$noTargetGraceSeconds)
        $parentExitGraceStarted=$true
        Write-GuardLog('[watchdog] parent exited before startup acknowledgement; starting '+$noTargetGraceSeconds+'-second orphan recovery grace')
      }
      $targetQuiet=($targetSeen -and (((Get-Date)-$lastTargetActivity).TotalSeconds -ge 30))
      if(([DateTime]::UtcNow -gt $sessionDeadline) -and (-not $targetSeen -or $targetQuiet)){
        # Re-check the acknowledgement and parent immediately before allowing cleanup.
        $parentReadyAcknowledged=Test-WatchdogParentReadyAcknowledgement
        if($parentReadyAcknowledged){
          Write-GuardLog('[watchdog] parent-ready acknowledgement arrived at final cleanup gate; returning to normal monitoring')
          $parentReadyLogged=$true
          $parentExitGraceStarted=$false
          continue WatchdogLoop
        }
        $finalParentState=Get-SessionProcessState $cfg
        if([bool]$finalParentState.ParentAlive){
          Write-GuardLog('[watchdog] final cleanup gate blocked: parent is still alive; ParentLeaseState='+[string]$finalParentState.ParentLeaseState+' ParentProbeState='+[string]$finalParentState.ParentProbeState+'; restarting orphan grace')
          $parentExitGraceStarted=$false
          Write-SessionHeartbeat 'Monitoring' 'Final parent-liveness gate detected a live parent; protection retained'
          continue WatchdogLoop
        }
        Write-GuardLog('[watchdog] parent-ready acknowledgement absent; fresh parent-exit verification passed; automatic recovery allowed; ParentLeaseState='+[string]$finalParentState.ParentLeaseState+' ParentProbeState='+[string]$finalParentState.ParentProbeState)
        break
      }
      Write-SessionHeartbeat 'Monitoring' 'Parent acknowledgement absent; parent exited, recovery grace active; protection retained'
      Start-Sleep -Seconds 1
      continue
    }
  }

  # Once a Minecraft target has appeared, its own process activity controls shutdown;
  # the GuardLauncher parent may legitimately remain alive while waiting for cleanup.
  if($targetSeen){
    $parentExitGraceStarted=$false
    # Give launchers a short hand-off window to spawn Java after exiting.
    if(((Get-Date)-$lastTargetActivity).TotalSeconds -ge 30){break}
  }else{
    # Before any Minecraft target appears, GuardLauncher itself owns the startup
    # transaction. Never restore/delete session state while its parent is alive.
    # Start the no-target grace period only after that exact parent process exits.
    if($parentAlive){
      if($parentExitGraceStarted){Write-GuardLog('[watchdog] GuardLauncher parent reappeared; canceling no-target exit grace');$parentExitGraceStarted=$false}
      Write-SessionHeartbeat 'Monitoring' 'Waiting for Minecraft launcher; GuardLauncher parent is still alive, protection retained'
    }else{
      if(-not $parentExitGraceStarted){
        $sessionDeadline=[DateTime]::UtcNow.AddSeconds([double]$noTargetGraceSeconds)
        $parentExitGraceStarted=$true
        Write-GuardLog('[watchdog] no Minecraft target appeared and GuardLauncher parent exited; starting '+$noTargetGraceSeconds+'-second recovery grace')
      }
      if([DateTime]::UtcNow -gt $sessionDeadline){
        if(-not $targetSeen){
          $finalParentState=Get-SessionProcessState $cfg
          if([bool]$finalParentState.ParentAlive){
            Write-GuardLog('[watchdog] final no-target cleanup gate blocked: GuardLauncher parent is alive; ParentLeaseState='+[string]$finalParentState.ParentLeaseState+' ParentProbeState='+[string]$finalParentState.ParentProbeState+'; restarting grace')
            $parentExitGraceStarted=$false
            Write-SessionHeartbeat 'Monitoring' 'Final no-target gate detected a live parent; protection retained'
            continue WatchdogLoop
          }
        }
        break
      }
    }
  }
  Start-Sleep -Seconds 1
}
Write-GuardLog('[watchdog] protected processes exited; restoring state')
Write-SessionHeartbeat 'Restoring' 'Protected Minecraft processes exited; restoration started'
$cleanupSucceeded=$false
for($attempt=1;$attempt -le 3;$attempt++){
  try{
    Write-GuardLog('[restore] attempt '+$attempt+' started')
    Write-SessionHeartbeat 'RecoveryRetry' ('Restoration attempt '+$attempt+' started')
    $attemptResults=New-Object System.Collections.Generic.List[object]
    if($cfg.Strict){$attemptResults.Add((Invoke-LoggedRecoveryStep 'firewall-all' {Remove-Fw}))}
    $attemptResults.Add((Invoke-LoggedRecoveryStep 'tencent-acl-all' {Restore-GuardACLs}))
    $remainingRules=@(Get-GuardFirewallRulesByGroup -Group ([string]$cfg.Group) -PolicyStore 'ActiveStore')
    if($remainingRules.Count -ne 0){$attemptResults.Add([pscustomobject]@{Name='firewall-rule-postcheck';Success=$false;Error=('remaining rules='+$remainingRules.Count)})}
    $cleanupSucceeded=Write-SessionRecoverySummary ('Watchdog restoration attempt '+$attempt) @($attemptResults.ToArray())
    if($cleanupSucceeded){
      Write-GuardLog('[watchdog] restoration attempt '+$attempt+' completed all independent firewall and ACL groups')
      Write-SessionHeartbeat 'Restored' 'All current restoration steps reported success'
      break
    }
    $attemptError=(@($attemptResults|Where-Object{-not $_.Success}|ForEach-Object{$_.Name+': '+$_.Error}) -join ' | ')
    Write-GuardLog('[watchdog] cleanup attempt '+$attempt+' incomplete; recovery state retained: '+$attemptError)
    try{Write-SessionHeartbeat 'RecoveryFailed' ('attempt '+$attempt+': '+$attemptError)}catch{Write-GuardLog('[heartbeat] failed to persist recovery failure status: '+$_.Exception.Message)}
    if($attempt -lt 3){Start-Sleep -Seconds 5}
  }catch{
    $attemptError=$_.Exception.ToString()
    if($_.ScriptStackTrace){$attemptError+=' | ScriptStackTrace='+$_.ScriptStackTrace}
    Write-GuardLog('[watchdog] restoration attempt '+$attempt+' raised an unexpected error; state retained: '+($attemptError -replace '\r?\n',' | '))
    try{Write-SessionHeartbeat 'RecoveryFailed' ('attempt '+$attempt+': '+$_.Exception.Message)}catch{Write-GuardLog('[heartbeat] failed to persist recovery exception: '+$_.Exception.Message)}
    if($attempt -lt 3){Start-Sleep -Seconds 5}
  }
}
if($cleanupSucceeded){
  try{
    $deleteParentState=$processState
    if($null -ne $finalParentState){$deleteParentState=$finalParentState}
    $deleteParentLeaseState='NotAvailable';$deleteParentProbeState='NotAvailable';$deleteParentAlive='NotAvailable'
    if($null -ne $deleteParentState){
      $deleteParentLeaseState=[string]$deleteParentState.ParentLeaseState
      $deleteParentProbeState=[string]$deleteParentState.ParentProbeState
      $deleteParentAlive=[string][bool]$deleteParentState.ParentAlive
    }
    Write-GuardLog('[watchdog] STATE_DIR_DELETE_BEGIN path='+$cfg.StateDir+' group='+$cfg.Group+' parentReadyAcknowledged='+$parentReadyAcknowledged+' targetSeen='+$targetSeen+' parentPID='+[int]$cfg.ParentPID+' parentLeaseState='+$deleteParentLeaseState+' parentProbeState='+$deleteParentProbeState+' parentAlive='+$deleteParentAlive)
    Remove-Item -LiteralPath $cfg.StateDir -Recurse -Force -ErrorAction Stop
    Write-GuardLog('[watchdog] RESTORE COMPLETE; every recovery group verified and session state directory removed')
  }catch{Write-GuardLog('[watchdog] restoration succeeded, but state-directory removal failed; retained for cleanup: '+$_.Exception.ToString()+' | ScriptStackTrace='+$_.ScriptStackTrace)}
}else{
  Write-GuardLog('[watchdog] IMPORTANT: automatic restoration is incomplete; state directory retained for stale-session recovery: '+$cfg.StateDir)
}
}catch{
  try{Write-WatchdogStartupDiagnostic ('FATAL lifecycle failure: '+$_.Exception.ToString()+'; ScriptStackTrace='+$_.ScriptStackTrace)}catch{}
  try{Write-GuardLog('[watchdog] FATAL lifecycle failure: '+$_.Exception.ToString()+'; stack='+$_.ScriptStackTrace)}catch{}
  try{Write-SessionHeartbeat 'Failed' $_.Exception.Message}catch{}
  throw
}finally{
  Release-SessionLease
}
`

const javaProcessProbeScript = `
$ErrorActionPreference='Stop'
$session=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SESSION_B64__')) | ConvertFrom-Json
__JAVA_PROCESS_FUNCTIONS__
$state=Get-SessionProcessState $session
if($state.NativeFallback -and @($state.JavaProcesses).Count -gt 0){'UNKNOWN_ALIVE'}elseif(@($state.JavaProcesses).Count -gt 0){'YES'}else{'NO'}
`

func psEncoded(s string) string {
	// PowerShell -EncodedCommand is UTF-16LE base64.
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u16)*2)
	for _, u := range u16 {
		b = append(b, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func hashFileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:]), nil
}

func psSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func normalizePSDiagnostic(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	lines := strings.Split(s, "\n")
	clean := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.Contains(line, "#< CLIXML") || strings.HasPrefix(strings.TrimSpace(line), "<Objs ") || strings.HasPrefix(strings.TrimSpace(line), "<S ") {
			continue
		}
		clean = append(clean, line)
	}
	return strings.TrimSpace(strings.Join(clean, "\n"))
}

func writeUTF8BOMFile(path string, content string, perm os.FileMode) error {
	b := make([]byte, 0, len(content)+3)
	b = append(b, 0xEF, 0xBB, 0xBF)
	b = append(b, []byte(content)...)
	return os.WriteFile(path, b, perm)
}

// powershellExePath deliberately resolves Windows PowerShell from the Windows system
// directory instead of PATH. The helper is later launched elevated; trusting a
// PATH-resolved powershell.exe would allow a writable PATH entry to substitute the
// executable used for privileged firewall/ACL changes.
func powershellExePath() (string, error) {
	// Query the OS system directory through kernel32 instead of trusting PATH,
	// SystemRoot, or WINDIR inherited from the launching environment.
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getSystemDirectory := kernel32.NewProc("GetSystemDirectoryW")
	buf := make([]uint16, 32768)
	n, _, callErr := getSystemDirectory.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		if callErr != syscall.Errno(0) {
			return "", fmt.Errorf("GetSystemDirectoryW failed: %w", callErr)
		}
		return "", errors.New("GetSystemDirectoryW returned an invalid system directory")
	}
	systemDir := syscall.UTF16ToString(buf[:n])
	path := filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe")
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("Windows PowerShell not found at system path %q: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("Windows PowerShell path is a directory: %q", path)
	}
	return path, nil
}

func validatePowerShellScript(path string) error {
	ps, err := powershellExePath()
	if err != nil {
		return fmt.Errorf("找不到 Windows PowerShell：%w", err)
	}
	command := fmt.Sprintf(`$tokens=$null;$parseErrors=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$tokens,[ref]$parseErrors);if($parseErrors.Count -gt 0){$parseErrors|ForEach-Object{$_.ToString()};exit 78};exit 0`, psSingleQuote(path))
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	detail := normalizePSDiagnostic(string(out))
	if detail == "" {
		detail = err.Error()
	}
	return fmt.Errorf("PowerShell 语法预检查失败：%s", detail)
}

func waitForElevatedBootstrapResult(diagPath, errorPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastDiagnostic string
	for {
		if data, err := os.ReadFile(diagPath); err == nil {
			lastDiagnostic = string(data)
			if strings.Contains(lastDiagnostic, "[bootstrap] HELPER_RESULT=OK") {
				return nil
			}
			if strings.Contains(lastDiagnostic, "[bootstrap] FAILED") {
				detail := lastDiagnostic
				if errorData, readErr := os.ReadFile(errorPath); readErr == nil && len(errorData) > 0 {
					detail += "\nBootstrap 错误详情:\n" + string(errorData)
				}
				return fmt.Errorf("UAC Bootstrap 明确报告 FAILED，拒绝将管理员组件标记为成功：%s", trimDiagnosticTail(detail, 80000))
			}
		}
		if errorData, readErr := os.ReadFile(errorPath); readErr == nil && len(errorData) > 0 {
			detail := strings.TrimSpace(lastDiagnostic) + "\nBootstrap 错误详情:\n" + string(errorData)
			return fmt.Errorf("UAC Bootstrap 已写入失败诊断，拒绝将管理员组件标记为成功：%s", trimDiagnosticTail(detail, 80000))
		}
		if time.Now().After(deadline) {
			detail := strings.TrimSpace(lastDiagnostic)
			if errorData, readErr := os.ReadFile(errorPath); readErr == nil && len(errorData) > 0 {
				detail += "\nBootstrap 错误详情:\n" + string(errorData)
			}
			if detail == "" {
				detail = "未读取到 Bootstrap 诊断文件或成功标记"
			}
			return fmt.Errorf("UAC Bootstrap 在 %s 内未提交显式 HELPER_RESULT=OK 成功标记；按失败处理：%s", timeout, trimDiagnosticTail(detail, 80000))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func trimDiagnosticTail(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	return "[诊断前部已截断]\n" + s[len(s)-maxBytes:]
}

func buildUACTrampoline(stageDir, bootstrapPath, bootstrapHash, diagPath, callerSID string) string {
	// This small, UTF-16LE-encoded trampoline is the only code carried on the
	// UAC command line. It first hardens the staging directory, then verifies
	// the full bootstrap script before executing it from disk. The large
	// bootstrap/helper/watchdog bodies therefore never inflate CreateProcess.
	return fmt.Sprintf(`
$ErrorActionPreference='Stop'
$stageDir='%s'
$bootstrapPath='%s'
$expectedHash='%s'
$diagPath='%s'
$callerSID='%s'
$stageTouched=$false
function Write-TrampolineDiag([string]$message){
  try{$line=(Get-Date).ToUniversalTime().ToString('o')+' [bootstrap-trampoline] '+$message+[Environment]::NewLine;[IO.File]::AppendAllText($diagPath,$line,(New-Object System.Text.UTF8Encoding($false)))}catch{}
}
function Restore-TrampolineCleanupAccess([string]$dir,[string]$sid){
  $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $caller=New-Object System.Security.Principal.SecurityIdentifier($sid)
  $dirAcl=Get-Acl -LiteralPath $dir -ErrorAction Stop
  $dirAcl.SetOwner($owner)
  $dirAcl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($caller,'Modify','ContainerInherit,ObjectInherit','None','Allow')))
  Set-Acl -LiteralPath $dir -AclObject $dirAcl -ErrorAction Stop
  foreach($file in @(Get-ChildItem -LiteralPath $dir -Force -File -ErrorAction Stop)){
    if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue}
    $fileAcl=Get-Acl -LiteralPath $file.FullName -ErrorAction Stop
    $fileAcl.SetOwner($owner)
    $fileAcl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($caller,'Modify','None','None','Allow')))
    Set-Acl -LiteralPath $file.FullName -AclObject $fileAcl -ErrorAction Stop
  }
}
try{
  $stage=Get-Item -LiteralPath $stageDir -Force -ErrorAction Stop
  if(-not $stage.PSIsContainer){throw 'UAC staging path is not a directory'}
  if(($stage.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'UAC staging directory is a reparse point'}
  $admins=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $user=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $ds=New-Object System.Security.AccessControl.DirectorySecurity
  $ds.SetAccessRuleProtection($true,$false)
  $ds.SetOwner($admins)
  $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
  $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
  $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
  [IO.Directory]::SetAccessControl($stageDir,$ds)
  $stageTouched=$true
  foreach($file in @(Get-ChildItem -LiteralPath $stageDir -Force -File -ErrorAction Stop)){
    if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('UAC staging file is a reparse point: '+$file.Name)}
    $fs=New-Object System.Security.AccessControl.FileSecurity
    $fs.SetAccessRuleProtection($true,$false)
    $fs.SetOwner($admins)
    $fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins,'FullControl','None','None','Allow')))
    $fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system,'FullControl','None','None','Allow')))
    $fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user,'Read','None','None','Allow')))
    [IO.File]::SetAccessControl($file.FullName,$fs)
  }
  Write-TrampolineDiag 'Staging ACL secured before bootstrap integrity verification'
  $bytes=[IO.File]::ReadAllBytes($bootstrapPath)
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$actual=(-join ($sha.ComputeHash($bytes)|ForEach-Object{$_.ToString('x2')}))}finally{$sha.Dispose()}
  if($actual -ne $expectedHash){throw ('bootstrap.ps1 SHA-256 mismatch; expected='+$expectedHash+' actual='+$actual)}
  Write-TrampolineDiag ('Bootstrap SHA-256 verified: '+$actual)
  & $bootstrapPath
  exit 0
}catch{
  $detail=$_.Exception.ToString()
  if($_.ScriptStackTrace){$detail+=' | ScriptStackTrace='+$_.ScriptStackTrace}
  Write-TrampolineDiag ('FAILED '+$detail)
  if($stageTouched){
    try{Restore-TrampolineCleanupAccess $stageDir $callerSID;Write-TrampolineDiag 'Staging cleanup access restored after trampoline failure'}
    catch{Write-TrampolineDiag ('Staging cleanup access restoration failed: '+$_.Exception.ToString())}
  }
  try{[Console]::Error.WriteLine('HACHIMIGUARD_TRAMPOLINE_ERROR '+$detail)}catch{}
  exit 79
}
`, psSingleQuote(stageDir), psSingleQuote(bootstrapPath), bootstrapHash, psSingleQuote(diagPath), psSingleQuote(callerSID))
}

func runElevated(mode string, cfg Config, wait bool) error {
	psExe, err := powershellExePath()
	if err != nil {
		return err
	}
	// The complete bootstrap/helper/watchdog scripts are staged as files. Only a
	// small integrity-checking trampoline is encoded onto the UAC command line.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "HachimiGuard-elevated-")
	if err != nil {
		return fmt.Errorf("create elevated helper temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	helperPath := filepath.Join(tmpDir, "helper.ps1")
	watchdogPath := filepath.Join(tmpDir, "watchdog.ps1")
	configPath := filepath.Join(tmpDir, "config.json")
	errorPath := filepath.Join(tmpDir, "elevated_error.txt")
	diagPath := filepath.Join(tmpDir, "elevated_diagnostic.txt")
	runtimeWatchdog := strings.ReplaceAll(watchdogScript, "__PERSISTENCE_FUNCTIONS__", powershellSessionLifecycleFunctions)
	runtimeWatchdog = strings.ReplaceAll(runtimeWatchdog, "__JAVA_PROCESS_FUNCTIONS__", powershellJavaProcessFunctions)
	runtimeWatchdog = strings.ReplaceAll(runtimeWatchdog, "__EFFECTIVE_ACL_FUNCTIONS__", powershellEffectiveACLFunctions)
	runtimeWatchdog = strings.ReplaceAll(runtimeWatchdog, "__WATCHDOG_UTF16_B64__", "")
	if strings.Contains(runtimeWatchdog, "__JAVA_PROCESS_FUNCTIONS__") || strings.Contains(runtimeWatchdog, "__PERSISTENCE_FUNCTIONS__") || strings.Contains(runtimeWatchdog, "__EFFECTIVE_ACL_FUNCTIONS__") {
		return errors.New("内部错误：Watchdog 进程识别函数占位符未替换")
	}
	watchdogB64 := psEncoded(runtimeWatchdog)
	runtimeHelper := strings.ReplaceAll(helperScript, "__PERSISTENCE_FUNCTIONS__", powershellSessionLifecycleFunctions)
	runtimeHelper = strings.ReplaceAll(runtimeHelper, "__HELPER_WATCHDOG_FUNCTIONS__", powershellHelperWatchdogFunctions)
	runtimeHelper = strings.ReplaceAll(runtimeHelper, "__JAVA_PROCESS_FUNCTIONS__", powershellJavaProcessFunctions)
	runtimeHelper = strings.ReplaceAll(runtimeHelper, "__EFFECTIVE_ACL_FUNCTIONS__", powershellEffectiveACLFunctions)
	runtimeHelper = strings.ReplaceAll(runtimeHelper, "__WATCHDOG_UTF16_B64__", watchdogB64)
	if strings.Contains(runtimeHelper, "__WATCHDOG_UTF16_B64__") || strings.Contains(runtimeHelper, "__HELPER_WATCHDOG_FUNCTIONS__") || strings.Contains(runtimeHelper, "__JAVA_PROCESS_FUNCTIONS__") || strings.Contains(runtimeHelper, "__PERSISTENCE_FUNCTIONS__") || strings.Contains(runtimeHelper, "__EFFECTIVE_ACL_FUNCTIONS__") {
		return errors.New("内部错误：管理员 Helper 脚本占位符未替换")
	}
	if err := writeUTF8BOMFile(helperPath, runtimeHelper, 0600); err != nil {
		return fmt.Errorf("write elevated helper script: %w", err)
	}
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		return fmt.Errorf("write elevated helper config: %w", err)
	}
	if err := writeUTF8BOMFile(watchdogPath, runtimeWatchdog, 0600); err != nil {
		return fmt.Errorf("write watchdog validation script: %w", err)
	}
	if err := os.WriteFile(errorPath, nil, 0600); err != nil {
		return fmt.Errorf("create elevated error diagnostics file: %w", err)
	}
	if err := os.WriteFile(diagPath, []byte("HachimiGuard UAC helper diagnostics\r\n"), 0600); err != nil {
		return fmt.Errorf("create elevated bootstrap diagnostics file: %w", err)
	}

	helperHash, err := hashFileSHA256(helperPath)
	if err != nil {
		return fmt.Errorf("hash elevated helper script: %w", err)
	}
	configHash, err := hashFileSHA256(configPath)
	if err != nil {
		return fmt.Errorf("hash elevated helper config: %w", err)
	}

	bootstrap := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$scriptPath='%s'
$scriptExpected='%s'
$configPath='%s'
$configExpected='%s'
$errorPath='%s'
$diagPath='%s'
$auditPath='%s'
$mode='%s'
$callerSID='%s'
function Get-Sha256Hex([byte[]]$bytes){
  $sha=[Security.Cryptography.SHA256]::Create()
  try{ return (-join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })) }
  finally { $sha.Dispose() }
}
function Write-Diag([string]$text){
  $line=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')+' [bootstrap] '+$text+[Environment]::NewLine
  # Keep the private staging diagnostic even if ProgramData is unavailable.
  try{ [IO.File]::AppendAllText($diagPath, $line, (New-Object System.Text.UTF8Encoding($false))) }catch{}
  if([string]::IsNullOrWhiteSpace($auditPath)){return}
  $mutex=$null;$locked=$false;$stream=$null
  try{
    $auditDir=Split-Path -Parent $auditPath
    if(-not (Test-Path -LiteralPath $auditDir)){New-Item -ItemType Directory -Force -Path $auditDir|Out-Null}
    $fullAuditPath=[IO.Path]::GetFullPath($auditPath).ToLowerInvariant()
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$auditHash=(-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($fullAuditPath))|ForEach-Object{$_.ToString('x2')}))}finally{$sha.Dispose()}
    $mutex=New-Object -TypeName System.Threading.Mutex -ArgumentList @($false,('Local\HachimiGuardLog-'+$auditHash))
    try{$locked=$mutex.WaitOne(10000)}catch [System.Threading.AbandonedMutexException]{$locked=$true}
    if(-not $locked){throw '等待共享会话审计日志互斥锁超时'}
    $stream=[IO.File]::Open($auditPath,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
    $bytes=(New-Object System.Text.UTF8Encoding($false)).GetBytes($line)
    $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
  }catch{
    try{[IO.File]::AppendAllText($diagPath,((Get-Date).ToUniversalTime().ToString('o')+' [bootstrap-audit-fallback] '+$_.Exception.Message+[Environment]::NewLine),(New-Object System.Text.UTF8Encoding($false)))}catch{}
  }finally{
    if($stream){try{$stream.Dispose()}catch{}}
    if($locked -and $mutex){try{$mutex.ReleaseMutex()}catch{}}
    if($mutex){try{$mutex.Dispose()}catch{}}
  }
}
function Format-Error([object]$err){
  $lines=@()
  try{$lines += ('ExceptionType: '+$err.Exception.GetType().FullName)}catch{}
  try{$lines += ('Message: '+$err.Exception.Message)}catch{}
  try{$lines += ('HResult: '+$err.Exception.HResult)}catch{}
  try{$lines += ('FullyQualifiedErrorId: '+$err.FullyQualifiedErrorId)}catch{}
  try{$lines += ('CategoryInfo: '+$err.CategoryInfo)}catch{}
  try{$lines += ('ScriptLineNumber: '+$err.InvocationInfo.ScriptLineNumber)}catch{}
  try{$lines += ('OffsetInLine: '+$err.InvocationInfo.OffsetInLine)}catch{}
  try{$lines += ('PositionMessage: '+$err.InvocationInfo.PositionMessage)}catch{}
  try{$lines += ('Invocation: '+$err.InvocationInfo.Line)}catch{}
  try{$lines += ('ScriptStackTrace: '+$err.ScriptStackTrace)}catch{}
  try{$lines += ('ExceptionToString: '+$err.Exception.ToString())}catch{}
  return ($lines -join [Environment]::NewLine)
}
function Secure-Staging([string]$dir){
  $user=[Security.Principal.WindowsIdentity]::GetCurrent().User
  $admins=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $ds=New-Object System.Security.AccessControl.DirectorySecurity
  $ds.SetAccessRuleProtection($true,$false)
  $ds.SetOwner($admins)
  $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
  $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
  $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
  [IO.Directory]::SetAccessControl($dir,$ds)
  foreach($f in Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue){
    $fs=New-Object System.Security.AccessControl.FileSecurity
    $fs.SetAccessRuleProtection($true,$false)
    $fs.SetOwner($admins)
    $fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins,'FullControl','None','None','Allow')))
    $fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system,'FullControl','None','None','Allow')))
    $fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user,'Read','None','None','Allow')))
    [IO.File]::SetAccessControl($f.FullName,$fs)
  }
}
function Restore-Staging([string]$dir,[string]$callerSID){
  try{
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $admins=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $ds=New-Object System.Security.AccessControl.DirectorySecurity
    $ds.SetAccessRuleProtection($true,$false)
    $ds.SetOwner($user)
    $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user,'Modify','ContainerInherit,ObjectInherit','None','Allow')))
    if($callerSID){$caller=New-Object System.Security.Principal.SecurityIdentifier($callerSID);$ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($caller,'Modify','ContainerInherit,ObjectInherit','None','Allow')))}
    [IO.Directory]::SetAccessControl($dir,$ds)
    foreach($f in Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue){
      $fs=New-Object System.Security.AccessControl.FileSecurity
      $fs.SetAccessRuleProtection($true,$false)
      $fs.SetOwner($user)
      $fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins,'FullControl','None','None','Allow')))
      $fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system,'FullControl','None','None','Allow')))
      $fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user,'Modify','None','None','Allow')))
      if($callerSID){$caller=New-Object System.Security.Principal.SecurityIdentifier($callerSID);$fs.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($caller,'Modify','None','None','Allow')))}
      [IO.File]::SetAccessControl($f.FullName,$fs)
    }
  }catch{}
}
try {
  Write-Diag ('BEGIN mode='+$mode)
  Secure-Staging (Split-Path -Parent $scriptPath)
  Write-Diag 'Staging ACL secured before integrity checks'
  Write-Diag ('PowerShellVersion='+$PSVersionTable.PSVersion.ToString())
  Write-Diag ('Identity='+[Security.Principal.WindowsIdentity]::GetCurrent().Name)
  Write-Diag ('IsAdmin='+([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
  Write-Diag ('ScriptPath='+$scriptPath)
  Write-Diag ('ConfigPath='+$configPath)
  Write-Diag ('ScriptExpectedHash='+$scriptExpected)
  Write-Diag ('ConfigExpectedHash='+$configExpected)
  if(-not (Test-Path -LiteralPath $scriptPath)){ throw "helper.ps1 不存在" }
  if(-not (Test-Path -LiteralPath $configPath)){ throw "config.json 不存在" }
  $scriptBytes=[IO.File]::ReadAllBytes($scriptPath)
  $scriptText=([Text.Encoding]::UTF8.GetString($scriptBytes)).TrimStart([char]0xFEFF)
  $scriptActual=Get-Sha256Hex $scriptBytes
  Write-Diag ('ScriptActualHash='+$scriptActual)
  if($scriptActual -ne $scriptExpected){ throw "helper.ps1 SHA-256 校验失败" }
  $configBytes=[IO.File]::ReadAllBytes($configPath)
  $configActual=Get-Sha256Hex $configBytes
  Write-Diag ('ConfigActualHash='+$configActual)
  Write-Diag ('ConfigBytes='+$configBytes.Length)
  Write-Diag ('HelperBytes='+$scriptBytes.Length)
  if($configActual -ne $configExpected){ throw "config.json SHA-256 校验失败" }
  Write-Diag 'Invoking helper script'
  $helperBlock=[ScriptBlock]::Create($scriptText)
  $configB64=[Convert]::ToBase64String($configBytes)
  $result = & $helperBlock -Mode $mode -ConfigPath $configPath -ConfigExpectedHash $configExpected -ScriptExpectedHash $scriptExpected -ConfigJsonB64 $configB64 2>&1
  if($result){
    foreach($item in @($result)){ Write-Diag ('HELPER_OUTPUT: '+[string]$item) }
  }
  if(-not ($result -contains 'HACHIMIGUARD_OK')){
    throw ('管理员 helper 未返回成功标记。最后输出：'+((@($result) | Select-Object -Last 8) -join ' | '))
  }
  Write-Diag 'HELPER_RESULT=OK'
  Restore-Staging (Split-Path -Parent $scriptPath) $callerSID
  exit 0
} catch {
  $detail=Format-Error $_
  try { Write-Diag ('FAILED'+[Environment]::NewLine+$detail) } catch {}
  try {
    [IO.File]::WriteAllText($errorPath, ('UAC bootstrap failed'+[Environment]::NewLine+$detail), (New-Object System.Text.UTF8Encoding($false)))
  } catch {}
  [Console]::Error.WriteLine('HACHIMIGUARD_BOOTSTRAP_ERROR_BEGIN')
  [Console]::Error.WriteLine($detail)
  [Console]::Error.WriteLine('HACHIMIGUARD_BOOTSTRAP_ERROR_END')
  Restore-Staging (Split-Path -Parent $scriptPath) $callerSID
  exit 79
}
`, psSingleQuote(helperPath), helperHash, psSingleQuote(configPath), configHash, psSingleQuote(errorPath), psSingleQuote(diagPath), psSingleQuote(cfg.AuditLogPath), psSingleQuote(mode), psSingleQuote(cfg.UserSID))

	bootstrapPath := filepath.Join(tmpDir, "bootstrap.ps1")
	if err := writeUTF8BOMFile(bootstrapPath, bootstrap, 0600); err != nil {
		return fmt.Errorf("write UAC bootstrap script: %w", err)
	}
	bootstrapHash, err := hashFileSHA256(bootstrapPath)
	if err != nil {
		return fmt.Errorf("hash UAC bootstrap script: %w", err)
	}
	trampoline := buildUACTrampoline(tmpDir, bootstrapPath, bootstrapHash, diagPath, cfg.UserSID)
	trampolinePath := filepath.Join(tmpDir, "trampoline-validation.ps1")
	if err := writeUTF8BOMFile(trampolinePath, trampoline, 0600); err != nil {
		return fmt.Errorf("write UAC trampoline validation script: %w", err)
	}
	if err := validatePowerShellScript(trampolinePath); err != nil {
		writeFileLog(fmt.Sprintf("[ERROR] [%s] UAC trampoline PowerShell 语法预检查失败：%v", timestamp(), err))
		return err
	}
	writeFileLog(fmt.Sprintf("[SUCCEED] [%s] UAC trampoline PowerShell 语法预检查通过", timestamp()))
	encodedTrampoline := psEncoded(trampoline)
	// Only the small integrity-checking trampoline travels through -EncodedCommand.
	// The full bootstrap script is staged, ACL-hardened by the trampoline, and
	// SHA-256 verified before it is executed with elevated privileges.
	if len(encodedTrampoline) > 14000 {
		return fmt.Errorf("UAC integrity trampoline is unexpectedly large (%d Base64 characters); refusing to launch", len(encodedTrampoline))
	}
	outer := fmt.Sprintf("$ErrorActionPreference='Stop';$argsList=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','%s');$p=Start-Process -FilePath '%s' -Verb RunAs -PassThru -WindowStyle Hidden -ArgumentList $argsList -ErrorAction Stop;if($null -eq $p){exit 80};try{Wait-Process -InputObject $p -ErrorAction Stop;$p.Refresh();if(-not $p.HasExited){exit 81};exit [int]$p.ExitCode}catch{[Console]::Error.WriteLine('UAC bootstrap process wait failed: '+$_.Exception.ToString());exit 82}", encodedTrampoline, psSingleQuote(psExe))
	if !wait {
		outer = fmt.Sprintf("$argsList=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','%s');Start-Process -FilePath '%s' -Verb RunAs -WindowStyle Hidden -ArgumentList $argsList | Out-Null", encodedTrampoline, psSingleQuote(psExe))
	}
	outerCommandUnits := len(utf16.Encode([]rune(outer)))
	if outerCommandUnits+256 > 16000 {
		return fmt.Errorf("UAC launcher command is unexpectedly large (%d UTF-16 units); refusing to launch", outerCommandUnits)
	}

	writeFileLog(fmt.Sprintf("[INFO] [%s] UAC helper: mode=%s temp=%s helperSHA256=%s configSHA256=%s bootstrapSHA256=%s", timestamp(), mode, tmpDir, helperHash, configHash, bootstrapHash))
	if err := validatePowerShellScript(bootstrapPath); err != nil {
		writeFileLog(fmt.Sprintf("[ERROR] [%s] UAC bootstrap PowerShell 语法预检查失败：%v", timestamp(), err))
		return err
	}
	writeFileLog(fmt.Sprintf("[SUCCEED] [%s] UAC bootstrap PowerShell 语法预检查通过", timestamp()))
	if err := validatePowerShellScript(watchdogPath); err != nil {
		writeFileLog(fmt.Sprintf("[ERROR] [%s] Watchdog PowerShell 语法预检查失败：%v", timestamp(), err))
		return err
	}
	writeFileLog(fmt.Sprintf("[SUCCEED] [%s] Watchdog PowerShell 语法预检查通过", timestamp()))
	if err := validatePowerShellScript(helperPath); err != nil {
		writeFileLog(fmt.Sprintf("[ERROR] [%s] UAC helper 语法预检查失败：%v", timestamp(), err))
		return err
	}
	writeFileLog(fmt.Sprintf("[SUCCEED] [%s] UAC helper 语法预检查通过：PowerShell Parser 未发现语法错误", timestamp()))
	writeFileLog(fmt.Sprintf("[INFO] [%s] UAC command length: trampolineBase64=%d chars, outerCommand=%d UTF-16 units; full bootstrap loaded from verified staging file", timestamp(), len(encodedTrampoline), outerCommandUnits))
	cmd := exec.Command(psExe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", outer)
	out, err := cmd.CombinedOutput()
	if err != nil {
		parts := []string{}
		if s := strings.TrimSpace(string(out)); s != "" {
			parts = append(parts, "外层 PowerShell 输出:\n"+normalizePSDiagnostic(s))
		}
		if b, readErr := os.ReadFile(errorPath); readErr == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				parts = append(parts, "Bootstrap 错误详情:\n"+string(b))
			}
		}
		if b, readErr := os.ReadFile(diagPath); readErr == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				parts = append(parts, "Helper 诊断:\n"+string(b))
			}
		}
		detail := strings.TrimSpace(strings.Join(parts, "\n\n"))
		if detail == "" {
			detail = "未取得管理员组件的详细错误信息"
		}
		writeFileLog(fmt.Sprintf("[UAC-FAILURE] [%s] mode=%s error=%v\n%s", timestamp(), mode, err, detail))
		if appLogPath != "" {
			stamp := time.Now().Format("2006-01-02_15-04-05.000")
			path := filepath.Join(filepath.Dir(appLogPath), "uac-failure-"+stamp+".log")
			_ = os.WriteFile(path, []byte(detail+"\n"), 0600)
			writeFileLog(fmt.Sprintf("[ERROR] [%s] UAC 详细诊断已保存：%s", timestamp(), path))
		}
		return fmt.Errorf("管理员保护组件启动失败：%w\n%s", err, detail)
	}
	if bootstrapErr := waitForElevatedBootstrapResult(diagPath, errorPath, 120*time.Second); bootstrapErr != nil {
		detail := bootstrapErr.Error()
		writeFileLog(fmt.Sprintf("[UAC-FAILURE] [%s] mode=%s outer PowerShell returned zero but Bootstrap did not confirm success: %s", timestamp(), mode, detail))
		if appLogPath != "" {
			stamp := time.Now().Format("2006-01-02_15-04-05.000")
			path := filepath.Join(filepath.Dir(appLogPath), "uac-failure-"+stamp+".log")
			_ = os.WriteFile(path, []byte(detail+"\n"), 0600)
			writeFileLog(fmt.Sprintf("[ERROR] [%s] UAC 详细诊断已保存：%s", timestamp(), path))
		}
		return fmt.Errorf("管理员保护组件未完成：%w", bootstrapErr)
	}
	writeFileLog(fmt.Sprintf("[UAC-SUCCESS] [%s] mode=%s elevated helper completed; explicit Bootstrap HELPER_RESULT=OK marker verified", timestamp(), mode))
	return nil
}

func parseLine(line string) (host string, port int, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", 0, false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", 0, false
	}
	if len(fields) > 1 && !strings.HasPrefix(fields[1], "#") {
		return "", 0, false
	}
	line = strings.TrimSpace(fields[0])
	if line == "" {
		return "", 0, false
	}
	parsePort := func(raw string) (int, bool) {
		n, err := strconv.Atoi(raw)
		return n, err == nil && n > 0 && n <= 65535
	}
	if strings.HasPrefix(line, "[") {
		if h, p, err := net.SplitHostPort(line); err == nil {
			if n, valid := parsePort(p); valid && net.ParseIP(h) != nil {
				return h, n, true
			}
			return "", 0, false
		}
		if strings.HasSuffix(line, "]") {
			h := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if net.ParseIP(h) != nil {
				return h, 443, true
			}
		}
		return "", 0, false
	}
	if ip := net.ParseIP(line); ip != nil {
		return ip.String(), 443, true
	}
	if strings.Count(line, ":") == 1 {
		h, p, err := net.SplitHostPort(line)
		if err != nil {
			return "", 0, false
		}
		n, valid := parsePort(p)
		if !valid || h == "" || strings.ContainsAny(h, "[]") {
			return "", 0, false
		}
		h = strings.TrimSuffix(h, ".")
		return h, n, validEndpointHost(h)
	}
	if strings.Contains(line, ":") || strings.ContainsAny(line, "[]/\\") {
		return "", 0, false
	}
	line = strings.TrimSuffix(line, ".")
	return line, 443, validEndpointHost(line)
}

func validEndpointHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 || strings.EqualFold(host, "Any") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

var windowsEnvToken = regexp.MustCompile(`%([^%]+)%`)

// expandWindowsEnv expands the %NAME% form used by Windows path configuration.
// os.ExpandEnv only understands $NAME and ${NAME}, so using it directly would
// silently skip all default paths written in the Windows-native form.
func expandWindowsEnv(value string) string {
	return windowsEnvToken.ReplaceAllStringFunc(value, func(token string) string {
		name := token[1 : len(token)-1]
		if replacement, ok := os.LookupEnv(name); ok {
			return replacement
		}
		return token
	})
}

func resolveEndpoint(host string, port int) (Endpoint, error) {
	e := Endpoint{Host: host, Port: port}
	if ip := net.ParseIP(host); ip != nil {
		e.IPs = []string{ip.String()}
		return e, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return e, fmt.Errorf("cannot resolve %s: %v", host, err)
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			e.IPs = append(e.IPs, s)
		}
	}
	return e, nil
}

func loadEndpoints(path string) ([]Endpoint, []string, error) {
	data, err := readConfigText(path, false)
	if err != nil {
		return nil, nil, err
	}
	var out []Endpoint
	var warnings []string
	seen := map[string]bool{}
	for index, line := range strings.Split(data, "\n") {
		h, p, ok := parseLine(line)
		if !ok {
			if value := strings.TrimSpace(line); value != "" && !strings.HasPrefix(value, "#") {
				warnings = append(warnings, fmt.Sprintf("第 %d 行无效：%.160s", index+1, value))
			}
			continue
		}
		key := strings.ToLower(h) + ":" + strconv.Itoa(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		e, resolveErr := resolveEndpoint(h, p)
		if resolveErr != nil {
			// Keep the endpoint in the allowlist. The elevated helper can use a
			// Windows Firewall dynamic keyword (FQDN) rule even when DNS is
			// temporarily unavailable at startup.
			e.ResolveError = resolveErr.Error()
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, nil, errors.New("AllowedDomains.txt contains no usable endpoints")
	}
	return out, warnings, nil
}

// readConfigText accepts UTF-8 with an optional BOM. Missing optional files are
// distinct from unreadable or malformed files; the latter must never be defaults.
func readConfigText(path string, optional bool) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", fmt.Errorf("%s 必须是有效 UTF-8 文本（允许 UTF-8 BOM）", path)
	}
	return string(b), nil
}

type javaDiscovery struct {
	Paths      []string
	Candidates []string
	Warnings   []string
}

func loadJavaPaths(path string, launcher string) (javaDiscovery, error) {
	var result javaDiscovery
	text, err := readConfigText(path, true)
	if err != nil {
		return result, fmt.Errorf("读取 JavaPaths.txt：%w", err)
	}
	seen := map[string]bool{}
	add := func(raw string, explicit bool) error {
		value := expandWindowsEnv(strings.Trim(strings.TrimSpace(raw), "\""))
		if value == "" {
			return nil
		}
		if windowsEnvToken.MatchString(value) {
			return fmt.Errorf("未解析环境变量：%s", value)
		}
		if !filepath.IsAbs(value) {
			value = filepath.Join(filepath.Dir(path), value)
		}
		value = filepath.Clean(value)
		st, e := os.Stat(value)
		if e != nil {
			return fmt.Errorf("%s：%w", value, e)
		}
		if !st.Mode().IsRegular() || (!strings.EqualFold(filepath.Base(value), "java.exe") && !strings.EqualFold(filepath.Base(value), "javaw.exe")) {
			return fmt.Errorf("不是 java.exe/javaw.exe 普通文件：%s", value)
		}
		key := strings.ToLower(value)
		if !seen[key] {
			seen[key] = true
			if explicit {
				result.Paths = append(result.Paths, value)
			} else {
				result.Candidates = append(result.Candidates, value)
			}
		}
		return nil
	}
	var invalid []error
	for index, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := add(line, true); err != nil {
			invalid = append(invalid, fmt.Errorf("第 %d 行：%w", index+1, err))
		}
	}
	if len(invalid) > 0 {
		return result, errors.Join(invalid...)
	}
	// Do not grant rules to PATH/JAVA_HOME or every package's Java. These can be
	// IDE/Gradle runtimes. Scanned files are candidates only, never ALLOW targets.
	roots := []string{filepath.Join(filepath.Dir(launcher), "runtime"), filepath.Join(filepath.Dir(launcher), ".minecraft", "runtime"), filepath.Join(filepath.Dir(launcher), "jre"), filepath.Join(filepath.Dir(launcher), "java")}
	for _, root := range []string{os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA"), os.Getenv("USERPROFILE")} {
		if root != "" {
			roots = append(roots, filepath.Join(root, ".minecraft", "runtime"), filepath.Join(root, "MinecraftLauncher", "runtime"))
		}
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		matches, e := filepath.Glob(filepath.Join(local, "Packages", "Microsoft.*Minecraft*", "LocalCache", "*", ".minecraft", "runtime"))
		if e != nil {
			result.Warnings = append(result.Warnings, e.Error())
		}
		roots = append(roots, matches...)
	}
	scanned := map[string]bool{}
	for _, root := range roots {
		key := strings.ToLower(filepath.Clean(root))
		if scanned[key] {
			continue
		}
		scanned[key] = true
		st, e := os.Stat(root)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("无法扫描 %s：%v", root, e))
			continue
		}
		if !st.IsDir() {
			continue
		}
		e = filepath.WalkDir(root, func(value string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("扫描不完整 %s：%v", value, walkErr))
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				result.Warnings = append(result.Warnings, "扫描未跟随链接（可在 JavaPaths.txt 显式指定运行时）："+value)
				return nil
			}
			if !d.IsDir() && (strings.EqualFold(d.Name(), "java.exe") || strings.EqualFold(d.Name(), "javaw.exe")) {
				if e := add(value, false); e != nil {
					result.Warnings = append(result.Warnings, e.Error())
				}
			}
			return nil
		})
		if e != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("扫描失败 %s：%v", root, e))
		}
	}
	return result, nil
}

func readProtectedPaths(path string) ([]string, error) {
	defaults := []string{`%APPDATA%\Tencent`, `%USERPROFILE%\Documents\Tencent Files`, `%USERPROFILE%\Documents\Tencent`, `%PUBLIC%\Documents\Tencent`}
	text, err := readConfigText(path, true)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			defaults = append(defaults, strings.Trim(line, "\""))
		}
	}
	return defaults, nil
}

func validateLauncherPath(path string) (string, error) {
	abs, err := filepath.Abs(expandWindowsEnv(cleanDroppedPath(path)))
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || !strings.EqualFold(filepath.Ext(abs), ".exe") {
		return "", fmt.Errorf("启动器必须是实际的 .exe 普通文件：%s", abs)
	}
	return abs, nil
}

func randID() string {
	b := make([]byte, 8)
	if _, e := rand.Read(b); e != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

var appLog *os.File
var appLogMu sync.Mutex
var appLogPath string
var sessionAuditPath string
var sessionGroup string
var consoleHidden bool

func openRunLog(exePath string) (*os.File, error) {
	logDir := filepath.Join(filepath.Dir(exePath), "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, err
	}
	name := time.Now().Format("2006-01-02_15-04-05.000") + ".log"
	path := filepath.Join(logDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	appLogPath = path
	return f, nil
}

// setupCrashFallbackLogging is used only when a panic happens before the normal
// executable-directory logger could be initialized. It keeps early startup crashes
// persistent under the current user's profile (or the system temp directory).
func setupCrashFallbackLogging() {
	appLogMu.Lock()
	if appLog != nil {
		appLogMu.Unlock()
		return
	}
	root := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if root == "" {
		root = os.TempDir()
	}
	dir := filepath.Join(root, "HachimiGuard", "logs")
	if err := os.MkdirAll(dir, 0700); err == nil {
		name := "early-crash-" + time.Now().Format("2006-01-02_15-04-05.000") + ".log"
		path := filepath.Join(dir, name)
		if f, openErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); openErr == nil {
			appLog = f
			appLogPath = path
		}
	}
	appLogMu.Unlock()
}

func setupLogging(exePath string, background bool) {
	f, err := openRunLog(exePath)
	if err != nil {
		// Diagnostics must never block containment. Try a per-user fallback only for logging.
		fallbackRoot := os.Getenv("LOCALAPPDATA")
		if fallbackRoot == "" {
			fallbackRoot = os.TempDir()
		}
		fallbackDir := filepath.Join(fallbackRoot, "HachimiGuard", "logs")
		if mkErr := os.MkdirAll(fallbackDir, 0700); mkErr == nil {
			fallback := filepath.Join(fallbackDir, time.Now().Format("2006-01-02_15-04-05.000")+".log")
			if ff, openErr := os.OpenFile(fallback, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); openErr == nil {
				f = ff
				appLogPath = fallback
			}
		}
	}
	appLog = f
	consoleHidden = background
	if appLog != nil {
		writeFileLog(fmt.Sprintf("[INFO] [%s] HachimiGuard %s log started", timestamp(), appVersion))
		if appLogPath != "" {
			writeFileLog(fmt.Sprintf("[INFO] [%s] log file: %s", timestamp(), appLogPath))
		}
		if err != nil {
			writeFileLog(fmt.Sprintf("[WARN] [%s] program-directory logs folder was unavailable: %v; using fallback", timestamp(), err))
		}
	}
}

func writeFileLog(line string) {
	appLogMu.Lock()
	defer appLogMu.Unlock()
	if appLog != nil {
		_, _ = appLog.WriteString(line + "\n")
		_ = appLog.Sync()
	}
	if sessionAuditPath != "" {
		if err := appendSharedAuditLog(sessionAuditPath, line); err != nil && appLog != nil {
			_, _ = appLog.WriteString(fmt.Sprintf("[WARN] [%s] shared lifecycle audit append failed: %v\n", timestamp(), err))
			_ = appLog.Sync()
		}
	}
}

func setSessionAuditPath(path, group string) error {
	path = strings.TrimSpace(path)
	if path == "" || strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("session audit path is empty or contains control characters")
	}
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		return fmt.Errorf("session audit file is not initialized at %q: %w", clean, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("session audit path is not a regular file: %q", clean)
	}
	f, err := os.OpenFile(clean, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("session audit file is not writable by the caller at %q: %w", clean, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close session audit validation handle %q: %w", clean, err)
	}
	appLogMu.Lock()
	sessionAuditPath = clean
	sessionGroup = group
	appLogMu.Unlock()
	writeFileLog(fmt.Sprintf("[INFO] [%s] session audit attached group=%s path=%q", timestamp(), group, clean))
	return nil
}

// appendSharedAuditLog serializes Go and PowerShell writers through the same
// per-file Windows named mutex. The file is opened in append mode and flushed
// before the mutex is released so lifecycle events survive abrupt termination.
func appendSharedAuditLog(path, line string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("empty audit log path")
	}
	full, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return err
	}
	key := strings.ToLower(full)
	sum := sha256.Sum256([]byte(key))
	mutexName, err := syscall.UTF16PtrFromString(`Local\HachimiGuardLog-` + hex.EncodeToString(sum[:]))
	if err != nil {
		return err
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutex := kernel32.NewProc("CreateMutexW")
	waitForSingleObject := kernel32.NewProc("WaitForSingleObject")
	releaseMutex := kernel32.NewProc("ReleaseMutex")
	closeHandle := kernel32.NewProc("CloseHandle")
	h, _, callErr := createMutex.Call(0, 0, uintptr(unsafe.Pointer(mutexName)))
	if h == 0 {
		return fmt.Errorf("CreateMutexW failed: %v", callErr)
	}
	defer closeHandle.Call(h)
	const (
		waitObject0   = 0x00000000
		waitAbandoned = 0x00000080
		waitTimeout   = 0x00000102
	)
	result, _, waitErr := waitForSingleObject.Call(h, 10000)
	if result != waitObject0 && result != waitAbandoned {
		if result == waitTimeout {
			return errors.New("shared audit log mutex timeout")
		}
		return fmt.Errorf("WaitForSingleObject failed: result=0x%x error=%v", result, waitErr)
	}
	defer releaseMutex.Call(h)
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(strings.TrimRight(line, "\r\n") + "\r\n"); err != nil {
		return err
	}
	return f.Sync()
}

func closeLog() {
	appLogMu.Lock()
	defer appLogMu.Unlock()
	if appLog != nil {
		_ = appLog.Sync()
		_ = appLog.Close()
		appLog = nil
	}
}

func timestamp() string { return time.Now().Format("15:04:05.000") }

func consoleAttr(kind string) uint16 {
	const (
		fgBlue      = 0x0001
		fgGreen     = 0x0002
		fgRed       = 0x0004
		fgIntensity = 0x0008
		fgWhite     = 0x0007
		bgRed       = 0x0040
	)
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "INFO":
		return fgBlue | fgIntensity
	case "WARN":
		// Classic CMD has no true orange; bright yellow is the closest portable warning color.
		return fgRed | fgGreen | fgIntensity
	case "ERROR":
		return fgRed | fgIntensity
	case "SUCCEED":
		return fgGreen | fgIntensity
	case "FATAL":
		// High-visibility fatal state: white text on a red background.
		return fgWhite | bgRed | fgIntensity
	default:
		return fgWhite
	}
}

func setConsoleTitle(title string) {
	if consoleHidden {
		return
	}
	user32 := syscall.NewLazyDLL("kernel32.dll")
	setTitle := user32.NewProc("SetConsoleTitleW")
	u16, _ := syscall.UTF16FromString(title)
	if len(u16) == 0 {
		return
	}
	_, _, _ = setTitle.Call(uintptr(unsafe.Pointer(&u16[0])))
}

func writeConsoleLine(line, kind string) {
	if consoleHidden {
		return
	}
	// Try the Windows console API so UTF-8/中文 output is written as UTF-16 directly.
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getStdHandle := kernel32.NewProc("GetStdHandle")
	setAttr := kernel32.NewProc("SetConsoleTextAttribute")
	writeConsoleW := kernel32.NewProc("WriteConsoleW")
	stdOut := ^uintptr(10) // STD_OUTPUT_HANDLE = (DWORD)-11
	h, _, _ := getStdHandle.Call(stdOut)
	if h != 0 {
		if _, _, e := setAttr.Call(h, uintptr(consoleAttr(kind))); e == syscall.Errno(0) || e == nil {
			u16, _ := syscall.UTF16FromString(line)
			if len(u16) > 0 {
				var written uint32
				if r, _, _ := writeConsoleW.Call(h, uintptr(unsafe.Pointer(&u16[0])), uintptr(len(u16)-1), uintptr(unsafe.Pointer(&written)), 0); r != 0 {
					_, _, _ = setAttr.Call(h, uintptr(0x0007))
					return
				}
			}
		}
	}
	_, _ = fmt.Fprint(os.Stdout, line)
}

func uiLine(kind, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] [%s] %s", kind, timestamp(), msg)
	writeConsoleLine(line+"\n", kind)
	writeFileLog(line)
}

func uiStep(format string, args ...interface{})  { uiLine("INFO", format, args...) }
func uiOK(format string, args ...interface{})    { uiLine("SUCCEED", format, args...) }
func uiWarn(format string, args ...interface{})  { uiLine("WARN", format, args...) }
func uiErr(format string, args ...interface{})   { uiLine("ERROR", format, args...) }
func uiInfo(format string, args ...interface{})  { uiLine("INFO", format, args...) }
func uiFatal(format string, args ...interface{}) { uiLine("FATAL", format, args...) }

type notificationTail struct {
	identity os.FileInfo
	offset   int64
	pending  []byte
	dropping bool
}

func readNotificationLines(path string, tail *notificationTail) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if tail.identity == nil || !os.SameFile(tail.identity, info) || info.Size() < tail.offset {
		tail.offset = 0
		tail.pending = nil
		tail.dropping = false
	}
	tail.identity = info
	if _, err = file.Seek(tail.offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, 256*1024))
	if err != nil {
		return nil, err
	}
	tail.offset += int64(len(data))
	data = append(tail.pending, data...)
	tail.pending = nil
	var lines []string
	for {
		newline := bytes.IndexByte(data, '\n')
		if newline < 0 {
			break
		}
		if !tail.dropping && newline <= 64*1024 {
			lines = append(lines, strings.TrimPrefix(strings.TrimSpace(string(data[:newline])), "\ufeff"))
		}
		tail.dropping = false
		data = data[newline+1:]
	}
	if len(data) > 64*1024 {
		tail.dropping = true
	} else if !tail.dropping {
		tail.pending = append([]byte(nil), data...)
	}
	return lines, nil
}

func startNotificationMonitor(path string, stop <-chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(350 * time.Millisecond)
		defer ticker.Stop()
		tail := notificationTail{}
		seen := map[int64]bool{}
		order := make([]int64, 0, 1024)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			lines, err := readNotificationLines(path, &tail)
			if err != nil {
				continue
			}
			for _, line := range lines {
				var n FirewallNotification
				if json.Unmarshal([]byte(line), &n) != nil || n.Type != "firewall_block" || n.RecordID <= 0 || seen[n.RecordID] {
					continue
				}
				seen[n.RecordID] = true
				order = append(order, n.RecordID)
				if len(order) > 1024 {
					delete(seen, order[0])
					order = order[1:]
				}
				uiOK("已拦截出站请求：%s → %s:%s（%s）", n.Application, n.Destination, n.DestPort, n.Protocol)
			}
		}
	}()
}

func cleanDroppedPath(line string) string {
	line = strings.TrimSpace(line)
	line = strings.Trim(line, "\r\n")
	line = strings.TrimSpace(line)
	if len(line) >= 2 && line[0] == '"' && line[len(line)-1] == '"' {
		line = line[1 : len(line)-1]
	}
	return strings.TrimSpace(line)
}

const defaultLauncherFileName = "DefaultLauncherPath.txt"

func defaultLauncherPathFile(exePath string) string {
	return filepath.Join(filepath.Dir(exePath), defaultLauncherFileName)
}

func readDefaultLauncherPath(exePath string) (string, error) {
	path := defaultLauncherPathFile(exePath)
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_ = os.WriteFile(path, []byte("# HachimiGuard 默认 Minecraft 启动器路径；保存成功后下次会自动使用。\r\n# 也可以手动把 EXE 的完整路径写在下一行。\r\n"), 0600)
			return "", nil
		}
		return "", err
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := cleanDroppedPath(strings.TrimSpace(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line, nil
	}
	return "", nil
}

func saveDefaultLauncherPath(exePath, launcher string) error {
	path := defaultLauncherPathFile(exePath)
	content := "# HachimiGuard 默认 Minecraft 启动器路径\r\n" + launcher + "\r\n"
	return os.WriteFile(path, []byte(content), 0600)
}

type openFileName struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       uintptr
	lpstrCustomFilter uintptr
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         uintptr
	nMaxFile          uint32
	lpstrFileTitle    uintptr
	nMaxFileTitle     uint32
	lpstrInitialDir   uintptr
	lpstrTitle        uintptr
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       uintptr
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    uintptr
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

func pickLauncherFile() (string, error) {
	comdlg32 := syscall.NewLazyDLL("comdlg32.dll")
	proc := comdlg32.NewProc("GetOpenFileNameW")
	if proc == nil {
		return "", errors.New("Windows 文件选择器不可用")
	}
	fileBuf := make([]uint16, 32768)
	filter, _ := syscall.UTF16FromString("Minecraft 启动器 (*.exe)\x00*.exe\x00所有文件 (*.*)\x00*.*\x00\x00")
	title, _ := syscall.UTF16FromString("选择 Minecraft 启动器")
	initial, _ := syscall.UTF16FromString(filepath.Dir(mustExecutablePath()))
	of := openFileName{
		lStructSize:     uint32(unsafe.Sizeof(openFileName{})),
		lpstrFilter:     uintptr(unsafe.Pointer(&filter[0])),
		lpstrFile:       uintptr(unsafe.Pointer(&fileBuf[0])),
		nMaxFile:        uint32(len(fileBuf)),
		lpstrInitialDir: uintptr(unsafe.Pointer(&initial[0])),
		lpstrTitle:      uintptr(unsafe.Pointer(&title[0])),
		flags:           0x00001000 | 0x00000800 | 0x00080000, // OFN_FILEMUSTEXIST|PATHMUSTEXIST|EXPLORER
	}
	r, _, callErr := proc.Call(uintptr(unsafe.Pointer(&of)))
	if r == 0 {
		if callErr != syscall.Errno(0) && callErr != nil {
			return "", callErr
		}
		return "", errors.New("用户取消了文件选择")
	}
	return syscall.UTF16ToString(fileBuf), nil
}

func mustExecutablePath() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return p
}

func promptForLauncher(exePath string) (string, error) {
	// Background mode may reuse a previously saved launcher. Only refuse to
	// prompt after checking the saved path, because a hidden console cannot
	// receive interactive input or display the file picker.
	if saved, err := readDefaultLauncherPath(exePath); err == nil && saved != "" {
		abs, absErr := filepath.Abs(saved)
		if absErr == nil {
			if st, statErr := os.Stat(abs); statErr == nil && !st.IsDir() && strings.EqualFold(filepath.Ext(abs), ".exe") {
				uiOK("已加载默认启动器：%s", abs)
				uiInfo("如需更换默认启动器，可修改程序目录下的 %s", defaultLauncherFileName)
				return abs, nil
			}
		}
		uiWarn("默认启动器路径无效：%s；将进入手动选择。", saved)
	} else if err != nil {
		uiWarn("读取默认启动器文件失败：%v；将进入手动选择。", err)
	}
	if consoleHidden {
		return "", errors.New("background mode requires an explicit launcher path or a valid saved DefaultLauncherPath.txt")
	}
	uiInfo("首次使用：请将 MinecraftLauncher.exe 拖到窗口后按 Enter。")
	uiInfo("如果当前终端不支持拖放，可直接粘贴完整路径并按 Enter，或输入 F2 后按 Enter 打开文件选择器。")
	reader := bufio.NewReader(os.Stdin)
	for {
		uiLine("INFO", "等待启动器路径…")
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return "", fmt.Errorf("读取启动器路径失败：%w", err)
		}
		path := cleanDroppedPath(line)
		if strings.EqualFold(path, "F2") {
			chosen, pickErr := pickLauncherFile()
			if pickErr != nil {
				if strings.Contains(pickErr.Error(), "用户取消") {
					uiWarn("已取消文件选择。")
				} else {
					uiErr("打开文件选择器失败：%v", pickErr)
				}
				continue
			}
			path = chosen
		}
		if path == "" {
			uiWarn("未检测到路径，请拖入、粘贴路径，或输入 F2 后按 Enter。")
			if err != nil {
				return "", err
			}
			continue
		}
		abs, absErr := filepath.Abs(path)
		if absErr != nil {
			uiWarn("无法解析路径：%s", path)
			if err != nil {
				return "", absErr
			}
			continue
		}
		st, statErr := os.Stat(abs)
		if statErr != nil {
			uiWarn("找不到可执行文件：%s", abs)
			if err != nil {
				return "", statErr
			}
			continue
		}
		if st.IsDir() {
			uiWarn("选择的是文件夹而不是 EXE：%s", abs)
			if err != nil {
				return "", errors.New("launcher path is a directory")
			}
			continue
		}
		if !strings.EqualFold(filepath.Ext(abs), ".exe") {
			uiWarn("选择的文件不是 EXE：%s", abs)
			if err != nil {
				return "", errors.New("launcher must be an .exe file")
			}
			continue
		}
		if saveErr := saveDefaultLauncherPath(exePath, abs); saveErr != nil {
			uiWarn("无法保存默认启动器地址：%v；本次仍会正常使用。", saveErr)
		} else {
			uiInfo("已保存默认启动器地址：%s", defaultLauncherFileName)
		}
		uiOK("已读取启动器：%s", abs)
		return abs, nil
	}
}

func getUserSID() (string, error) {
	ps, err := powershellExePath()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
	b, err := cmd.Output()
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("empty user SID")
	}
	return s, nil
}

func runPS(expr string) (string, error) {
	ps, pathErr := powershellExePath()
	if pathErr != nil {
		return "", pathErr
	}
	// Larger shared probes no longer fit -EncodedCommand's UTF-16 command line.
	file, err := os.CreateTemp("", "HachimiGuard-probe-*.ps1")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err = file.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	defer os.Remove(path)
	if err = writeUTF8BOMFile(path, "$ErrorActionPreference='Stop';\n"+expr, 0600); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	b, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return strings.TrimSpace(string(b)), fmt.Errorf("PowerShell 查询超过 30 秒：%w", ctx.Err())
	}
	return strings.TrimSpace(string(b)), err
}

func firewallProfiles() (map[string]string, error) {
	out, err := runPS("Get-NetFirewallProfile | ForEach-Object { ($_.Name + '=' + $_.DefaultOutboundAction.ToString() + '|' + $_.Enabled.ToString()) }")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m, nil
}

func firewallProfilesActive() (map[string]string, error) {
	out, err := runPS("Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { ($_.Name + '=' + $_.DefaultOutboundAction.ToString() + '|' + $_.Enabled.ToString()) }")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		}
	}
	return m, nil
}

func guardRuleCount(group string) (int, error) {
	out, err := runPS(fmt.Sprintf("@(Get-NetFirewallRule -PolicyStore ActiveStore -Group '%s' -ErrorAction SilentlyContinue).Count", strings.ReplaceAll(group, "'", "''")))
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, err
	}
	return n, nil
}

// activeEndpointListIsEmpty only accepts a valid JSON array with zero entries.
// PowerShell 5.1 Set-Content -Encoding UTF8 may prepend a UTF-8 BOM, so strip it
// before decoding. This lets the caller distinguish intentional BLOCK-only mode
// from a missing or malformed active_endpoints.json recovery record.
func activeEndpointListIsEmpty(stateDir string) (bool, error) {
	path := filepath.Join(stateDir, "active_endpoints.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	var endpoints []json.RawMessage
	if err := json.Unmarshal([]byte(text), &endpoints); err != nil {
		return false, fmt.Errorf("active_endpoints.json 无法解析：%w", err)
	}
	if endpoints == nil {
		return false, errors.New("active_endpoints.json 根节点不是 JSON 数组")
	}
	return len(endpoints) == 0, nil
}

func pathACL(path string) (string, error) {
	ps, pathErr := powershellExePath()
	if pathErr != nil {
		return "", pathErr
	}
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf("$ErrorActionPreference='Stop';(Get-Acl -LiteralPath '%s' -ErrorAction Stop).Sddl", strings.ReplaceAll(path, "'", "''")))
	b, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(b)), err
	}
	return strings.TrimSpace(string(b)), nil
}

func hasDenyForSID(path, sid string) (bool, error) {
	expr := powershellEffectiveACLFunctions + fmt.Sprintf("\nif(Test-GuardProtectionEffective '%s' '%s'){'YES'}else{'NO'}", psSingleQuote(expandWindowsEnv(path)), psSingleQuote(sid))
	out, err := runPS(expr)
	if err != nil {
		return false, fmt.Errorf("读取 ACL 失败：%w；输出=%s", err, out)
	}
	switch strings.TrimSpace(out) {
	case "YES":
		return true, nil
	case "NO":
		return false, nil
	default:
		return false, fmt.Errorf("ACL 检查返回无法识别的结果：%q", out)
	}
}
func sha256File(path string) (string, error) {
	ps, pathErr := powershellExePath()
	if pathErr != nil {
		return "", pathErr
	}
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", fmt.Sprintf("(Get-FileHash -LiteralPath '%s' -Algorithm SHA256).Hash", strings.ReplaceAll(path, "'", "''")))
	b, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(b)), err
	}
	return strings.TrimSpace(string(b)), nil
}

func snapshotConfiguredACLs(paths []string) (map[string]string, []error) {
	m := map[string]string{}
	var failures []error
	for _, p := range paths {
		path := expandWindowsEnv(p)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			failures = append(failures, fmt.Errorf("%s：%w", path, err))
			continue
		}
		if s, err := pathACL(path); err == nil && s != "" {
			m[strings.ToLower(filepath.Clean(path))] = s
		} else {
			failures = append(failures, fmt.Errorf("%s：ACL 快照失败：%v", path, err))
		}
	}
	return m, failures
}

func compareProfiles(a, b map[string]string) bool {
	for _, n := range []string{"Domain", "Private", "Public"} {
		if a[n] != b[n] {
			return false
		}
	}
	return true
}

func waitForAnyKey() {
	if consoleHidden {
		return
	}
	// Prefer a true single-key wait on Windows. Fall back to an Enter wait if
	// stdin is redirected or the CRT call is unavailable.
	msvcrt := syscall.NewLazyDLL("msvcrt.dll")
	getch := msvcrt.NewProc("_getch")
	if getch != nil {
		if _, _, err := getch.Call(); err == syscall.Errno(0) || err == nil {
			return
		}
	}
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func fatalPauseAndExit(code int, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	writeFileLog(fmt.Sprintf("[FATAL] [%s] exitCode=%d message=%s", timestamp(), code, message))
	uiFatal("%s", message)
	uiFatal("按任意键退出")
	closeLog()
	waitForAnyKey()
	os.Exit(code)
}

func main() {
	defer closeLog()
	defer func() {
		if recovered := recover(); recovered != nil {
			setupCrashFallbackLogging()
			writeFileLog(fmt.Sprintf("[CRASH] [%s] unrecovered panic: %v\n%s", timestamp(), recovered, debug.Stack()))
			panic(recovered)
		}
	}()
	args := os.Args[1:]
	strict, background, diagnose := true, false, false
	var launcher string
	var launcherArgs []string
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep >= 0 {
		for _, a := range args[:sep] {
			switch a {
			case "--no-network-lock":
				strict = false
			case "--background":
				background = true
			case "--diagnose":
				diagnose = true
			default:
				if strings.HasPrefix(a, "--") {
					uiWarn("忽略未知参数：%s", a)
				}
			}
		}
		if sep+1 < len(args) {
			launcher = args[sep+1]
			launcherArgs = append([]string(nil), args[sep+2:]...)
		}
	} else {
		for _, a := range args {
			switch a {
			case "--no-network-lock":
				strict = false
			case "--background":
				background = true
			case "--diagnose":
				diagnose = true
			default:
				if launcher == "" && !strings.HasPrefix(a, "--") {
					// Accept the launcher path after flags as well as before them:
					// GuardLauncher.exe --background C:\Minecraft\Launcher.exe
					launcher = a
				} else if launcher != "" {
					launcherArgs = append(launcherArgs, a)
				} else if strings.HasPrefix(a, "--") {
					uiWarn("忽略未知参数：%s", a)
				}
			}
		}
	}
	exePath, exErr := os.Executable()
	if exErr != nil {
		setupCrashFallbackLogging()
		writeFileLog(fmt.Sprintf("[FATAL] [%s] os.Executable failed: %v", timestamp(), exErr))
		uiFatal("无法定位 GuardLauncher.exe：%v", exErr)
		fatalPauseAndExit(2, "无法继续启动")
	}
	if background {
		hideConsole()
	}
	setupLogging(exePath, background)
	writeFileLog(fmt.Sprintf("[LIFECYCLE] [%s] process startup version=%s pid=%d args=%q", timestamp(), appVersion, os.Getpid(), os.Args[1:]))
	setConsoleTitle(appVersion + " - Minecraft 防护启动器")
	uiInfo("HachimiGuard " + appVersion + " 启动（兼容性与恢复修复版）")
	if appLogPath != "" {
		uiInfo("详细日志：%s", appLogPath)
	}
	interactiveMode := launcher == ""
	writeFileLog(fmt.Sprintf("[INFO] [%s] interactive mode=%t background=%t diagnose=%t strict=%t", timestamp(), interactiveMode, background, diagnose, strict))
	var err error
	if interactiveMode {
		launcher, err = promptForLauncher(exePath)
		if err != nil {
			fatalPauseAndExit(2, "无法获得 Minecraft 启动器路径：%v", err)
		}
	}
	uiInfo("网络模式：%s", map[bool]string{true: "严格模式：默认出站 BLOCK，仅允许白名单 IP:端口或已注册的 FQDN 动态白名单", false: "网络隔离关闭：仅保护 QQ/Tencent 文件"}[strict])
	launcher, err = validateLauncherPath(launcher)
	if err != nil {
		fatalPauseAndExit(2, "启动器路径无效：%v", err)
	}
	writeFileLog(fmt.Sprintf("[INFO] [%s] launcher=%s", timestamp(), launcher))

	uiStep("启动检查 1/8：检查 PowerShell 与 Windows 防火墙组件")
	if _, err := powershellExePath(); err != nil {
		fatalPauseAndExit(3, "未找到系统 Windows PowerShell：%v", err)
	}
	if out, err := runPS("(Get-Command Get-NetFirewallProfile).Source"); err != nil || strings.TrimSpace(out) == "" {
		fatalPauseAndExit(3, "Windows 防火墙 PowerShell 命令不可用：%s", out)
	}
	uiOK("PowerShell 与 Windows 防火墙组件可用")

	uiStep("启动检查 2/8：读取当前防火墙状态")
	baselineFW, err := firewallProfiles()
	if err != nil {
		fatalPauseAndExit(3, "无法读取防火墙配置：%v", err)
	}
	for _, n := range []string{"Domain", "Private", "Public"} {
		parts := strings.SplitN(baselineFW[n], "|", 2)
		if len(parts) == 2 {
			uiInfo("  %s 防火墙启用=%s，默认出站=%s", n, parts[1], parts[0])
		} else {
			uiInfo("  %s 防火墙状态=%s", n, baselineFW[n])
		}
	}

	uiStep("启动检查 3/8：识别当前登录用户 SID")
	userSID, err := getUserSID()
	if err != nil {
		fatalPauseAndExit(3, "无法确定当前用户 SID：%v", err)
	}
	uiOK("当前用户 SID：%s", userSID)

	base := filepath.Dir(exePath)
	domainsPath := filepath.Join(base, "AllowedDomains.txt")
	javaFile := filepath.Join(base, "JavaPaths.txt")
	protectedFile := filepath.Join(base, "ProtectedPaths.txt")
	uiStep("启动检查 4/8：加载白名单与 Java 配置")
	endpoints, endpointWarnings, err := loadEndpoints(domainsPath)
	for _, warning := range endpointWarnings {
		uiWarn("AllowedDomains.txt %s；该行保持 BLOCK", warning)
	}
	if err != nil {
		fatalPauseAndExit(3, "AllowedDomains.txt 配置读取失败：%v", err)
	}
	if strict {
		for _, e := range endpoints {
			if len(e.IPs) == 0 {
				uiWarn("白名单目标暂时无法解析：%s:%d；仍保留在允许名单，系统将尝试使用 FQDN 动态白名单", e.Host, e.Port)
				uiInfo("  注意：Windows FQDN 动态规则依赖系统 DNS 查询以及 Defender/Network Protection 条件；若条件不满足，该目标可能暂时继续被 BLOCK。")
				if e.ResolveError != "" {
					writeFileLog(fmt.Sprintf("[WARN] [%s] endpoint unresolved %s:%d :: %s", timestamp(), e.Host, e.Port, e.ResolveError))
				}
				continue
			}
			uiInfo("  ALLOW %s:%d -> %s", e.Host, e.Port, strings.Join(e.IPs, ", "))
			writeFileLog(fmt.Sprintf("[INFO] [%s] endpoint allow %s:%d -> %s", timestamp(), e.Host, e.Port, strings.Join(e.IPs, ",")))
		}
	}
	discovery, javaErr := loadJavaPaths(javaFile, launcher)
	if javaErr != nil {
		if strict {
			fatalPauseAndExit(4, "JavaPaths.txt 配置失败：%v", javaErr)
		}
		uiWarn("JavaPaths.txt 配置未能完整加载：%v；本次仅进行文件保护，不下发 Java 网络规则", javaErr)
	}
	javaPaths := discovery.Paths
	for _, warning := range discovery.Warnings {
		uiWarn("Java 扫描：%s", warning)
	}
	for _, p := range javaPaths {
		uiInfo("用户明确配置的 Java 路径：%s", p)
	}
	for _, p := range discovery.Candidates {
		uiInfo("候选运行时（尚未确认本次使用，不授予规则）：%s", p)
	}
	if strict {
		uiInfo("Watchdog 将核验本次启动链及 Minecraft 参数，再向实际 Java 下发同一组精确白名单；未确认时保持 BLOCK。")
	}
	if launcherAlive, probeErr := processPathAlive(launcher); probeErr != nil {
		fatalPauseAndExit(4, "无法可靠完成启动器预检（尚未 Apply）：%v", probeErr)
	} else if launcherAlive {
		fatalPauseAndExit(4, "指定的 Minecraft 启动器已经在运行，请先关闭它，再启动 GuardLauncher")
	}
	// A Java executable may also be used by IDEs, Gradle, build tools or other apps.
	// Reject only a Java process whose command line is attributable to Minecraft,
	// not every process sharing one of the configured Java runtime paths.
	if existingMinecraft, checkErr := queryMinecraftJavaProcess(Config{SessionStartUtc: "1601-01-01T00:00:00Z", JavaPaths: javaPaths}); checkErr != nil {
		fatalPauseAndExit(4, "无法可靠检查已有 Minecraft 进程（尚未 Apply）：%v", checkErr)
	} else if existingMinecraft {
		fatalPauseAndExit(4, "检测到已有 Minecraft Java 进程；为避免接管其他游戏会话，请先关闭已有 Minecraft，再启动 GuardLauncher")
	}

	uiStep("启动检查 5/8：检查 QQ/Tencent 保护目录")
	protected, protectedErr := readProtectedPaths(protectedFile)
	if protectedErr != nil {
		fatalPauseAndExit(4, "ProtectedPaths.txt 读取失败：%v", protectedErr)
	}
	for i, p := range protected {
		expanded := expandWindowsEnv(p)
		if windowsEnvToken.MatchString(expanded) {
			fatalPauseAndExit(4, "ProtectedPaths.txt 包含无法解析的环境变量：%s；请检查变量名称或使用绝对路径", p)
		}
		protected[i] = expanded
	}
	for _, p := range protected {
		ex := p
		if _, e := os.Stat(ex); e == nil {
			uiOK("  保护目标存在：%s", ex)
		} else {
			uiInfo("  当前不存在（无需处理）：%s", ex)
		}
	}
	uiInfo("管理员保护组件还会自动发现 QQ 的 UserDataSavePath 自定义目录。")

	uiStep("启动检查 6/8：检查保护状态存储")
	programDataRoot := strings.TrimSpace(os.Getenv("ProgramData"))
	if programDataRoot == "" || !filepath.IsAbs(programDataRoot) {
		fatalPauseAndExit(4, "Windows ProgramData 环境变量为空或不是绝对路径：%q", programDataRoot)
	}
	programDataRoot = filepath.Clean(programDataRoot)
	stateRoot := filepath.Join(programDataRoot, "HachimiGuard")
	uiInfo("保护状态目录将由管理员保护组件加固：%q", stateRoot)

	uiStep("启动检查 7/8：记录恢复检查点")
	baselineACL, baselineACLErrors := snapshotConfiguredACLs(protected)
	for _, snapshotErr := range baselineACLErrors {
		uiWarn("恢复诊断基线不完整：%v", snapshotErr)
	}
	uiInfo("已记录 %d 个现有目标的 ACL，用于恢复诊断", len(baselineACL))

	uiStep("启动检查 8/8：显示本次保护策略")
	uiInfo("  * Minecraft 启动器保持普通用户权限运行")
	uiInfo("  * 只有临时保护组件获得 UAC 管理员权限")
	uiInfo("  * 本次会话的网络隔离对 Windows 出站网络全局生效")
	uiInfo("  * 只有配置的启动器/Java 路径获得白名单放行")
	uiInfo("  * QQ/Tencent 路径临时拒绝当前用户访问，结束后仅撤销 Guard 自己添加的规则")
	uiInfo("  * 不修改 hosts；防火墙直接按解析得到的目标 IP 建立规则")
	uiInfo("  * 管理员审计日志：%q", filepath.Join(stateRoot, "audit"))

	group := "HachimiGuard-" + randID()
	writeFileLog(fmt.Sprintf("[INFO] [%s] session group=%s stateRoot=%q", timestamp(), group, stateRoot))
	stateDir := filepath.Join(stateRoot, "session-"+randID())
	logPath := appLogPath
	auditRoot := filepath.Join(stateRoot, "audit")
	auditPath := filepath.Join(auditRoot, "session-"+strings.TrimPrefix(filepath.Base(stateDir), "session-")+".log")
	writeFileLog(fmt.Sprintf("[LIFECYCLE] [%s] planned session paths stateDir=%q auditPath=%q", timestamp(), stateDir, auditPath))
	parentPath, parentPathErr := os.Executable()
	if parentPathErr != nil || strings.TrimSpace(parentPath) == "" {
		fatalPauseAndExit(4, "无法确定 GuardLauncher 自身可执行文件路径：%v", parentPathErr)
	}
	cfg := Config{Group: group, StateDir: stateDir, StateRoot: stateRoot, LauncherPath: launcher, JavaPaths: javaPaths, Endpoints: endpoints, ProtectedPaths: protected, CallerAppData: os.Getenv("APPDATA"), CallerLocalAppData: os.Getenv("LOCALAPPDATA"), CallerUserProfile: os.Getenv("USERPROFILE"), CallerPublic: os.Getenv("PUBLIC"), ParentPID: os.Getpid(), ParentPath: parentPath, SessionStartUtc: time.Now().UTC().Format(time.RFC3339Nano), UserSID: userSID, LogPath: logPath, AuditLogPath: auditPath, NotificationPath: filepath.Join(stateDir, "notifications.ndjson"), Schema: 11, Version: appVersion, WatchdogReadyToken: randID(), Strict: strict}

	if diagnose {
		uiOK("诊断完成：没有修改防火墙或文件权限")
		uiInfo("日志：%s", logPath)
		return
	}

	parentLease, parentLeaseErr := startParentLivenessLease(group)
	if parentLeaseErr != nil {
		// The direct System.Diagnostics.Process probe remains mandatory in the
		// Watchdog. A mutex failure is logged rather than disabling protection.
		writeFileLog(fmt.Sprintf("[WARN] [%s] parent liveness mutex unavailable; Watchdog will also use direct process-handle verification: %v", timestamp(), parentLeaseErr))
		uiWarn("父进程内核存活锁不可用；将启用独立进程核验，并记录兼容性警告")
	} else {
		defer parentLease.Close()
		writeFileLog(fmt.Sprintf("[LIFECYCLE] [%s] parent liveness mutex acquired before UAC; group=%s name=%q", timestamp(), group, parentLivenessMutexName(group)))
	}

	uiStep("执行 1/4：请求临时管理员保护组件")
	if err := runElevated("Apply", cfg, true); err != nil {
		if auditErr := setSessionAuditPath(auditPath, group); auditErr != nil {
			writeFileLog(fmt.Sprintf("[WARN] [%s] session audit was not created by the elevated bootstrap; retaining failure details in the per-run log only: %v", timestamp(), auditErr))
		}
		writeFileLog(fmt.Sprintf("[ERROR] [%s] initial elevated Apply failed: %v", timestamp(), err))
		fatalPauseAndExit(5, "管理员保护组件启动失败：%v", err)
	}
	if auditErr := setSessionAuditPath(auditPath, group); auditErr != nil {
		writeFileLog(fmt.Sprintf("[WARN] [%s] elevated Apply returned success but session audit could not be attached; per-run log remains active: %v", timestamp(), auditErr))
	}
	uiOK("管理员保护组件执行完成")
	initialWatchdog, watchdogErr := waitForWatchdogReady(cfg, 15*time.Second)
	if watchdogErr != nil {
		writeFileLog(fmt.Sprintf("[FATAL] [%s] Watchdog initial readiness failed: %v", timestamp(), watchdogErr))
		fatalPauseAndExit(6, "Watchdog 未能通过心跳与进程身份验证，无法可靠保证自动恢复：%v", watchdogErr)
	}
	if ackErr := writeWatchdogParentReadyAck(cfg); ackErr != nil {
		writeFileLog(fmt.Sprintf("[FATAL] [%s] Watchdog parent-ready acknowledgement failed; Watchdog must retain protection: %v", timestamp(), ackErr))
		fatalPauseAndExit(6, "无法向 Watchdog 确认主程序已完成就绪检查；保护状态将保留：%v", ackErr)
	}
	uiOK("Watchdog 已就绪：PID=%d，状态=%s，心跳序号=%d", initialWatchdog.PID, initialWatchdog.Status, initialWatchdog.Sequence)
	watchdogStop := make(chan struct{})
	watchdogDone := make(chan struct{})
	go superviseWatchdog(cfg, initialWatchdog, watchdogStop, watchdogDone)

	var notificationWG sync.WaitGroup
	notificationStop := make(chan struct{})
	if strict {
		startNotificationMonitor(cfg.NotificationPath, notificationStop, &notificationWG)
		if _, e := os.Stat(filepath.Join(stateDir, "audit_policy.json")); e == nil {
			uiInfo("已启用 Windows 防火墙拦截反馈；受保护进程的出站请求被拦截时会实时显示")
		} else {
			uiWarn("本次未启用 5157 连接审计；防火墙保护仍会继续，但窗口不会显示每次拦截")
		}
	}

	uiStep("执行 2/4：自检当前网络隔离")
	if strict {
		nowFW, e := firewallProfilesActive()
		if e != nil {
			fatalPauseAndExit(6, "无法验证 Windows 防火墙实际生效策略（ActiveStore）：%v", e)
		}
		ok := true
		for _, n := range []string{"Domain", "Private", "Public"} {
			parts := strings.SplitN(nowFW[n], "|", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Block") || !strings.EqualFold(parts[1], "True") {
				ok = false
			}
			if len(parts) == 2 {
				uiInfo("  %s 防火墙启用=%s，默认出站=%s", n, parts[1], parts[0])
			} else {
				uiInfo("  %s 防火墙状态无法解析：%s", n, nowFW[n])
			}
		}
		if !ok {
			fatalPauseAndExit(6, "Windows 防火墙 ActiveStore 实际生效策略没有全部进入 BLOCK 状态，或本地规则未生效；网络隔离无法保证")
		}
		count, e := guardRuleCount(group)
		if e != nil {
			fatalPauseAndExit(6, "无法读取 HachimiGuard 防火墙规则：%v", e)
		}
		if count == 0 {
			intentionalBlockOnly, activeErr := activeEndpointListIsEmpty(stateDir)
			if activeErr != nil || !intentionalBlockOnly {
				fatalPauseAndExit(6, "没有检测到 HachimiGuard 防火墙允许规则，且无法确认这是有意的 BLOCK-only 降级状态；网络保护可能未生效")
			}
			uiWarn("当前没有可用的静态 IP 或 FQDN 白名单目标；防火墙仍保持默认出站 BLOCK（BLOCK-only）")
			uiWarn("Minecraft 启动器可能无法登录或下载；请检查网络/DNS/DoH 条件后重新启动保护会话")
		} else {
			uiOK("检测到 %d 条 HachimiGuard 防火墙规则", count)
		}
	}

	uiStep("执行 3/4：自检 QQ/Tencent 文件保护")
	aclChecks := 0
	aclGood := 0
	for _, p := range protected {
		ex := expandWindowsEnv(p)
		if _, e := os.Stat(ex); e == nil {
			aclChecks++
			good, checkErr := hasDenyForSID(ex, userSID)
			if checkErr != nil {
				uiErr("  ACL 读取失败：%s：%v", ex, checkErr)
			}
			if good && checkErr == nil {
				aclGood++
				uiOK("  deny rule confirmed: %s", ex)
			} else if checkErr == nil {
				uiWarn("  没有适用于目标本身的 FullControl Deny：%s", ex)
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			aclChecks++
			uiErr("无法读取目标状态：%s：%v", ex, e)
		}
	}
	if aclGood != aclChecks {
		fatalPauseAndExit(7, "ACL 自检未通过：已有配置目标中仅 %d/%d 个受到保护；为避免在保护不完整时启动，已中止本次启动", aclGood, aclChecks)
	}
	uiOK("ACL 自检：已有配置目标中 %d/%d 个受到保护", aclGood, aclChecks)

	uiStep("执行 4/4：启动 Minecraft 启动器")
	cmd := exec.Command(launcher, launcherArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		uiFatal("Minecraft 启动器启动失败：%v", err)
		uiWarn("隐藏的 Watchdog 仍会尝试执行自动恢复")
		uiFatal("按任意键退出")
		closeLog()
		waitForAnyKey()
		os.Exit(8)
	}
	uiOK("Minecraft 启动器已启动，PID=%d", cmd.Process.Pid)
	uiInfo("保护已经生效。正常关闭 Minecraft 即可，GuardLauncher 会自动恢复系统状态。")

	javaLast := false
	javaStateKnown := false
	checkJava := func() (bool, bool) {
		// Match the elevated Helper and Watchdog: explicit Minecraft arguments, or a
		// configured Java executable descended from this session's launcher/parent.
		alive, probeErr := queryMinecraftJavaProcess(cfg)
		if probeErr != nil {
			javaProcessProbeWarning.Do(func() {
				writeFileLog(fmt.Sprintf("[WARN] [%s] 无法可靠查询 Minecraft Java 进程归属；为避免提前恢复，暂按仍有受保护进程处理：%v", timestamp(), probeErr))
			})
			return true, false
		}
		return alive, true
	}
	doneMon := make(chan struct{})
	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		defer close(doneMon)
		defer func() {
			if recovered := recover(); recovered != nil {
				writeFileLog(fmt.Sprintf("[CRASH] [%s] Minecraft process monitor panic: %v\n%s", timestamp(), recovered, debug.Stack()))
			}
		}()
		seenJava := false
		launcherExitAt := time.Time{}
		for range t.C {
			alive, known := checkJava()
			if known {
				if alive && (!javaStateKnown || !javaLast) {
					uiOK("检测到受保护的 Minecraft Java 进程")
				}
				if !alive && javaStateKnown && javaLast {
					uiInfo("受保护的 Minecraft Java 进程已退出")
				}
				javaLast = alive
				javaStateKnown = true
			}
			// Unknown is treated as potentially alive for lifecycle safety, but is
			// not reported to the player as a confirmed Minecraft process.
			if alive {
				seenJava = true
			}
			if !processIDAlive(cmd.Process.Pid) {
				if launcherExitAt.IsZero() {
					launcherExitAt = time.Now()
				}
			} else {
				launcherExitAt = time.Time{}
			}
			if known && !alive && seenJava {
				return
			}
			// Allow a launcher that exits before its Java child is fully visible to hand off.
			if !seenJava && !launcherExitAt.IsZero() && time.Since(launcherExitAt) >= 30*time.Second {
				return
			}
		}
	}()

	err = cmd.Wait()
	if err != nil {
		uiWarn("Minecraft 启动器退出，返回信息：%v", err)
	} else {
		uiOK("Minecraft launcher process exited normally")
	}
	uiInfo("正在等待 Watchdog 确认所有受保护的 Java 进程退出…")
	monitorCompleted := false
	select {
	case <-doneMon:
		monitorCompleted = true
	case <-time.After(30 * time.Second):
		uiWarn("Java 进程监控尚未确认退出；不会仅凭超时撤销保护，将继续等待 Watchdog 或进程监控给出明确结果")
		writeFileLog(fmt.Sprintf("[WARN] [%s] main process monitor exceeded 30s; protection remains active until an attributed-process check or Watchdog confirms exit", timestamp()))
	}
	if !monitorCompleted {
		// Give WMI and the independent Watchdog time to recover. A state-directory
		// removal is accepted only as Watchdog's completed restore signal. A timeout
		// alone must never authorize the final Restore helper.
		deadline := time.NewTimer(120 * time.Second)
		statePoll := time.NewTicker(1 * time.Second)
		waiting := true
		for waiting {
			select {
			case <-doneMon:
				monitorCompleted = true
				waiting = false
			case <-statePoll.C:
				if _, stateErr := os.Stat(stateDir); os.IsNotExist(stateErr) {
					writeFileLog(fmt.Sprintf("[LIFECYCLE] [%s] Watchdog removed session state after completed restoration", timestamp()))
					waiting = false
				}
			case <-deadline.C:
				waiting = false
			}
		}
		statePoll.Stop()
		deadline.Stop()
	}
	close(watchdogStop)
	<-watchdogDone
	if !monitorCompleted {
		if _, stateErr := os.Stat(stateDir); stateErr == nil {
			close(notificationStop)
			notificationWG.Wait()
			fatalPauseAndExit(9, "无法可靠确认 Minecraft 进程已退出，且 Watchdog 尚未完成恢复；为避免误解除保护，恢复状态已保留。请保留日志并在下一次启动时执行遗留会话恢复。日志：%s", logPath)
		}
	}
	if _, stateErr := os.Stat(stateDir); stateErr == nil && monitorCompleted {
		writeFileLog(fmt.Sprintf("[RETRY] [%s] Watchdog has not removed session state after confirmed game exit; requesting elevated final Restore", timestamp()))
		if restoreErr := runElevated("Restore", cfg, true); restoreErr != nil {
			writeFileLog(fmt.Sprintf("[ERROR] [%s] elevated final Restore failed; stale recovery data retained: %v", timestamp(), restoreErr))
		} else {
			writeFileLog(fmt.Sprintf("[SUCCEED] [%s] elevated final Restore completed", timestamp()))
		}
	}
	for i := 0; i < 120; i++ {
		nowFW, e := firewallProfiles()
		rules, re := guardRuleCount(group)
		restored := e == nil && compareProfiles(nowFW, baselineFW) && re == nil && rules == 0
		aclRestored := len(baselineACLErrors) == 0
		for p, baselineSDDL := range baselineACL {
			currentSDDL, aclErr := pathACL(p)
			if aclErr != nil || currentSDDL != baselineSDDL {
				aclRestored = false
				break
			}
		}
		stateRemoved := false
		if _, stateErr := os.Stat(stateDir); os.IsNotExist(stateErr) {
			stateRemoved = true
		}
		if restored && aclRestored && stateRemoved {
			close(notificationStop)
			notificationWG.Wait()
			uiOK("最终自检成功：防火墙与 Guard 添加的文件保护都已恢复")
			uiInfo("本次保护会话结束，临时系统修改已经恢复。")
			return
		}
		time.Sleep(1 * time.Second)
	}
	close(notificationStop)
	notificationWG.Wait()
	fatalPauseAndExit(9, "最终自检失败或在 120 秒内未完成恢复；日志：%s。下一次启动也会继续尝试恢复遗留会话。", logPath)
}

func readWatchdogHeartbeat(stateDir string) (watchdogHeartbeat, error) {
	var heartbeat watchdogHeartbeat
	path := filepath.Join(stateDir, "watchdog.heartbeat.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return heartbeat, fmt.Errorf("读取 Watchdog 心跳失败：%w", err)
	}
	if err := json.Unmarshal(data, &heartbeat); err != nil {
		return heartbeat, fmt.Errorf("Watchdog 心跳 JSON 损坏：%w", err)
	}
	if heartbeat.Schema != 1 || heartbeat.PID <= 0 || heartbeat.Group == "" || heartbeat.ProcessCreatedUtc == "" || heartbeat.HeartbeatUtc == "" {
		return heartbeat, errors.New("Watchdog 心跳字段缺失或版本不受支持")
	}
	beatAt, err := time.Parse(time.RFC3339Nano, heartbeat.HeartbeatUtc)
	if err != nil {
		return heartbeat, fmt.Errorf("Watchdog 心跳时间无效：%w", err)
	}
	age := time.Since(beatAt)
	if age < -5*time.Second {
		return heartbeat, fmt.Errorf("Watchdog 心跳时间异常地位于未来：%s", heartbeat.HeartbeatUtc)
	}
	if age > 60*time.Second {
		return heartbeat, fmt.Errorf("Watchdog 心跳已过期：age=%s status=%s", age.Round(time.Millisecond), heartbeat.Status)
	}
	return heartbeat, nil
}

func queryProcessIdentity(pid int) (processIdentity, error) {
	var identity processIdentity
	if pid <= 0 {
		return identity, errors.New("invalid process id")
	}
	// Limited query rights allow the ordinary parent to inspect its elevated
	// Watchdog without PROCESS_VM_READ or a WMI provider dependency.
	handle, err := syscall.OpenProcess(0x1000, false, uint32(pid))
	if err != nil {
		return identity, fmt.Errorf("OpenProcess limited query PID=%d：%w", pid, err)
	}
	defer syscall.CloseHandle(handle)
	imageName := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	ok, _, callErr := imageName.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if ok == 0 {
		return identity, fmt.Errorf("QueryFullProcessImageNameW PID=%d：%w", pid, callErr)
	}
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return identity, fmt.Errorf("GetProcessTimes PID=%d：%w", pid, err)
	}
	identity = processIdentity{PID: pid, Executable: syscall.UTF16ToString(buffer[:length]), CreationDate: time.Unix(0, created.Nanoseconds()).UTC().Format(time.RFC3339Nano)}
	if identity.Executable == "" {
		return identity, errors.New("原生进程身份缺少映像路径")
	}
	return identity, nil
}

func verifyWatchdogIdentity(cfg Config, heartbeat watchdogHeartbeat, expectedPID int) error {
	pidPath := filepath.Join(cfg.StateDir, "watchdog.pid")
	pidBytes, err := os.ReadFile(pidPath)
	if err != nil {
		return fmt.Errorf("Watchdog PID 文件不可读：%w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid != expectedPID || heartbeat.PID != expectedPID {
		return fmt.Errorf("Watchdog PID 不匹配：pidfile=%q heartbeat=%d expected=%d", strings.TrimSpace(string(pidBytes)), heartbeat.PID, expectedPID)
	}
	if heartbeat.Group != cfg.Group {
		return fmt.Errorf("Watchdog 会话组不匹配：got=%s expected=%s", heartbeat.Group, cfg.Group)
	}
	if !processIDAlive(expectedPID) {
		return fmt.Errorf("Watchdog PID=%d 已退出", expectedPID)
	}
	actual, err := queryProcessIdentity(expectedPID)
	if err != nil {
		return err
	}
	expectedPS, err := powershellExePath()
	if err != nil {
		return err
	}
	actualPath, err := filepath.Abs(actual.Executable)
	if err != nil {
		return err
	}
	expectedPath, err := filepath.Abs(expectedPS)
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(actualPath), filepath.Clean(expectedPath)) {
		return fmt.Errorf("Watchdog 可执行文件身份不匹配：%s", actual.Executable)
	}
	actualCreated, err := time.Parse(time.RFC3339Nano, actual.CreationDate)
	if err != nil {
		return fmt.Errorf("Watchdog 实际创建时间无法解析：%w", err)
	}
	expectedCreated, err := time.Parse(time.RFC3339Nano, heartbeat.ProcessCreatedUtc)
	if err != nil {
		return fmt.Errorf("Watchdog 心跳创建时间无法解析：%w", err)
	}
	delta := actualCreated.Sub(expectedCreated)
	if delta < 0 {
		delta = -delta
	}
	if delta > 3*time.Second {
		return fmt.Errorf("Watchdog PID 可能已被复用：实际创建时间=%s 心跳创建时间=%s", actualCreated.UTC(), expectedCreated.UTC())
	}
	return nil
}

func writeWatchdogParentReadyAck(cfg Config) error {
	if strings.TrimSpace(cfg.AuditLogPath) == "" || strings.TrimSpace(cfg.WatchdogReadyToken) == "" || cfg.ParentPID <= 0 || strings.TrimSpace(cfg.Group) == "" {
		return errors.New("Watchdog parent-ready acknowledgement configuration is incomplete")
	}
	path := cfg.AuditLogPath + ".watchdog.parent_ready.json"
	ack := watchdogParentReadyAck{Schema: 1, Group: cfg.Group, ParentPID: cfg.ParentPID, Token: cfg.WatchdogReadyToken, ReadyUtc: time.Now().UTC().Format(time.RFC3339Nano)}
	data, err := json.Marshal(ack)
	if err != nil {
		return fmt.Errorf("encode Watchdog parent-ready acknowledgement: %w", err)
	}
	// Helper pre-creates this file and grants the caller write access. Do not
	// create a new file in the protected ProgramData audit directory here.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("open pre-authorized Watchdog parent-ready file %q: %w", path, err)
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write Watchdog parent-ready acknowledgement: %w", err)
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("flush Watchdog parent-ready acknowledgement: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close Watchdog parent-ready acknowledgement: %w", err)
	}
	writeFileLog(fmt.Sprintf("[LIFECYCLE] [%s] Watchdog parent-ready acknowledgement committed group=%s parentPID=%d path=%q", timestamp(), cfg.Group, cfg.ParentPID, path))
	return nil
}

func validateWatchdogSessionState(cfg Config) (int, error) {
	if strings.TrimSpace(cfg.StateDir) == "" {
		return 0, errors.New("Watchdog StateDir is empty")
	}
	info, err := os.Stat(cfg.StateDir)
	if err != nil {
		return 0, fmt.Errorf("Watchdog StateDir unavailable %q: %w", cfg.StateDir, err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("Watchdog StateDir is not a directory: %q", cfg.StateDir)
	}
	metaPath := filepath.Join(cfg.StateDir, "session.json")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return 0, fmt.Errorf("read Watchdog session metadata %q: %w", metaPath, err)
	}
	// PowerShell writes session.json as UTF-8 without a BOM. Accept a legacy
	// UTF-8 BOM if present, but reject invalid UTF-8 instead of allowing
	// encoding/json to replace malformed bytes in identity/path fields.
	metaBytes = bytes.TrimPrefix(metaBytes, []byte{0xEF, 0xBB, 0xBF})
	if !utf8.Valid(metaBytes) {
		return 0, fmt.Errorf("Watchdog session metadata %q is not valid UTF-8", metaPath)
	}
	var meta Config
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return 0, fmt.Errorf("decode Watchdog session metadata %q: %w", metaPath, err)
	}
	if meta.Group != cfg.Group || meta.Schema != cfg.Schema || meta.Version != cfg.Version || meta.ParentPID != cfg.ParentPID || meta.WatchdogReadyToken != cfg.WatchdogReadyToken || !strings.EqualFold(filepath.Clean(meta.StateDir), filepath.Clean(cfg.StateDir)) {
		return 0, fmt.Errorf("Watchdog session metadata identity mismatch: group=%q schema=%d version=%q parentPID=%d stateDir=%q", meta.Group, meta.Schema, meta.Version, meta.ParentPID, meta.StateDir)
	}
	pidPath := filepath.Join(cfg.StateDir, "watchdog.pid")
	pidBytes, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, fmt.Errorf("read Watchdog PID metadata %q: %w", pidPath, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid Watchdog PID metadata %q: %q", pidPath, strings.TrimSpace(string(pidBytes)))
	}
	return pid, nil
}

func waitForWatchdogReady(cfg Config, timeout time.Duration) (watchdogHeartbeat, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	missingStateDirObservations := 0
	for time.Now().Before(deadline) {
		watchdogPIDFromState, stateErr := validateWatchdogSessionState(cfg)
		if stateErr != nil {
			// validateWatchdogSessionState wraps os.Stat errors with %w; errors.Is
			// is required to recognize the underlying Windows ERROR_FILE_NOT_FOUND.
			if errors.Is(stateErr, os.ErrNotExist) || strings.Contains(strings.ToLower(stateErr.Error()), "not a directory") {
				missingStateDirObservations++
			}
			lastErr = fmt.Errorf("会话状态目录/身份文件尚不可用（观察次数=%d）：%w", missingStateDirObservations, stateErr)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		hb, err := readWatchdogHeartbeat(cfg.StateDir)
		if err == nil {
			if hb.Group != cfg.Group {
				lastErr = fmt.Errorf("Watchdog group mismatch: %s", hb.Group)
			} else if hb.Status != "Starting" && hb.Status != "Monitoring" {
				lastErr = fmt.Errorf("Watchdog 状态尚未就绪：%s %s", hb.Status, hb.Message)
			} else if hb.PID != watchdogPIDFromState {
				lastErr = fmt.Errorf("Watchdog PID file/heartbeat mismatch: pidFile=%d heartbeat=%d", watchdogPIDFromState, hb.PID)
			} else if err = verifyWatchdogIdentity(cfg, hb, hb.PID); err == nil {
				return hb, nil
			} else {
				lastErr = err
			}
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("尚未收到 Watchdog 就绪心跳")
	}
	diagnostics := readWatchdogStartupDiagnostics(cfg.AuditLogPath)
	if diagnostics != "" {
		return watchdogHeartbeat{}, fmt.Errorf("等待 Watchdog 就绪超时：%w；Watchdog 诊断：%s", lastErr, diagnostics)
	}
	return watchdogHeartbeat{}, fmt.Errorf("等待 Watchdog 就绪超时：%w", lastErr)
}

func readWatchdogStartupDiagnostics(auditLogPath string) string {
	auditLogPath = strings.TrimSpace(auditLogPath)
	if auditLogPath == "" {
		return ""
	}
	files := []string{"watchdog.startup.log", "watchdog.stderr.log", "watchdog.stdout.log"}
	var parts []string
	for _, name := range files {
		path := auditLogPath + "." + name
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		const maxBytes = 4096
		if len(data) > maxBytes {
			data = data[len(data)-maxBytes:]
		}
		text := strings.TrimSpace(string(data))
		if text != "" {
			parts = append(parts, name+"="+strings.ReplaceAll(text, "\r\n", " | "))
		}
	}
	return strings.Join(parts, " ; ")
}

func superviseWatchdog(cfg Config, initial watchdogHeartbeat, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	defer func() {
		if recovered := recover(); recovered != nil {
			writeFileLog(fmt.Sprintf("[CRASH] [%s] Watchdog supervisor panic; failing the main process so no silent unsupervised session continues: %v\n%s", timestamp(), recovered, debug.Stack()))
			panic(recovered)
		}
	}()
	currentPID := initial.PID
	lastIdentityCheck := time.Now()
	resumeAttempted := false
	lastWarning := time.Time{}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	writeFileLog(fmt.Sprintf("[LIFECYCLE] [%s] Watchdog supervision started pid=%d created=%s", timestamp(), currentPID, initial.ProcessCreatedUtc))
	for {
		select {
		case <-stop:
			writeFileLog(fmt.Sprintf("[LIFECYCLE] [%s] Watchdog supervisor stopped", timestamp()))
			return
		case <-ticker.C:
		}
		if _, err := os.Stat(cfg.StateDir); os.IsNotExist(err) {
			writeFileLog(fmt.Sprintf("[LIFECYCLE] [%s] session state directory removed; restoration completed", timestamp()))
			return
		}
		hb, err := readWatchdogHeartbeat(cfg.StateDir)
		if err == nil && hb.PID != currentPID {
			err = fmt.Errorf("Watchdog heartbeat PID changed unexpectedly: got=%d expected=%d", hb.PID, currentPID)
		}
		if err == nil && time.Since(lastIdentityCheck) >= 12*time.Second {
			err = verifyWatchdogIdentity(cfg, hb, currentPID)
			lastIdentityCheck = time.Now()
		} else if err == nil && !processIDAlive(currentPID) {
			err = fmt.Errorf("Watchdog PID=%d no longer exists", currentPID)
		}
		if err == nil {
			switch hb.Status {
			case "Restored":
				writeFileLog(fmt.Sprintf("[LIFECYCLE] [%s] Watchdog reported restoration complete", timestamp()))
				return
			case "Failed":
				err = fmt.Errorf("Watchdog reported a fatal lifecycle failure: %s", hb.Message)
			default:
				continue
			}
		}
		if lastWarning.IsZero() || time.Since(lastWarning) >= 15*time.Second {
			writeFileLog(fmt.Sprintf("[ERROR] [%s] Watchdog health check failed: %v", timestamp(), err))
			lastWarning = time.Now()
		}
		if resumeAttempted {
			continue
		}
		resumeAttempted = true
		writeFileLog(fmt.Sprintf("[RETRY] [%s] requesting elevated Watchdog recovery for group=%s", timestamp(), cfg.Group))
		if resumeErr := runElevated("ResumeWatchdog", cfg, true); resumeErr != nil {
			writeFileLog(fmt.Sprintf("[ERROR] [%s] elevated Watchdog recovery failed; session state retained: %v", timestamp(), resumeErr))
			continue
		}
		if _, stateErr := os.Stat(cfg.StateDir); os.IsNotExist(stateErr) {
			writeFileLog(fmt.Sprintf("[SUCCEED] [%s] replacement Watchdog completed restoration before a new heartbeat could be observed", timestamp()))
			return
		}
		restarted, readyErr := waitForWatchdogReady(cfg, 40*time.Second)
		if readyErr != nil {
			writeFileLog(fmt.Sprintf("[ERROR] [%s] replacement Watchdog did not become ready; session state retained: %v", timestamp(), readyErr))
			continue
		}
		if ackErr := writeWatchdogParentReadyAck(cfg); ackErr != nil {
			writeFileLog(fmt.Sprintf("[ERROR] [%s] replacement Watchdog parent-ready acknowledgement failed; protection retained: %v", timestamp(), ackErr))
			continue
		}
		currentPID = restarted.PID
		lastIdentityCheck = time.Now()
		resumeAttempted = false
		lastWarning = time.Time{}
		writeFileLog(fmt.Sprintf("[SUCCEED] [%s] Watchdog recovered pid=%d sequence=%d", timestamp(), currentPID, restarted.Sequence))
	}
}

func processPathAlive(path string) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, nil
	}
	expr := fmt.Sprintf("$q='%s'; Get-CimInstance -ClassName Win32_Process -OperationTimeoutSec 8 -ErrorAction Stop | ForEach-Object { try { if($_.ExecutablePath -and ([IO.Path]::GetFullPath($_.ExecutablePath) -ieq ([IO.Path]::GetFullPath($q)))) { 'YES' } } catch {} }", strings.ReplaceAll(path, "'", "''"))
	out, err := runPS(expr)
	if err != nil {
		return false, fmt.Errorf("CIM 启动器预检失败：%w；输出=%s", err, out)
	}
	return strings.Contains(out, "YES"), nil
}

func processIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// A successful os.FindProcess is not enough on Windows; ask PowerShell.
	out, err := runPS(fmt.Sprintf("if(Get-Process -Id %d -ErrorAction SilentlyContinue){'YES'}else{'NO'}", pid))
	return err == nil && strings.TrimSpace(out) == "YES"
}

var javaProcessProbeWarning sync.Once

func queryMinecraftJavaProcess(cfg Config) (bool, error) {
	probeConfig := struct {
		SessionStartUtc string   `json:"sessionStartUtc"`
		LauncherPath    string   `json:"launcherPath"`
		JavaPaths       []string `json:"javaPaths"`
		ParentPID       int      `json:"parentPid"`
		ParentPath      string   `json:"parentPath"`
		Group           string   `json:"group"`
	}{cfg.SessionStartUtc, cfg.LauncherPath, cfg.JavaPaths, cfg.ParentPID, cfg.ParentPath, cfg.Group}
	raw, err := json.Marshal(probeConfig)
	if err != nil {
		return false, fmt.Errorf("encode process attribution config: %w", err)
	}
	query := strings.ReplaceAll(javaProcessProbeScript, "__JAVA_PROCESS_FUNCTIONS__", powershellJavaProcessFunctions)
	query = strings.ReplaceAll(query, "__SESSION_B64__", base64.StdEncoding.EncodeToString(raw))
	out, err := runPS(query)
	if err != nil {
		return false, fmt.Errorf("query Win32_Process: %w; output=%s", err, strings.TrimSpace(out))
	}
	switch strings.TrimSpace(out) {
	case "YES":
		return true, nil
	case "NO":
		return false, nil
	case "UNKNOWN_ALIVE":
		return false, errors.New("CIM 不可用；原生通道发现尚不能归属的 Java，保持保护且不宣称已确认 Minecraft")
	default:
		return false, fmt.Errorf("unexpected process probe output: %q", strings.TrimSpace(out))
	}
}

func hideConsole() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	user32 := syscall.NewLazyDLL("user32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	showWindow := user32.NewProc("ShowWindow")
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd != 0 {
		const swHide = 0
		_, _, _ = showWindow.Call(hwnd, swHide)
	}
}
