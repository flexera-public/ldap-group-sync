# ---
# RightScript Name: Windows - RightScale Group Sync Monitor
# Description: Installs RightScale Group Sync specific monitoring.
# Inputs: {}
# Attachments:
#   - GroupSyncMonitor.ps1
# ...
#

$attachDir = $Env:RS_ATTACH_DIR
if (!$attachDir) {
  $attachDir = [System.IO.Path]::GetFullPath(".\attachments")
}

rsc rl10 create /rll/tss/exec/group_sync_monitor executable=$([io.path]::combine($attachDir, "GroupSyncMonitor.ps1"))