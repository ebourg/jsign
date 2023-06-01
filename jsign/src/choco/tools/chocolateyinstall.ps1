$toolsdir = Split-Path -parent $MyInvocation.MyCommand.Definition
$jsign_cmd = Join-Path $toolsdir 'jsign.cmd'

Install-BinFile -Name jsign -Path $jsign_cmd
