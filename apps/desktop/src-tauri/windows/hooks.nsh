; Allow incoming UDP to homelink so a Windows host is reachable through the
; forwarded port. Runs elevated because the installer is per-machine.
!macro NSIS_HOOK_POSTINSTALL
  nsExec::Exec 'netsh advfirewall firewall delete rule name="homelink"'
  nsExec::Exec 'netsh advfirewall firewall add rule name="homelink" dir=in action=allow protocol=UDP program="$INSTDIR\${MAINBINARYNAME}.exe" enable=yes profile=any'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::Exec 'netsh advfirewall firewall delete rule name="homelink"'
!macroend
