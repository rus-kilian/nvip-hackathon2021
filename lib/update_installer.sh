#!/bin/bash
[ -d /var/lib/bcn_updates ]||exit 0
UPDATES=$(ls -1 /var/lib/bcn_updates/*.run 2>/dev/null)
[ -n "$UPDATES" ]||exit 0
for update in $UPDATES;do
  echo "Installing: $update" >>/var/log/update_installer.log
  chmod +x $update
  echo "--------------------- UPDATE LOG OUTPUT ------------------------------------" >>/var/log/update_installer.log
  echo yes|$update >>/var/log/update_installer.log
  ret=$?
  echo "------------------- END: UPDATE LOG OUTPUT ---------------------------------" >>/var/log/update_installer.log
  echo "Exit code: $ret"
  if [ $ret -eq 42 ];then
    echo "Update ${update} is already installed" >>/var/log/update_installer.log
  fi
  # skipping removal upon error
  [ $ret -eq 1 ]||rm -f $update
  rm -f $update
  if [ $ret -eq 99 -o -f /usr/local/bluecat/updates/.rbf -o -n "$(ps --no-headers -F -C plymouthd)" ];then
    echo "Reboot performed by update itself. Waiting for shutdown" >>/var/log/update_installer.log
    sleep 300
    exit 0
  fi
  echo "Finished installing: $update" >>/var/log/update_installer.log
done
echo "Completed $0 run"
exit 0

