#!/bin/bash
echo "[+] JDK"
java -version
echo "[+] TEST"
while IFS= read -r line
do
  mvn -q -D"test=Log4ShellDOSExposureTest" -D"log4j2.target.version=$line" -D"log4j2.formatMsgNoLookups=true" clean test 1>/dev/null 2>&1
  rc=$?
  if [ $rc -ne 0 ]
  then
    echo "[RC: $rc] Version $line IS vulnerable."
  else
    echo "[RC: $rc] Version $line IS NOT vulnerable."
  fi
done < "all-versions.txt"