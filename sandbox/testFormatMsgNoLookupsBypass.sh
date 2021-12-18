#!/bin/bash
echo "[+] JDK"
java -version
echo "[+] TEST"
while IFS= read -r line
do
  mvn -q -D"test=Log4ShellExposureTestFormatMsgNoLookupsBypass" -D"log4j2.target.version=$line" -D"log4j2.formatMsgNoLookups=true" clean test 1>/dev/null
  rc1=$?
  mvn -q -D"test=Log4ShellExposureTestFormatMsgNoLookupsBypassWithPrintf" -D"log4j2.target.version=$line" -D"log4j2.formatMsgNoLookups=true" clean test 1>/dev/null
  rc2=$?
  rc=$(($rc1 + $rc2))
  echo ">>> RC: $rc"
  if [ $rc -ne 0 ]
  then
    echo "<<< Version $line flag log4j2.formatMsgNoLookups NOT effective."
  else
    echo "<<< Version $line flag log4j2.formatMsgNoLookups IS effective."
  fi
done < "versions.txt"