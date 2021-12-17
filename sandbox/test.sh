#!/bin/bash
FLAG_VALUE=$1
echo "[+] JDK"
java -version
echo "[+] TEST"
while IFS= read -r line
do
  mvn -q -D"log4j2.target.version=$line" -D"log4j2.formatMsgNoLookups=$FLAG_VALUE" clean test 1>/dev/null
  rc=$?
  v=$(cat target/Log4ShellExposureTest.out | head -1)
  echo ">>> $v - RC: $rc"
  if [ $rc -ne 0 ]
  then
    echo "<<< Version $line flag log4j2.formatMsgNoLookups NOT effective."
  else
    echo "<<< Version $line flag log4j2.formatMsgNoLookups IS effective."
  fi
done < "versions.txt"