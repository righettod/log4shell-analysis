#!/bin/bash
#########################################################################################################
# Script to identify code prone to CVE-2021-45046/CVE-2021-45105 in a collection of EAR/WAR/JAR files
# Based on this script:
# https://github.com/righettod/log4shell-analysis/blob/main/scripts/identify-log4j-class-location.sh
#########################################################################################################
#####
# Requirements
# 1) A release jar file from the project "https://github.com/intoolswetrust/jd-cli" must be present in the current folder.
# 2) Same for java binary, it must available in $PATH.
####
# Constants
JAR_FOUND=0
APP_LIBS_FOLDER=$1
WORK_FOLDER=/tmp/work
JAR_WORK_FOLDER=/tmp/jarwork
JAR_SRC_WORK_FOLDER=/tmp/jarsrcwork
NESTED_JAR_WORK_FOLDER=/tmp/nestedjarwork
CDIR=$(pwd)
DECOMPILER_JAR_FILE="jd-cli.jar"
IGNORE_LOG4J_ARTEFACTS=0
# See https://unix.stackexchange.com/a/9499
OIFS="$IFS"
IFS=$'\n'
if [ "$#" -lt 1 ]; then
    script_name=$(basename "$0")
    echo "Usage:"
    echo "   $script_name [BASE_SEARCH_FOLDER] [--ignore-log4j2-artefacts]"
    echo ""
    echo "Call example:"
    echo "    $script_name /apps"
	echo "    $script_name /apps --ignore-log4j2-artefacts"
    exit 1
fi
if [ "$#" -eq 2 ]; then
	IGNORE_LOG4J_ARTEFACTS=1
	echo -e "\e[93m[+] Exclude Log4J artefacts.\e[0m"
else
	IGNORE_LOG4J_ARTEFACTS=0
	echo -e "\e[93m[+] Include Log4J artefacts.\e[0m"
fi
# Check requirement
java -version 1>/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "Java not in PATH:"
	java -version
	exit 1
fi
if [ ! -f "$DECOMPILER_JAR_FILE" ]; then
	echo "Decompiler jar file not in current folder!"
	exit 1
fi
# Utility functions
inspect_jar_source_code(){
	jar_file_location=$1
	# Verify if the current jar file is part of the log4j artefacts and if the user want to exclude them from the search
	is_log4j_artfact=$(unzip -l "$jar_file_location" | grep -c "org/apache/logging/log4j")
	if [ $is_log4j_artfact -ne 0 -a $IGNORE_LOG4J_ARTEFACTS -eq 1 ];
	then
		return
	fi
	rm -rf "$JAR_SRC_WORK_FOLDER" 2>/dev/null
	mkdir "$JAR_SRC_WORK_FOLDER"
	# Decompile the jar file
	java -jar $CDIR/jd-cli.jar --logLevel OFF --outputDir "$JAR_SRC_WORK_FOLDER" "$jar_file_location"
	#Search usage of TCM across the files
	found1=$(grep -r --include "*.java" -nwE '(ThreadContext\.put|import\sorg\.apache\.logging\.log4j\.ThreadContext)' $JAR_SRC_WORK_FOLDER | wc -l)
	found2=$(grep -r --include "*.java" --include "*.properties" --include "*.xml" --include "*.json" --include "*.yaml" --include "*.yml" -nwE '%(X|mdc|MDC)\{\s*.*?\s*\}' $JAR_SRC_WORK_FOLDER | wc -l)
	found=$(($found1 + $found2))
	if [ $found -ne 0 ];
	then
		JAR_FOUND=1
		echo -e "\e\n[91m[!] Usage of the Thread Context Map identified in decompiled sources of the jar file '$jar_file_location':\e[0m"
		grep --color -r --include "*.java" -nwE '(ThreadContext\.put|import\sorg\.apache\.logging\.log4j\.ThreadContext)' $JAR_SRC_WORK_FOLDER
		grep --color -r --include "*.java" --include "*.properties" --include "*.xml" --include "*.json" --include "*.yaml" --include "*.yml" -nwE '%(X|mdc|MDC)\{\s*.*?\s*\}' $JAR_SRC_WORK_FOLDER
	fi
	found=$(grep -r --include "*.java" --include "*.properties" --include "*.xml" --include "*.json" --include "*.yaml" --include "*.yml" -nwE '\$\{\s*(ctx|log4j|sys|env|main|marker|java|base64|lower|upper|sd|map|jndi|jvmrunargs|date|event|bundle):.*?\s*\}' $JAR_SRC_WORK_FOLDER | wc -l)
	if [ $found -ne 0 ];		
	then
		JAR_FOUND=1
		echo -e "\e\n[91m[!] Usage of Expressions identified in decompiled sources of the jar file '$jar_file_location':\e[0m"
		grep --color -r --include "*.java" --include "*.properties" --include "*.xml" --include "*.json" --include "*.yaml" --include "*.yml" -nwE '\$\{\s*(ctx|log4j|sys|env|main|marker|java|base64|lower|upper|sd|map|jndi|jvmrunargs|date|event|bundle):.*?\s*\}' $JAR_SRC_WORK_FOLDER
	fi		
	rm -rf "$JAR_SRC_WORK_FOLDER" 2>/dev/null
}
inspect_folder (){
	folder_location=$1
	for jar_lib in $(find "$folder_location" -type f -iname "*.jar")
	do
		inspect_jar_file "$jar_lib"
	done
}
inspect_jar_file(){
	jar_file_location=$1
	inspect_jar_source_code "$jar_file_location"
	# Handle nested jar case
	has_nested_jar=$(unzip -l "$jar_file_location" | grep "\.jar$" | grep -cv "Archive:")
	if [ $has_nested_jar -ne 0 ]
	then
		nestedjar_lib_name="$(basename "$jar_file_location")_$RANDOM"
		mkdir -p "$NESTED_JAR_WORK_FOLDER/$nestedjar_lib_name"
		unzip -q -d "$NESTED_JAR_WORK_FOLDER/$nestedjar_lib_name" "$jar_file_location"
		chmod -R +r "$NESTED_JAR_WORK_FOLDER/$nestedjar_lib_name"
		inspect_folder "$NESTED_JAR_WORK_FOLDER/$nestedjar_lib_name"
	fi	
}
echo -e "\e[93m[+] Searching for Log4J2 Thread Context Map or Log4J2 Expressions usage across '$APP_LIBS_FOLDER' folder...\e[0m"
for lib in $(find "$APP_LIBS_FOLDER" -type f -iname "*.jar" -o -iname "*.war" -o -iname "*.ear")
do
	filename=$(basename "$lib")
	filename="$filename"
	extension="${filename##*.}"
	printf "\r[*] Inspecting file: %-80s" $filename
	if [ $extension == "ear" ]
	then
		rm -rf $WORK_FOLDER 2>/dev/null
		mkdir $WORK_FOLDER
		unzip -q -d $WORK_FOLDER "$lib"
		chmod -R +r $WORK_FOLDER
		for war_lib in $(find $WORK_FOLDER -type f -iname "*.war")
		do
			war_lib_name="$(basename "$war_lib")_$RANDOM"
			war_lib_folder="$WORK_FOLDER/$war_lib_name"
			mkdir "$war_lib_folder"
			unzip -q -d "$war_lib_folder" "$war_lib"
			chmod -R +r "$war_lib_folder"
		done
		inspect_folder "$WORK_FOLDER"
		rm -rf "$WORK_FOLDER" 2>/dev/null
	fi
	if [ $extension == "war" ]
	then
		rm -rf $WORK_FOLDER 2>/dev/null
		war_lib_name="$(basename "$lib")_$RANDOM"
		war_lib_folder=$WORK_FOLDER/$war_lib_name
		mkdir -p "$war_lib_folder"
		unzip -q -d "$war_lib_folder" "$lib"
		chmod -R +r "$war_lib_folder"
		inspect_folder "$WORK_FOLDER"
		rm -rf $WORK_FOLDER 2>/dev/null
	fi	
	if [ $extension == "jar" ]
	then
		inspect_jar_file "$lib"
	fi
done
printf "\r%-100s" " "
if [ $JAR_FOUND -eq 0 ]
then
	echo -e "\r\e[92m[V] Inspection finished - No usage found!\e[0m\n"
else
	echo -ne "\r\e[91m[!] Inspection finished - Usage found!\e[0m\n"
fi
IFS="$OIFS"
rm -rf "$NESTED_JAR_WORK_FOLDER" 2>/dev/null
exit $JAR_FOUND
