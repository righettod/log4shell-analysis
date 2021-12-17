#!/bin/bash
#########################################################################################################
# Script to identify Log4J affected class for CVE-2021-44228 in a collection of EAR/WAR/JAR files
# Based on this script:
# https://github.com/righettod/toolbox-pentest-web/blob/master/scripts/identify-class-location.sh
#########################################################################################################
if [ "$#" -lt 1 ]; then
    script_name=$(basename "$0")
    echo "Usage:"
    echo "   $script_name [BASE_SEARCH_FOLDER]"
    echo ""
    echo "Call example:"
    echo "    $script_name /apps"
    exit 1
fi
# Constants
JAR_FOUND=0
TARGET_CLASS_NAME="org/apache/logging/log4j/core/lookup/JndiLookup.class"
APP_LIBS_FOLDER=$1
WORK_FOLDER=/tmp/work
JAR_WORK_FOLDER=/tmp/jarwork
NESTED_JAR_WORK_FOLDER=/tmp/nestedjarwork
CDIR=$(pwd)
# See https://unix.stackexchange.com/a/9499
OIFS="$IFS"
IFS=$'\n'
# Utility functions
inspect_folder (){
	folder_location=$1
	for jar_lib in $(find "$folder_location" -type f -iname "*.jar")
	do
		inspect_jar_file "$jar_lib"
	done
}
inspect_jar_file(){
	jar_file_location=$1
	find=$(unzip -l "$jar_file_location" | grep -c "$TARGET_CLASS_NAME")
	if [ $find -ne 0 ]
	then
		JAR_FOUND=1
		echo ""
		echo -e "\e[91m[!] Class found in the file '$jar_file_location'.\e[0m"
		echo -e "\e[93m[+] Try to find the Maven artefact version...\e[0m"
		rm -rf "$JAR_WORK_FOLDER" 2>/dev/null
		mkdir "$JAR_WORK_FOLDER"
		unzip -q -d "$JAR_WORK_FOLDER" "$jar_file_location"
		chmod -R +r "$JAR_WORK_FOLDER"
		cd $JAR_WORK_FOLDER
		for f in $(grep -r "groupId\s*=\s*org.apache.logging.log4j" *)
		do
			file_loc=$(echo $f | cut -d":" -f1)
			artefact_version=$(grep -Po "version\s*=\s*.*" "$file_loc" | sed 's/version=//g')
			echo "File          : $jar_file_location"
			echo "Metadata file : $file_loc"
			echo "Log4J version : $artefact_version"
		done
		cd $CDIR
		rm -rf $JAR_WORK_FOLDER 2>/dev/null
	fi
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
echo -e "\e[93m[+] Searching class '$TARGET_CLASS_NAME' across '$APP_LIBS_FOLDER' folder...\e[0m"
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
	echo -e "\r\e[92m[V] Inspection finished - Class not found!\e[0m\n"
else
	echo -ne "\r\e[91m[!] Inspection finished - Class found!\e[0m\n"
fi
IFS="$OIFS"
rm -rf "$NESTED_JAR_WORK_FOLDER" 2>/dev/null
exit $JAR_FOUND
