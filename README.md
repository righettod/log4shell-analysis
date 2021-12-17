# Objective

Contains all my research and content produced regarding the [log4shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) vulnerability.

# Content

## Folder "analysis"

Contain the information that I gather about the vulnerability, affected versions, exploitation context/requirements, remediation plan proposal and so on...

This content is created using [Joplin](https://joplinapp.org/) and then exported as markdown to the **analysis** folder.

➡️ [Access to the content](analysis/06-STUDIES/04-Log4Shell_Vulnerability.md).

💡 Use the **TOC feature** of Github the navigate in the content (icon on top left):

![toc](toc-location.png)

## Folder "payloads"

Contain a collection of [log4shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) payloads seen on my twitter feeds.

The goal is to allows testing detection regexes defined in protection systems against payloads effectively used.

➡️ [Access to the content](payloads/README.md).

## Folder "playground"

Contains sample java files used to test my scripts.

## Folder "sandbox"

Contains a maven project used to perform testing with the log4j2 library as well as working on protection/detection technical material, like unit test cases.

It is a [IntelliJ IDEA](https://www.jetbrains.com/idea/download/#section=windows) project.

## Folder "scripts"

Contains utility script provided to help addressing this vulnerability.

### identify-log4j-class-location.sh

[identify-log4j-class-location.sh](scripts/identify-log4j-class-location.sh): Bash script to identify Log4J affected class for CVE-2021-44228 in a collection of EAR/WAR/JAR files

```bash
$ bash identify-log4j-class-location.sh ../playground/
[+] Searching class 'org/apache/logging/log4j/core/lookup/JndiLookup.class' across '../playground/' folder...
[*] Inspecting file: BBlog4j - core - 2.14.1.jar                                                             
[!] Class found in the file '../playground/BBlog4j - core - 2.14.1.jar'.
[+] Try to find the Maven artefact version...
File          : ../playground/BBlog4j - core - 2.14.1.jar
Metadata file : META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties
Log4J version : 2.14.1
[*] Inspecting file: dom4j-1.1.jar
...
[!] Inspection finished - Class found!
```

💡 For Windows target: You can use the **bash** provided by [Git portable for Windows](https://git-scm.com/download/win) to run the script.
