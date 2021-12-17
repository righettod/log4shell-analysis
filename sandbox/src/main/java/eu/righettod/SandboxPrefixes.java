package eu.righettod;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.lookup.MainMapLookup;

public class SandboxPrefixes {
    public static void main(String[] args) throws Exception {
        Logger log = LogManager.getLogger(SandboxPrefixes.class);
        //SYS (JVM properties) prefix resolved by the class "org.apache.logging.log4j.core.lookup.SystemPropertiesLookup"
        log.info("${sys:java.version}");
        //ENV prefix resolved by the class "org.apache.logging.log4j.core.lookup.EnvironmentLookup"
        log.info("${env:USERNAME}");
        //JAVA prefix resolved by the class "org.apache.logging.log4j.core.lookup.JavaLookup"
        log.info("${java:os}");
        //LOG4J prefix resolved by the class "org.apache.logging.log4j.core.lookup.Log4jLookup"
        log.info("${log4j:configLocation}");
        log.info("${log4j:configParentLocation}");
        //WEB/DOCKER prefixes resolved by the class "org.apache.logging.log4j.core.lookup.Interpolator"
        //DOCKER prefix resolved by the class "org.apache.logging.log4j.docker.DockerLookup" behind the scene
        //See https://search.maven.org/artifact/org.apache.logging.log4j/log4j-docker
        log.info("${docker:containerId}");//Is effective when the app run inside a container
        //WEB prefix resolved by the class "org.apache.logging.log4j.web.WebLookup" behind the scene
        //See https://search.maven.org/artifact/org.apache.logging.log4j/log4j-web
        log.info("${web:rootDir}");//Is effective when the app is a web app
        //MAIN prefix resolved by the class "org.apache.logging.log4j.core.lookup.MainMapLookup"
        //From class documentation:
        //An application's public static main(String[]) method calls method "MainMapLookup.setMainArguments(...)" to make
        //its main arguments available for lookup with the prefix "main".
        MainMapLookup.setMainArguments(args);
        log.info("${main:0} ${main:1}");
        //BUNDLE prefix resolved by the class "org.apache.logging.log4j.core.lookup.ResourceBundleLookup"
        //Here I have a "config.properties" file in the classpath
        log.info("${bundle:config:db.password}");
        //SPRING prefix resolved by the class "org.apache.logging.log4j.spring.cloud.config.client.SpringLookup"
        //See https://search.maven.org/artifact/org.apache.logging.log4j/log4j-spring-cloud-config-client


    }
}
