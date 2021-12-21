package eu.righettod;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.builder.api.AppenderComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.api.RootLoggerComponentBuilder;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test suite to ensure that the current version used of log4j-core is not exposed to log4shell DOS vulnerability for CVE-2021-45105.
 *
 * @see "https://www.studytonight.com/post/log4j2-programmatic-configuration-in-java-class"
 * @see "https://docs.oracle.com/javase/7/docs/technotes/guides/net/properties.html"
 * @see "https://issues.apache.org/jira/browse/LOG4J2-3230"
 * @see "https://issues.apache.org/jira/browse/LOG4J2-3230?focusedCommentId=17461971&page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment-tabpanel#comment-17461971"
 */
public class Log4ShellDOSExposureTest {

    private static String TEST_PAYLOAD;
    private Logger victim;

    @BeforeClass
    public static void generateDosPayload() {
        //Generate the huge payload: "${" + "${::-"*500000 + "$${::-j}" + "}"*500000 + "}"
        //Source is the ticket "LOG4J2-3230" - The comment added in tag SEE
        StringBuilder payload = new StringBuilder("${");
        int occurrences = 500000;
        payload.append("${::-".repeat(occurrences));
        payload.append("$${::-j}");
        payload.append("}".repeat(occurrences));
        payload.append("}");
        TEST_PAYLOAD = payload.toString();
    }

    @Before
    public void testSuiteSetup() throws Exception {
        //Setup the logger
        ConfigurationBuilder<BuiltConfiguration> builder = ConfigurationBuilderFactory.newConfigurationBuilder();
        builder.setStatusLevel(Level.INFO);
        builder.setConfigurationName("DefaultLogger");
        AppenderComponentBuilder appenderBuilder = builder.newAppender("Console", "CONSOLE").addAttribute("target", ConsoleAppender.Target.SYSTEM_OUT);
        appenderBuilder.add(builder.newLayout("PatternLayout").addAttribute("pattern", "${ctx:test} - %msg%n"));
        RootLoggerComponentBuilder rootLogger = builder.newRootLogger(Level.INFO);
        rootLogger.add(builder.newAppenderRef("Console"));
        builder.add(appenderBuilder);
        builder.add(rootLogger);
        //Configurator.reconfigure(builder.build());
        //Use this method is reconfigure(() do not exists in the log4j2 tested version
        Configurator.initialize(builder.build());
        //Setup the logger used
        victim = LogManager.getRootLogger();
        //Display execution context
        System.out.printf("LOG4J2 version: %s\n", victim.getClass().getPackage().getImplementationVersion());
        System.out.printf("Java version  : %s\n", System.getProperty("java.version"));
    }

    @Test(timeout = 60000L)
    public void testExposure() throws Exception {
        //Log the payload and trigger the vulnerability using different ways
        ThreadContext.put("test", TEST_PAYLOAD);
        System.out.println("triggering mode 1 via a Thread Context Map entry...");
        victim.info("triggering mode 1...");
        ThreadContext.remove("test");
        System.out.println("triggering mode 2 via a direct logging of the expression...");
        victim.info(TEST_PAYLOAD);
        System.out.println("triggering mode 3 via the printf() method logging the expression...");
        victim.printf(Level.INFO, "%s", TEST_PAYLOAD);
        //If the vulnerability is present then the execution will crash and
        //a "java.lang.OutOfMemoryError: Java heap space" error will be raised by the JVM running the test.
        //If the vulnerability is NOT present then the payload will be logged as large simple strings and the test will end normally.
    }
}
