package internals;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Test suite to ensure that the regex proposed to detect log4shell payload is not prone to a bypass.
 * The list of bypasses gathered is used as a source of payloads.
 *
 * @see "https://github.com/righettod/log4shell-analysis/blob/main/payloads/README.md"
 * @see "https://issues.apache.org/jira/browse/LOG4J2-3230"
 * @See "https://issues.apache.org/jira/browse/LOG4J2-3230?focusedCommentId=17461971&page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment-tabpanel#comment-17461971"
 */
public class DetectionRegexBypassTest {
    private static List<String> PAYLOADS;
    private static final Pattern DETECTION_REGEX = Pattern.compile("\\$\\{.*?:.*\\}");
    private static final Path PAYLOAD_MD_FILE_PATH = new File("../payloads/README.md").toPath();

    @BeforeClass
    public static void globalInit() throws Exception {
        //Load payloads form the MD file
        PAYLOADS = Files.readAllLines(PAYLOAD_MD_FILE_PATH).stream().filter(p -> p.contains("$")).collect(Collectors.toList());
        System.out.printf("%s expressions loaded and used to test the regex: %s\n", PAYLOADS.size(), DETECTION_REGEX.pattern());
    }

    @Test
    public void testExposureToBypasses() {
        PAYLOADS.forEach(p -> {
            Matcher matcher = DETECTION_REGEX.matcher(p);
            boolean matchFound = matcher.find();
            Assert.assertTrue("Regex cannot spot the pattern: '" + p + "'", matchFound);
        });
    }

    @Test(timeout = 60000L)
    public void testExposureToReDOS() {
        //Generate the huge payload: "${" + "${::-"*500000 + "$${::-j}" + "}"*500000 + "}"
        //Source is the ticket "LOG4J2-3230" - The comment added in tag SEE
        StringBuilder payload = new StringBuilder("${");
        int occurrences = 500000;
        payload.append("${::-".repeat(occurrences));
        payload.append("$${::-j}");
        payload.append("}".repeat(occurrences));
        payload.append("}");
        //Apply test
        Matcher matcher = DETECTION_REGEX.matcher(payload);
        boolean matchFound = matcher.find();
        System.out.println("Regex not prone to ReDOS.");
        Assert.assertTrue("Regex cannot spot the pattern: '" + payload + "'", matchFound);
    }

}
