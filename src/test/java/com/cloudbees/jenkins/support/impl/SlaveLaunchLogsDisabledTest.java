package com.cloudbees.jenkins.support.impl;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.cloudbees.jenkins.support.SupportPlugin;
import hudson.slaves.SlaveComputer;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.RealJenkinsExtension;

/**
 * Tests for DISABLE_ARCHIVE mode.
 * Uses RealJenkinsExtension because static finals require separate JVM.
 */
class SlaveLaunchLogsDisabledTest {

    @RegisterExtension
    private final RealJenkinsExtension extension = new RealJenkinsExtension();

    @Test
    void disabledArchive() throws Throwable {
        extension.javaOptions(
                "-D" + SlaveLaunchLogs.class.getName() + ".DISABLE_ARCHIVE=true",
                "-D" + SlaveLaunchLogs.class.getName() + ".MAX_FILE_SIZE=1000");
        extension.then(SlaveLaunchLogsDisabledTest::_session1);
        extension.then(SlaveLaunchLogsDisabledTest::_session2);
    }

    private static void _session1(JenkinsRule r) throws Exception {
        // Create agent-launches directory and oversized file
        File logsDir = new File(SupportPlugin.getLogsDirectory(), "agent-launches");
        logsDir.mkdirs();
        File allLog1 = new File(logsDir, "all.log.1");
        try (FileOutputStream fos = new FileOutputStream(allLog1)) {
            fos.write(new byte[5000]);
        }

        // Create online agent and println unique marker
        var agent = r.createOnlineSlave();
        String uniqueMarker = "Disabled archive test message " + UUID.randomUUID();
        ((SlaveComputer) agent.toComputer()).getListener().getLogger().println(uniqueMarker);

        // Assert all.log is absent or empty
        File allLog = new File(logsDir, "all.log");
        assertTrue(!allLog.exists() || allLog.length() == 0, "all.log should be absent or empty");

        // Assert no file in agent-launches contains the marker
        File[] allFiles = logsDir.listFiles();
        if (allFiles != null) {
            for (File f : allFiles) {
                if (f.isFile() && f.getName().startsWith("all.log")) {
                    String content = Files.readString(f.toPath());
                    assertFalse(content.contains(uniqueMarker), "Marker should not be in " + f.getName());
                }
            }
        }

        // Assert the agent's slave.log contains the marker
        File slaveLog = agent.toComputer().getLogFile();
        assertTrue(slaveLog.exists(), "slave.log should exist");
        String slaveLogContent = Files.readString(slaveLog.toPath());
        assertTrue(slaveLogContent.contains(uniqueMarker), "slave.log should contain the marker");
    }

    private static void _session2(JenkinsRule r) throws Exception {
        // After restart, verify quarantine happened
        File logsDir = new File(SupportPlugin.getLogsDirectory(), "agent-launches");
        File allLog1 = new File(logsDir, "all.log.1");
        File allLog = new File(logsDir, "all.log");

        // Assert all.log.1 does not exist (quarantine rename is synchronous)
        assertFalse(allLog1.exists(), "all.log.1 should not exist after restart");

        // Assert all.log is absent or empty
        assertTrue(!allLog.exists() || allLog.length() == 0, "all.log should be absent or empty");
    }
}
