package com.cloudbees.jenkins.support.impl;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SlaveLaunchLogsRotatingLogTest {

    private static final Pattern LINE_PATTERN =
            Pattern.compile("^\\[\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z [^\\]]+\\] .*$");

    @Test
    void rotatesBySizeAndKeepsConfiguredNumberOfFiles(@TempDir File dir) throws Exception {
        int cap = 1024;
        int maxRotate = 2;
        SlaveLaunchLogs.RotatingLog archive = new SlaveLaunchLogs.RotatingLog(dir, cap, maxRotate);

        byte[] nameBytes = "test-agent".getBytes(StandardCharsets.UTF_8);
        byte[] line = ("X".repeat(100) + "\n").getBytes(StandardCharsets.UTF_8);

        // Write about 10 KB
        int iterations = (10 * 1024) / line.length;
        for (int i = 0; i < iterations; i++) {
            archive.writeLine(nameBytes, line, line.length);
        }
        archive.close();

        // Assert exactly all.log, all.log.1, all.log.2 exist
        File allLog = new File(dir, "all.log");
        File allLog1 = new File(dir, "all.log.1");
        File allLog2 = new File(dir, "all.log.2");
        File allLog3 = new File(dir, "all.log.3");

        assertTrue(allLog.exists(), "all.log should exist");
        assertTrue(allLog1.exists(), "all.log.1 should exist");
        assertTrue(allLog2.exists(), "all.log.2 should exist");
        assertFalse(allLog3.exists(), "all.log.3 should not exist");

        // Each file should be no bigger than cap + longest possible record
        long maxRecordSize = 1 + 29 + 1 + nameBytes.length + 2 + 1 + line.length;
        long maxAllowedSize = cap + maxRecordSize;

        assertThat("all.log size", allLog.length(), lessThanOrEqualTo(maxAllowedSize));
        assertThat("all.log.1 size", allLog1.length(), lessThanOrEqualTo(maxAllowedSize));
        assertThat("all.log.2 size", allLog2.length(), lessThanOrEqualTo(maxAllowedSize));

        // Every line in every file matches the line regex
        for (File f : new File[] {allLog, allLog1, allLog2}) {
            List<String> lines = Files.readAllLines(f.toPath());
            for (String l : lines) {
                assertThat("Line format in " + f.getName(), l, matchesPattern(LINE_PATTERN));
            }
        }
    }

    @Test
    void concurrentWritersAcrossRotations(@TempDir File dir) throws Exception {
        int threads = 4;
        int linesPerThread = 2000;
        int cap = 4096;
        int maxRotate = 1000;

        SlaveLaunchLogs.RotatingLog archive = new SlaveLaunchLogs.RotatingLog(dir, cap, maxRotate);
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threads);

        for (int t = 0; t < threads; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    byte[] nameBytes = ("agent-" + threadId).getBytes(StandardCharsets.UTF_8);
                    byte[] line = ("Line from thread " + threadId + "\n").getBytes(StandardCharsets.UTF_8);

                    for (int i = 0; i < linesPerThread; i++) {
                        archive.writeLine(nameBytes, line, line.length);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(60, TimeUnit.SECONDS), "Threads should complete within timeout");
        executor.shutdown();
        archive.close();

        // Assert more than one file exists
        int fileCount = 0;
        List<File> files = new ArrayList<>();
        File allLog = new File(dir, "all.log");
        if (allLog.exists()) {
            fileCount++;
            files.add(allLog);
        }
        for (int i = 1; i <= maxRotate; i++) {
            File rotated = new File(dir, "all.log." + i);
            if (rotated.exists()) {
                fileCount++;
                files.add(rotated);
            }
        }

        assertThat("Should have more than one file", fileCount, greaterThan(1));

        // Count total lines
        int totalLines = 0;
        for (File f : files) {
            List<String> lines = Files.readAllLines(f.toPath());
            totalLines += lines.size();

            // Every line matches the regex
            for (String line : lines) {
                assertThat("Line format in " + f.getName(), line, matchesPattern(LINE_PATTERN));
            }
        }

        assertEquals(threads * linesPerThread, totalLines, "Total line count should match");
    }

    @Test
    void closingOneStreamKeepsSharedLogOpenAndTerminatesPartialLine(@TempDir File dir) throws Exception {
        SlaveLaunchLogs.RotatingLog archive = new SlaveLaunchLogs.RotatingLog(dir, 10240, 9);
        SlaveLaunchLogs.PrefixedStream streamA = new SlaveLaunchLogs.PrefixedStream(archive, "agent-A");
        SlaveLaunchLogs.PrefixedStream streamB = new SlaveLaunchLogs.PrefixedStream(archive, "agent-B");

        // A writes partial line (no newline)
        streamA.write("partial".getBytes(StandardCharsets.UTF_8));
        streamA.close();

        // B writes full line
        streamB.write("full line\n".getBytes(StandardCharsets.UTF_8));
        streamB.close();

        archive.close();

        // Read the log file
        File allLog = new File(dir, "all.log");
        List<String> lines = Files.readAllLines(allLog.toPath());

        // Assert exactly 2 well-formed lines: A's then B's
        assertEquals(2, lines.size(), "Should have exactly 2 lines");
        assertThat("First line (from A)", lines.get(0), matchesPattern(LINE_PATTERN));
        assertThat("Second line (from B)", lines.get(1), matchesPattern(LINE_PATTERN));

        // Verify content
        assertThat("Line A content", lines.get(0), matchesPattern(".*agent-A.*partial.*"));
        assertThat("Line B content", lines.get(1), matchesPattern(".*agent-B.*full line.*"));
    }

    @Test
    void quarantinesOnlyOversizedFilesAndDeletesQuarantined(@TempDir File dir) throws Exception {
        int cap = 1000;

        // Create all.log.1 at 3000 bytes
        File allLog1 = new File(dir, "all.log.1");
        try (FileOutputStream fos = new FileOutputStream(allLog1)) {
            fos.write(new byte[3000]);
        }

        // Create all.log.2 at 500 bytes
        File allLog2 = new File(dir, "all.log.2");
        try (FileOutputStream fos = new FileOutputStream(allLog2)) {
            fos.write(new byte[500]);
        }

        // Create leftover all.log.5.oversized
        File leftoverOversized = new File(dir, "all.log.5.oversized");
        leftoverOversized.createNewFile();

        // Run quarantineOversized
        SlaveLaunchLogs.RotatingLog.quarantineOversized(dir, cap);

        // Assert all.log.1 is gone, all.log.1.oversized exists, all.log.2 is untouched
        assertFalse(allLog1.exists(), "all.log.1 should be gone");
        File allLog1Oversized = new File(dir, "all.log.1.oversized");
        assertTrue(allLog1Oversized.exists(), "all.log.1.oversized should exist");
        assertTrue(allLog2.exists(), "all.log.2 should be untouched");

        // Run deleteQuarantined
        SlaveLaunchLogs.RotatingLog.deleteQuarantined(dir);

        // Assert no *.oversized files left, all.log.2 still there
        assertFalse(allLog1Oversized.exists(), "all.log.1.oversized should be deleted");
        assertFalse(leftoverOversized.exists(), "all.log.5.oversized should be deleted");
        assertTrue(allLog2.exists(), "all.log.2 should still be there");
    }
}
