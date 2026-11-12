/*
 * The MIT License
 *
 * Copyright (c) 2016, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.cloudbees.jenkins.support.impl;

import static com.cloudbees.jenkins.support.impl.JenkinsLogs.ROTATED_LOGFILE_FILTER;

import com.cloudbees.jenkins.support.SupportPlugin;
import com.cloudbees.jenkins.support.api.Container;
import com.cloudbees.jenkins.support.api.LaunchLogsFileContent;
import com.cloudbees.jenkins.support.api.ObjectComponent;
import com.cloudbees.jenkins.support.api.ObjectComponentDescriptor;
import com.cloudbees.jenkins.support.timer.FileListCapComponent;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.console.ConsoleLogFilter;
import hudson.console.LineTransformationOutputStream;
import hudson.init.Terminator;
import hudson.model.AbstractModelObject;
import hudson.model.Computer;
import hudson.model.PeriodicWork;
import hudson.model.Run;
import hudson.security.Permission;
import hudson.slaves.SlaveComputer;
import hudson.util.io.RewindableRotatingFileOutputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.Flushable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.apache.commons.io.output.TeeOutputStream;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Adds agent launch logs, which captures the current and past running connections to the agent.
 */
@Extension
public class SlaveLaunchLogs extends ObjectComponent<Computer> {

    private static final Logger LOGGER = Logger.getLogger(SlaveLaunchLogs.class.getName());
    private static final int MAX_ROTATE_LOGS =
            Integer.getInteger(SlaveLaunchLogs.class.getName() + ".MAX_ROTATE_LOGS", 9);
    private static final long MAX_FILE_SIZE =
            Long.getLong(SlaveLaunchLogs.class.getName() + ".MAX_FILE_SIZE", FileListCapComponent.MAX_FILE_SIZE);
    private static final boolean DISABLE_ARCHIVE =
            Boolean.getBoolean(SlaveLaunchLogs.class.getName() + ".DISABLE_ARCHIVE");

    @DataBoundConstructor
    public SlaveLaunchLogs() {
        super();
    }

    @NonNull
    @Override
    public Set<Permission> getRequiredPermissions() {
        return Collections.singleton(Jenkins.ADMINISTER);
    }

    @NonNull
    @Override
    public String getDisplayName() {
        return "Agent Launch Logs";
    }

    @Override
    public void addContents(@NonNull Container container) {
        LogArchiver archiver = LogArchiver.get();
        if (archiver != null) {
            archiver.addContents(container);
        }
    }

    @NonNull
    @Override
    public ComponentCategory getCategory() {
        return ComponentCategory.LOGS;
    }

    @Override
    public void addContents(@NonNull Container container, Computer item) {
        if (item.getNode() != null
                && item.getLogFile().lastModified() >= System.currentTimeMillis() - TimeUnit.DAYS.toMillis(7)) {
            File dir = new File(Jenkins.get().getRootDir(), "logs/slaves/" + item.getName());
            File[] files = dir.listFiles(ROTATED_LOGFILE_FILTER);
            if (files != null) {
                for (File f : files) {
                    container.add(new LaunchLogsFileContent(
                            "nodes/slave/{0}/launchLogs/{1}",
                            new String[] {dir.getName(), f.getName()}, f, FileListCapComponent.MAX_FILE_SIZE));
                }
            }
        }
    }

    @Extension
    public static final class LogArchiver extends ConsoleLogFilter {

        private final File logDir;
        private final RotatingLog rotatingLog;

        public LogArchiver() {
            logDir = new File(SupportPlugin.getLogsDirectory(), "agent-launches");

            // Apply validation to static configuration
            int maxRotate = MAX_ROTATE_LOGS < 0 ? 0 : MAX_ROTATE_LOGS;
            long maxFileSize = MAX_FILE_SIZE <= 0 ? FileListCapComponent.MAX_FILE_SIZE : MAX_FILE_SIZE;

            // Phase 1: quarantine oversized files (always runs, even when disabled)
            RotatingLog.quarantineOversized(logDir, maxFileSize);

            // Phase 2: delete quarantined files asynchronously
            jenkins.util.Timer.get().submit(() -> {
                RotatingLog.deleteQuarantined(logDir);
            });

            // Create rotating log if enabled
            if (!DISABLE_ARCHIVE) {
                RotatingLog tempLog = null;
                try {
                    tempLog = new RotatingLog(logDir, maxFileSize, maxRotate);
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Failed to create agent launch log rotating log", e);
                }
                rotatingLog = tempLog;
            } else {
                rotatingLog = null;
            }
        }

        /**
         * Returns the LogArchiver instance, or null if it's absent (e.g., filtered out by extension-filter plugin).
         */
        static LogArchiver get() {
            ExtensionList<LogArchiver> list = ExtensionList.lookup(LogArchiver.class);
            return list.isEmpty() ? null : list.get(0);
        }

        @Override
        public OutputStream decorateLogger(Computer computer, OutputStream logger) {
            if (rotatingLog != null && computer instanceof SlaveComputer) {
                return new TeeOutputStream(logger, new PrefixedStream(rotatingLog, computer.getName()));
            } else {
                return logger;
            }
        }

        @SuppressWarnings("rawtypes")
        @Override
        public OutputStream decorateLogger(Run build, OutputStream logger) throws IOException, InterruptedException {
            return logger;
        }

        public void addContents(@NonNull Container container) {
            // Flush before reading to ensure latest data is in files
            if (rotatingLog != null) {
                rotatingLog.flush();
            }

            File[] files = logDir.listFiles(ROTATED_LOGFILE_FILTER);
            if (files != null) {
                for (File f : files) {
                    container.add(new LaunchLogsFileContent(
                            "nodes/slave/launches/" + f.getName(),
                            new String[0],
                            f,
                            FileListCapComponent.MAX_FILE_SIZE));
                }
            }
        }

        @Terminator
        public static void close() {
            LogArchiver archiver = get();
            if (archiver != null && archiver.rotatingLog != null) {
                try {
                    archiver.rotatingLog.close();
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Failed to close agent launch log rotating log", e);
                }
            }
        }
    }

    static class PrefixedStream extends LineTransformationOutputStream {
        private final RotatingLog rotatingLog;
        private final byte[] nameBytes;

        PrefixedStream(RotatingLog rotatingLog, String name) {
            this.rotatingLog = rotatingLog;
            this.nameBytes = name.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        protected void eol(byte[] b, int len) throws IOException {
            rotatingLog.writeLine(nameBytes, b, len);
        }

        @Override
        public void flush() throws IOException {
            // No-op: rotating log flushes itself periodically
        }

        @Override
        public void close() throws IOException {
            super.close(); // Calls forceEol() only; NEVER closes the rotating log
        }
    }

    @Override
    public boolean isSelectedByDefault() {
        return false;
    }

    @Override
    public boolean isSelectedByDefault(Computer item) {
        return true;
    }

    @Override
    public <C extends AbstractModelObject> boolean isApplicable(Class<C> clazz) {
        return Jenkins.class.isAssignableFrom(clazz) || Computer.class.isAssignableFrom(clazz);
    }

    @Override
    public boolean isApplicable(Computer item) {
        return item != Jenkins.get().toComputer();
    }

    @Override
    public SlaveLaunchLogs.DescriptorImpl getDescriptor() {
        return Jenkins.get().getDescriptorByType(SlaveLaunchLogs.DescriptorImpl.class);
    }

    @Extension
    @Symbol("agentsLaunchLogsComponent")
    public static class DescriptorImpl extends ObjectComponentDescriptor<Computer> {

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public String getDisplayName() {
            return "Agent Launch Logs";
        }
    }

    /**
     * Periodically flushes the agent launch log rotating log to disk.
     */
    @Extension
    public static final class Flusher extends PeriodicWork {

        @Override
        public long getRecurrencePeriod() {
            return 3000; // 3 seconds, same as CustomLogs.LogFlusher
        }

        @Override
        protected void doRun() {
            LogArchiver archiver = LogArchiver.get();
            if (archiver != null && archiver.rotatingLog != null) {
                archiver.rotatingLog.flush();
            }
        }
    }

    /**
     * Manages the agent launch log rotating log with size-based rotation.
     * All state is guarded by {@code this}.
     */
    static final class RotatingLog implements Closeable, Flushable {

        static final String FILE_NAME = "all.log";
        private static final Logger LOGGER = Logger.getLogger(RotatingLog.class.getName());
        private static final int BUFFER_SIZE = 64 * 1024;

        // DateTimeFormatter that always includes milliseconds (3 digits)
        private static final DateTimeFormatter TIMESTAMP_FORMATTER =
                new DateTimeFormatterBuilder().appendInstant(3).toFormatter();

        private final File dir;
        private final long maxFileSize;
        private final RewindableRotatingFileOutputStream rotating;
        private final BufferedOutputStream out;
        private long written;
        private boolean dirty;
        private boolean failureLogged;
        private boolean closed;

        /**
         * Creates a new rotating log and performs startup rotation.
         *
         * @param dir directory for log files
         * @param maxFileSize maximum bytes per file before rotating
         * @param maxRotate number of rotated files to keep
         * @throws IOException if the rotating log cannot be created
         */
        RotatingLog(File dir, long maxFileSize, int maxRotate) throws IOException {
            this.dir = dir;
            this.maxFileSize = maxFileSize;
            this.rotating = new RewindableRotatingFileOutputStream(new File(dir, FILE_NAME), maxRotate);
            this.rotating.rewind();
            this.out = new BufferedOutputStream(rotating, BUFFER_SIZE);
            this.written = 0;
            this.dirty = false;
            this.failureLogged = false;
            this.closed = false;
        }

        /**
         * Appends one prefixed record. Never throws (failure isolation).
         *
         * @param prefixNameBytes computer name as UTF-8 bytes
         * @param line line data
         * @param len length of valid data in line
         */
        synchronized void writeLine(byte[] prefixNameBytes, byte[] line, int len) {
            if (closed) {
                LOGGER.log(Level.FINE, "writeLine called after close, ignoring");
                return;
            }

            try {
                // Build record: [ISO_INSTANT computerName] line\n
                byte[] timestamp = TIMESTAMP_FORMATTER
                        .format(Instant.now().truncatedTo(ChronoUnit.MILLIS))
                        .getBytes(StandardCharsets.US_ASCII);

                // Calculate record size
                int recordSize = 1 + timestamp.length + 1 + prefixNameBytes.length + 2 + len;
                boolean needsNewline = (len == 0 || line[len - 1] != '\n');
                if (needsNewline) {
                    recordSize++;
                }

                // Rotate if needed (only between records)
                if (written > 0 && written + recordSize > maxFileSize) {
                    out.flush();
                    rotating.rewind();
                    written = 0;
                }

                // Write the record
                out.write('[');
                out.write(timestamp);
                out.write(' ');
                out.write(prefixNameBytes);
                out.write(']');
                out.write(' ');
                out.write(line, 0, len);
                if (needsNewline) {
                    out.write('\n');
                }

                written += recordSize;
                dirty = true;

                // Reset failure state on success
                if (failureLogged) {
                    LOGGER.log(Level.INFO, "Agent launch log rotating log write succeeded after previous failures");
                    failureLogged = false;
                }
            } catch (IOException | RuntimeException e) {
                Level level = failureLogged ? Level.FINE : Level.WARNING;
                LOGGER.log(
                        level,
                        "Failed to write to agent launch log rotating log, agent launch will continue normally",
                        e);
                failureLogged = true;
            }
        }

        @Override
        public synchronized void flush() {
            if (!dirty || closed) {
                return;
            }
            try {
                out.flush();
                dirty = false;
            } catch (IOException | RuntimeException e) {
                Level level = failureLogged ? Level.FINE : Level.WARNING;
                LOGGER.log(level, "Failed to flush agent launch log rotating log", e);
                failureLogged = true;
            }
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            try {
                flush();
                out.close();
            } catch (IOException | RuntimeException e) {
                LOGGER.log(Level.WARNING, "Failed to close agent launch log rotating log", e);
            } finally {
                closed = true;
            }
        }

        File getDirectory() {
            return dir;
        }

        /**
         * Quarantines oversized files by renaming them (phase 1 of cleanup).
         * A file is oversized if it exceeds 2 × maxFileSize.
         * Runs synchronously before the rotating log is created.
         *
         * @param dir directory containing log files
         * @param maxFileSize size threshold
         */
        static void quarantineOversized(File dir, long maxFileSize) {
            if (!dir.exists() || !dir.isDirectory()) {
                return;
            }

            File[] files = dir.listFiles(ROTATED_LOGFILE_FILTER);
            if (files == null) {
                return;
            }

            long threshold = 2 * maxFileSize;
            for (File file : files) {
                try {
                    long fileSize = file.length();
                    if (fileSize > threshold) {
                        File target = new File(dir, file.getName() + ".oversized");
                        Files.move(file.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
                        LOGGER.log(Level.INFO, "Quarantined oversized file: {0} ({1} bytes)", new Object[] {
                            file.getName(), fileSize
                        });
                    }
                } catch (IOException | SecurityException e) {
                    LOGGER.log(Level.WARNING, "Failed to quarantine oversized file: " + file.getName(), e);
                }
            }
        }

        /**
         * Deletes quarantined files (phase 2 of cleanup).
         * Should be run asynchronously on jenkins.util.Timer.
         *
         * @param dir directory containing log files
         */
        static void deleteQuarantined(File dir) {
            if (!dir.exists() || !dir.isDirectory()) {
                return;
            }

            File[] files = dir.listFiles((d, name) -> name.endsWith(".oversized"));
            if (files == null) {
                return;
            }

            for (File file : files) {
                try {
                    long size = file.length();
                    if (file.delete()) {
                        LOGGER.log(Level.INFO, "Deleted quarantined file: {0} ({1} bytes)", new Object[] {
                            file.getName(), size
                        });
                    } else {
                        LOGGER.log(Level.WARNING, "Failed to delete quarantined file: {0}", file.getName());
                    }
                } catch (SecurityException e) {
                    LOGGER.log(Level.WARNING, "Failed to delete file: " + file.getName(), e);
                }
            }
        }
    }
}
