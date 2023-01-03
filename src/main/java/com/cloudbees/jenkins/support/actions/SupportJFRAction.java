package com.cloudbees.jenkins.support.actions;

import com.cloudbees.jenkins.support.BundleFileName;
import com.cloudbees.jenkins.support.SupportAction;
import com.cloudbees.jenkins.support.SupportPlugin;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import jdk.jfr.Configuration;
import jdk.jfr.EventType;
import jdk.jfr.FlightRecorder;
import jdk.jfr.Recording;
import jdk.jfr.RecordingState;
import jenkins.model.Jenkins;
import jenkins.util.SystemProperties;
import net.sf.json.JSONObject;
import org.apache.commons.io.FileUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Support Action to manage Java Flight Recorder features.
 */
@Restricted(NoExternalUse.class)
public class SupportJFRAction extends SupportChildAction {

    private static final Logger LOGGER = Logger.getLogger(SupportJFRAction.class.getName());

    private static final String RECORDING_PATH_PROPERTY = SupportJFRAction.class.getName() + ".recordingsDir";

    private static final String RECORDING_PATH = SupportPlugin.getRootDirectory().toPath() + "/"
        + SystemProperties.getString(RECORDING_PATH_PROPERTY, "jfr");

    static final String URL = "jfr";

    public SupportJFRAction(@NonNull SupportAction supportAction) {
        super(supportAction);
        File recordingDir = getRootDir();
        if (!recordingDir.exists() && !recordingDir.mkdirs()) {
            throw new Error("Failed to create " + recordingDir);
        }
    }

    @Override
    public String getIconFileName() {
        return "/plugin/support-core/images/support.svg";
    }

    @Override
    public String getDisplayName() {
        return Messages.SupportJFRAction_DisplayName();
    }

    @Override
    public String getUrlName() {
        return URL;
    }

    @RequirePOST
    @SuppressWarnings("unused") // Stapler
    public void doStopRecording(StaplerRequest req, StaplerResponse rsp) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        Recording currentrecording = getCurrentRecording();

        if (currentrecording == null) {
            rsp.sendError(HttpServletResponse.SC_BAD_REQUEST, "No recording to stop");
            return;
        }

        File currentDumpPath = currentrecording.getDestination().toFile();
        CrashDump.stop();

        LOGGER.fine("Trying to download recording " + currentDumpPath.getAbsolutePath());
        try {
            File zipFile = createZipFile(currentDumpPath);
            rsp.setContentType("application/zip");
            rsp.addHeader("Content-Disposition", "inline; filename=" + zipFile.getName() + ";");
            FileUtils.copyFile(zipFile, rsp.getOutputStream());
            LOGGER.info("File " + zipFile.getAbsolutePath() + " successfully downloaded");
        } catch (RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Unable to download file " + currentDumpPath.getAbsolutePath(), e);
        } finally {
            try {
                Files.deleteIfExists(currentDumpPath.toPath());
            } catch (IOException ioe) {
                LOGGER.log(Level.WARNING, "Could not delete file", ioe);
            }
        }
    }

    @RequirePOST
    @SuppressWarnings("unused") // Stapler
    public void doStartRecording(StaplerRequest req, StaplerResponse rsp) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        try {
            CrashDump.start();
        } catch (ParseException e) {
            throw new IOException(e);
        }
        rsp.sendRedirect(".");
    }

    @RequirePOST
    @SuppressWarnings("unused") // Stapler
    public void doDumpRecording(StaplerRequest req, StaplerResponse rsp) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);


        Recording currentrecording = getCurrentRecording();

        if (currentrecording == null) {
            rsp.sendError(HttpServletResponse.SC_BAD_REQUEST, "No recording to stop");
            return;
        }

        File crashDumpFile = CrashDump.dump();

        LOGGER.fine("Trying to download recording " + crashDumpFile.getAbsolutePath());
        try {
            File zipFile = createZipFile(crashDumpFile);
            rsp.setContentType("application/zip");
            rsp.addHeader("Content-Disposition", "inline; filename=" + zipFile.getName() + ";");
            FileUtils.copyFile(zipFile, rsp.getOutputStream());
            LOGGER.info("File " + zipFile.getAbsolutePath() + " successfully downloaded");
        } catch (RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Unable to download file " + crashDumpFile.getAbsolutePath(), e);
        } finally {
            try {
                Files.deleteIfExists(crashDumpFile.toPath());
            } catch (IOException ioe) {
                LOGGER.log(Level.WARNING, "Could not delete file", ioe);
            }
        }
    }

    @RequirePOST
    @SuppressWarnings("unused") // Stapler
    public void doDeleteDumps(StaplerRequest req, StaplerResponse rsp) throws ServletException, IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        JSONObject json = req.getSubmittedForm();
        if (!json.has("jfrDumps")) {
            rsp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        Set<File> dumpsToDelete = getSelectedDumps(req, json);
        for (File dumpToDelete : dumpsToDelete) {
            LOGGER.fine("Trying to delete dump file " + dumpToDelete.getAbsolutePath());
            try {
                if (dumpToDelete.delete()) {
                    LOGGER.info("Dump " + dumpToDelete.getAbsolutePath() + " successfully deleted.");
                } else {
                    LOGGER.log(Level.SEVERE, "Unable to delete file " + dumpToDelete.getAbsolutePath());
                }
            } catch (RuntimeException e) {
                LOGGER.log(Level.SEVERE, "Unable to delete file " + dumpToDelete.getAbsolutePath(), e);
            }
        }
        rsp.sendRedirect(".");
    }

    @RequirePOST
    @SuppressWarnings("unused") // Stapler
    public void doDownloadDumps(StaplerRequest req, StaplerResponse rsp) throws ServletException, IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        JSONObject json = req.getSubmittedForm();
        if (!json.has("jfrDumps")) {
            rsp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        Set<File> dumpsToDownload = getSelectedDumps(req, json);
        File fileToDownload;
        if (dumpsToDownload.size() > 1) {
            // more than one dump were selected, create a zip file
            fileToDownload = createZipFile(dumpsToDownload);
        } else {
            fileToDownload = createZipFile(dumpsToDownload.iterator().next());
        }
        LOGGER.fine("Trying to download file " + fileToDownload.getAbsolutePath());
        try {
            rsp.setContentType("application/zip");
            rsp.addHeader("Content-Disposition", "inline; filename=" + fileToDownload.getName() + ";");
            FileUtils.copyFile(fileToDownload, rsp.getOutputStream());
            LOGGER.info("Dump " + fileToDownload.getAbsolutePath() + " successfully downloaded");
        } catch (RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Unable to download file " + fileToDownload.getAbsolutePath(), e);
        } finally {
            if (dumpsToDownload.size() > 1) {
                if (fileToDownload.delete()) {
                    LOGGER.log(Level.FINE, "Temporary multiDump file deleted: " + fileToDownload.getAbsolutePath());
                } else {
                    LOGGER.log(Level.SEVERE, "Unable to delete temporary multiDump file: " + fileToDownload.getAbsolutePath());
                }
            }
        }
    }

    @SuppressWarnings("unused") // Stapler
    public boolean isRecording() {
        return CrashDump.isRunning();
    }

    @CheckForNull
    @SuppressWarnings("unused") // Stapler
    public Recording getCurrentRecording() {
        return CrashDump.getRecording();
    }

    @SuppressWarnings("unused") // Stapler
    public List<File> getDumps() {
        List<File> res = new ArrayList<>();
        File[] recordings = getRootDir().listFiles((dir, name) -> name.endsWith(".jfr"));
        if (recordings != null) {
            res = Arrays.asList(recordings);
            Collections.sort(res);
        }
        return res;
    }

    @NonNull
    public static File getRootDir() {
        return new File(RECORDING_PATH);
    }

    private File createZipFile(File recording) throws IOException {
        File zipFile = File.createTempFile(recording.getName(), ".zip");
        zipFile.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(zipFile);
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            byte[] buffer = new byte[1024];
            try (FileInputStream fis = new FileInputStream(recording)) {
                zos.putNextEntry(new ZipEntry(recording.getName()));
                int length;
                while ((length = fis.read(buffer)) > 0) {
                    zos.write(buffer, 0, length);
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error creating zip file: " + zipFile.getAbsolutePath(), e);
        }
        return zipFile;
    }

    private File createZipFile(Set<File> files) throws IOException {
        File zipFile = File.createTempFile(String.format("multiDump(%s)-", files.size()), ".zip");
        zipFile.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(zipFile);
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            byte[] buffer = new byte[1024];
            for (File file : files) {
                try (FileInputStream fis = new FileInputStream(file)) {
                    zos.putNextEntry(new ZipEntry(file.getName()));
                    int length;
                    while ((length = fis.read(buffer)) > 0) {
                        zos.write(buffer, 0, length);
                    }
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error creating zip file: " + zipFile.getAbsolutePath(), e);
        }
        return zipFile;
    }

    private Set<File> getSelectedDumps(StaplerRequest req, JSONObject json) {
        Set<File> recordings = new HashSet<>();
        List<File> existingDumps = getDumps();
        for (SupportAction.Selection s : req.bindJSONToList(SupportAction.Selection.class, json.get("recordings"))) {
            if (s.isSelected()) {
                if (existingDumps.stream().anyMatch(file -> file.getName().equals(s.getName()))) {
                    recordings.add(Paths.get(getRootDir().getAbsolutePath(), s.getName()).toFile());
                } else {
                    LOGGER.log(Level.FINE, "The recording selected {0} does not exist, so it will not be processed",
                        s.getName());
                }
            }
        }
        return recordings;
    }

    public static class CrashDump {

        private static Recording rec;

        public static synchronized void start() throws IOException, ParseException {

            if (rec != null) {
                stop();
            }

            rec = prepareRecording();
            rec.start();

        }

        private static Recording prepareRecording() throws IOException, ParseException {
            Configuration conf = Configuration.getConfiguration("default");
            String generatedName = BundleFileName.generate("", "jfr");
            Recording recording = new Recording(conf);
            for (EventType et : FlightRecorder.getFlightRecorder().getEventTypes()) {
                recording.enable(et.getName());
            }
            recording.setName(generatedName);
            recording.setDumpOnExit(true);
            recording.setToDisk(false);
            recording.setDestination(new File(RECORDING_PATH, generatedName).toPath());
            return recording;
        }

        public static File dump() throws IOException {
            File result = new File(RECORDING_PATH, BundleFileName.generate("", "jfr"));
            rec.dump(result.toPath());
            return result;
        }

        @CheckForNull
        public static Recording getRecording() {
            return rec;
        }

        public static boolean isRunning() {
            return rec != null
                && (RecordingState.RUNNING == rec.getState() || RecordingState.DELAYED == rec.getState());
        }

        public static synchronized void stop() throws IOException {
            if (rec != null) {
                rec.stop();
                rec.close();
            }
            rec = null;
        }
    }
}
