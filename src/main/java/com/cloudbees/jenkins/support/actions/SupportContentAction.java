package com.cloudbees.jenkins.support.actions;

import com.cloudbees.jenkins.support.SupportAction;
import com.cloudbees.jenkins.support.SupportPlugin;
import edu.umd.cs.findbugs.annotations.NonNull;
import jenkins.model.Jenkins;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Support Action to Manage content generated by Support extensions.
 */
@Restricted(NoExternalUse.class)
public class SupportContentAction extends SupportChildAction {

    private static final Logger LOGGER = Logger.getLogger(SupportContentAction.class.getName());

    static final String URL = "content";

    public SupportContentAction(@NonNull SupportAction supportAction) {
        super(supportAction);
    }

    @Override
    public String getIconFileName() {
        return "/plugin/support-core/images/support.svg";
    }

    @Override
    public String getDisplayName() {
        return Messages.SupportContentAction_DisplayName();
    }

    @Override
    public String getUrlName() {
        return URL;
    }

    @RequirePOST
    @SuppressWarnings("unused") // Stapler
    public void doDeleteBundles(StaplerRequest req, StaplerResponse rsp) throws ServletException, IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        JSONObject json = req.getSubmittedForm();
        if (!json.has("bundles")) {
            rsp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        Set<String> bundlesToDelete = getSelectedBundles(req, json);
        File rootDirectory = SupportPlugin.getRootDirectory();
        for (String bundleToDelete : bundlesToDelete) {
            File fileToDelete = new File(rootDirectory, bundleToDelete);
            LOGGER.fine("Trying to delete bundle file " + fileToDelete.getAbsolutePath());
            try {
                if (fileToDelete.delete()) {
                    LOGGER.info("Bundle " + fileToDelete.getAbsolutePath() + " successfully deleted.");
                } else {
                    LOGGER.log(Level.SEVERE, "Unable to delete file " + fileToDelete.getAbsolutePath());
                }
            } catch (RuntimeException e) {
                LOGGER.log(Level.SEVERE, "Unable to delete file " + fileToDelete.getAbsolutePath(), e);
            }
        }
        rsp.sendRedirect(".");
    }

    @RequirePOST
    @SuppressWarnings("unused") // Stapler
    public void doDownloadBundles(StaplerRequest req, StaplerResponse rsp) throws ServletException, IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        JSONObject json = req.getSubmittedForm();
        if (!json.has("bundles")) {
            rsp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        Set<String> bundlesToDownload = getSelectedBundles(req, json);
        File fileToDownload;
        if (bundlesToDownload.size() > 1) {
            // more than one bundles were selected, create a zip file
            fileToDownload = createZipFile(bundlesToDownload);
        } else {
            fileToDownload = new File(SupportPlugin.getRootDirectory(), bundlesToDownload.iterator().next());
        }
        LOGGER.fine("Trying to download file " + fileToDownload.getAbsolutePath());
        try {
            rsp.setContentType("application/zip");
            rsp.addHeader("Content-Disposition", "inline; filename=" + fileToDownload.getName() + ";");
            FileUtils.copyFile(fileToDownload, rsp.getOutputStream());
            LOGGER.info("Bundle " + fileToDownload.getAbsolutePath() + " successfully downloaded");
        } catch (RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Unable to download file " + fileToDownload.getAbsolutePath(), e);
        } finally {
            if (bundlesToDownload.size() > 1) {
                if (fileToDownload.delete()) {
                    LOGGER.log(Level.FINE, "Temporary multiBundle file deleted: " + fileToDownload.getAbsolutePath());
                } else {
                    LOGGER.log(Level.SEVERE, "Unable to delete temporary multiBundle file: " + fileToDownload.getAbsolutePath());
                }
            }
        }
    }

    public List<String> getBundles() {
        List<String> res = new ArrayList<>();
        File rootDirectory = SupportPlugin.getRootDirectory();
        File[] bundlesFiles = rootDirectory.listFiles((dir, name) -> name.endsWith(".zip"));
        if (bundlesFiles != null) {
            for (File bundleFile : bundlesFiles) {
                res.add(bundleFile.getName());
            }
        }
        Collections.sort(res);
        return res;
    }

    private Set<String> getSelectedBundles(StaplerRequest req, JSONObject json) {
        Set<String> bundles = new HashSet<>();
        List<String> existingBundles = getBundles();
        for (SupportAction.Selection s : req.bindJSONToList(SupportAction.Selection.class, json.get("bundles"))) {
            if (s.isSelected()) {
                if (existingBundles.contains(s.getName())) {
                    bundles.add(s.getName());
                } else {
                    LOGGER.log(Level.FINE, "The bundle selected {0} does not exist, so it will not be processed", s.getName());
                }
            }
        }
        return bundles;
    }

    private File createZipFile(Set<String> bundles) throws IOException {
        File rootDirectory = SupportPlugin.getRootDirectory();
        File zipFile = File.createTempFile(
            String.format("multiBundle(%s)-", bundles.size()), ".zip");
        zipFile.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(zipFile);
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            byte[] buffer = new byte[1024];
            for (String bundle : bundles) {
                File file = new File(rootDirectory, bundle);
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
}