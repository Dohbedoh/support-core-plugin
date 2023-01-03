package com.cloudbees.jenkins.support.actions;

import com.cloudbees.jenkins.support.SupportAction;
import com.cloudbees.jenkins.support.SupportPlugin;
import edu.umd.cs.findbugs.annotations.NonNull;
import jdk.jfr.Configuration;
import jdk.jfr.EventType;
import jdk.jfr.FlightRecorder;
import jdk.jfr.Recording;
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
import java.nio.file.Path;
import java.text.ParseException;
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
 * Support Action to manage Java Flight Recorder features.
 */
@Restricted(NoExternalUse.class)
public class SupportJFRAction extends SupportChildAction {

    private static final Logger LOGGER = Logger.getLogger(SupportJFRAction.class.getName());

    static final String URL = "jfr";

    public SupportJFRAction(@NonNull SupportAction supportAction) {
        super(supportAction);
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
    public void doRecord(StaplerRequest req, StaplerResponse rsp) throws ServletException, IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        //TODO download logic
        rsp.sendRedirect(".");
    }

    @RequirePOST
    @SuppressWarnings("unused") // Stapler
    public void doDownload(StaplerRequest req, StaplerResponse rsp) throws ServletException, IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        //TODO download logic
        rsp.sendRedirect(".");
    }
    public static class CrashDump {

        private static Recording rec;

        public static synchronized void activate() throws IOException, ParseException {
            if (rec != null) {
                Configuration conf = Configuration.getConfiguration("default");
                rec = new Recording(conf);
                configureEvents(rec);
                // disable disk writes
                rec.setToDisk(false);
                rec.start();
            }

        }

        private static void configureEvents(Recording rec) {
            for (EventType et: FlightRecorder.getFlightRecorder().getEventTypes()) {
                if (isEnabledForCrachDump(et)) {
                    rec.enable(et.getName());
                }
            }

        }

        private static boolean isEnabledForCrachDump(EventType et) {
            return true;
        }

        public void dump(Path filename) throws IOException {
            rec.dump(filename);
        }

    }
}
