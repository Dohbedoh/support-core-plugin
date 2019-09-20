package com.cloudbees.jenkins.support.actions;

import com.cloudbees.jenkins.support.SupportPlugin;
import com.cloudbees.jenkins.support.api.AbstractComponent;
import hudson.model.*;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.util.DescribableList;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.Nonnull;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Abstract action for Support Action at Object level.
 * 
 * @param <T> The type of {@link Actionable}
 */
public abstract class AbstractSupportAction<T extends Actionable> implements Action {

    static final Logger LOGGER = Logger.getLogger(AbstractSupportAction.class.getName());

    private List<AbstractComponent<T>> components = new ArrayList<>();

    @Nonnull
    private final T object;

    public AbstractSupportAction(@Nonnull T object) {
        this.object = object;
    }

    @Nonnull
    public final T getObject() {
        return object;
    }

    @Override
    public String getUrlName() {
        return "support";
    }

    @Override
    public String getIconFileName() {
        return "/plugin/support-core/images/24x24/support.png";
    }

    @DataBoundSetter
    public void setComponents(List<AbstractComponent<T>> components) {
        this.components = new ArrayList<>(components);
    }

    public List<AbstractComponent<T>> getComponents() {
        return components;
    }

    @SuppressWarnings("unused") // used by Stapler
    public List<Descriptor<AbstractComponent<T>>> getApplicableComponentsDescriptors() {
        return AbstractComponent.for_(object);
    }
    
    @RequirePOST
    public final void doGenerateAndDownload(StaplerRequest req, StaplerResponse rsp) 
            throws ServletException, IOException, Descriptor.FormException {
        
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        LOGGER.fine("Preparing response...");
        rsp.setContentType("application/zip");

        JSONObject json = req.getSubmittedForm();
        if (!json.has("components")) {
            rsp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        LOGGER.fine("Parsing request...");
        List<AbstractComponent<T>> components = new ArrayList<>(parseRequest(req, getObject().getClass()));
//        List<AbstractComponent<T>> components = parseRequest(req, getObject().getClass()).stream()
//                .peek(abstractComponent -> abstractComponent.setItem(object))
//                .collect(Collectors.toList());

        rsp.addHeader("Content-Disposition", "inline; filename=" + SupportPlugin.getBundleFileName() + ";");
        
        try {
            SupportPlugin.setRequesterAuthentication(Jenkins.getAuthentication());
            try (ACLContext old = ACL.as(ACL.SYSTEM)) {
                SupportPlugin.writeBundle(rsp.getOutputStream(), components, object);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, e.getMessage(), e);
            } finally {
                SupportPlugin.clearRequesterAuthentication();
            }
        } finally {
            LOGGER.fine("Response completed");
        }
    }    
    
    
    protected final List<AbstractComponent<T>> parseRequest(StaplerRequest req, Class<? extends Actionable> objectClass)
            throws ServletException, Descriptor.FormException {

        LOGGER.fine("Parsing request...");
        // Inspired by https://github.com/jenkinsci/workflow-job-plugin/blob/workflow-job-2.35/src/main/java/org/jenkinsci/plugins/workflow/job/properties/PipelineTriggersJobProperty.java
        DescribableList<AbstractComponent<T>, Descriptor<AbstractComponent<T>>> components =
                new DescribableList<>(Saveable.NOOP);
        try {
            JSONObject componentsSection = new JSONObject();
            if (req.getSubmittedForm() != null) {
                componentsSection = req.getSubmittedForm().getJSONObject("components");
            }
            components.rebuild(req, componentsSection, getApplicableComponentsDescriptors());
        } catch (IOException e) {
            throw new Descriptor.FormException(e, "components");
        }
        return components;
    }
}
