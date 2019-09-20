package com.cloudbees.jenkins.support.impl;

import com.cloudbees.jenkins.support.api.ObjectComponent;
import com.cloudbees.jenkins.support.api.ObjectComponentDescriptor;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;
import hudson.model.AbstractModelObject;
import hudson.security.Permission;
import hudson.util.DirScanner;
import hudson.util.FileVisitor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.QueryParameter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Logger;

public abstract class DirectoryComponent<T extends AbstractModelObject> extends ObjectComponent<T> implements ExtensionPoint {

    static final Logger LOGGER = Logger.getLogger(DirectoryComponent.class.getName());

    private String includes;
    private String excludes;
    private int maxDepth;
    private boolean defaultExcludes;

    public DirectoryComponent() {
        super();
        setExcludes(getDescriptor().getExcludes());
        setIncludes(getDescriptor().getIncludes());
        setDefaultExcludes(getDescriptor().isDefaultExcludes());
        setMaxDepth(getDescriptor().getMaxDepth());
    }

    public DirectoryComponent(String includes, String excludes, boolean defaultExcludes, int maxDepth) {
        setExcludes(excludes);
        setIncludes(includes);
        setDefaultExcludes(defaultExcludes);
        setMaxDepth(maxDepth);
    }

    protected final void list(File dir, FileVisitor visitor) throws IOException {
        DirScanner scan = new DirScanner.Glob(getIncludes(), getExcludes(), getDefaultExcludes());
        scan.scan(dir, new FileVisitor() {

            @Override
            public void visit(File file, String s) throws IOException {
                if (Paths.get(s).getNameCount() <= getMaxDepth()) {
                    visitor.visit(file, s);
                }
            }
        });
    }

    public String getIncludes() {
        return includes;
    }

    public String getExcludes() {
        return excludes;
    }

    public boolean getDefaultExcludes() {
        return defaultExcludes;
    }

    public int getMaxDepth() {
        return maxDepth;
    }

    public void setIncludes(String includes) {
        this.includes = includes;
    }

    public void setExcludes(String excludes) {
        this.excludes = excludes;
    }

    public void setDefaultExcludes(boolean defaultExcludes) {
        this.defaultExcludes = defaultExcludes;
    }

    public void setMaxDepth(int maxDepth) {
        this.maxDepth = maxDepth;
    }

    @Override
    public DirectoryComponentsDescriptor<T> getDescriptor() {
        return Jenkins.get().getDescriptorByType(DirectoryComponentsDescriptor.class);
    }

    @NonNull
    @Override
    public Set<Permission> getRequiredPermissions() {
        return Collections.singleton(Jenkins.ADMINISTER);
    }

    @NonNull
    @Override
    public String getDisplayName() {
        return "Files in Directory";
    }

    public static class DirectoryComponentsDescriptor<T extends AbstractModelObject> extends ObjectComponentDescriptor<T> {

        static final int DEFAULT_MAX_DEPTH = 10;

        private String includes;
        private String excludes;
        private boolean defaultExcludes;
        private int maxDepth;

        public DirectoryComponentsDescriptor() {
            setExcludes("");
            setIncludes("");
            setMaxDepth(DEFAULT_MAX_DEPTH);
            setDefaultExcludes(true);
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public String getDisplayName() {
            return "Files in Directory";
        }

        public String getIncludes() {
            return includes;
        }

        public void setIncludes(String includes) {
            this.includes = includes;
        }

        public String getExcludes() {
            return excludes;
        }

        public void setExcludes(String excludes) {
            this.excludes = excludes;
        }

        public boolean isDefaultExcludes() {
            return defaultExcludes;
        }

        public void setDefaultExcludes(boolean defaultExcludes) {
            this.defaultExcludes = defaultExcludes;
        }

        public int getMaxDepth() {
            return maxDepth;
        }

        public void setMaxDepth(int maxDepth) {
            this.maxDepth = maxDepth;
        }

        @Restricted(NoExternalUse.class) // stapler
        @SuppressWarnings("unused") // used by Stapler
        public FormValidation doCheckMaxDepth(@QueryParameter String value) {
            return FormValidation.validatePositiveInteger(value);
        }
    }
}
