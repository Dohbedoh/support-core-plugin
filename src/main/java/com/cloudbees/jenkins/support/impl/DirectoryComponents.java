package com.cloudbees.jenkins.support.impl;

import com.cloudbees.jenkins.support.api.AbstractComponent;
import com.cloudbees.jenkins.support.api.Container;
import com.cloudbees.jenkins.support.api.FileContent;
import com.cloudbees.jenkins.support.api.FilePathContent;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionPoint;
import hudson.model.*;
import hudson.security.Permission;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class DirectoryComponents<T extends Actionable> extends AbstractComponent<T> implements ExtensionPoint {

    static final Logger LOGGER = Logger.getLogger(DirectoryComponents.class.getName());

    private String includes;
    private String excludes;

    public DirectoryComponents() {
        super();
        this.includes = "";
        this.excludes = "";
    }

    public DirectoryComponents(String includes, String excludes) {
        this.includes = includes;
        this.excludes = excludes;
    }

    public String getIncludes() {
        return includes;
    }

    public String getExcludes() {
        return excludes;
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
//    @Override
    public String getDisplayName() {
        return "Files in Directory";
    }

    public static class DirectoryComponentsDescriptor<T extends Actionable> extends Descriptor<AbstractComponent<T>> {

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public String getDisplayName() {
            return "Files in Directory";
        }

    }

    @Extension
    public static class NodeRemoteDirectoryComponents extends DirectoryComponents<Computer> {

        public NodeRemoteDirectoryComponents() {
            super();
        }

        @DataBoundConstructor
        public NodeRemoteDirectoryComponents(String includes, String excludes) {
            super(includes, excludes);
        }

        @Override
        public void addContents(@NonNull Container container, Computer item) {
            try {
                // https://github.com/jenkinsci/workflow-api-plugin/blob/master/src/main/java/org/jenkinsci/plugins/workflow/flow/StashManager.java
                Arrays.stream(item.getNode().getRootPath().list(getIncludes(), getExcludes(), false)).forEach(
                        filePath -> {
                            String relativePath = Paths.get(item.getNode().getRootPath().getRemote()).relativize(Paths.get(filePath.getRemote())).toString();
                            container.add(new FilePathContent(
                                    "nodes/{0}/remote/{1}",
                                    new String[]{item.getNode().getNodeName(), relativePath},
                                    filePath)
                            );
                        });
            } catch (IOException | InterruptedException e) {
                LOGGER.log(Level.WARNING, "Could not list files from remote directory of " + item.getNode().getNodeName(), e);
            }

        }

        @Override
        public boolean isApplicable(Class<?> clazz) {
            return Computer.class.isAssignableFrom(clazz);
        }

        @Override
        public DescriptorImpl getDescriptor() {
            return Jenkins.get().getDescriptorByType(DescriptorImpl.class);
        }

        @Extension
        @Symbol("nodeRemoteDirectoryComponent")
        public static class DescriptorImpl extends DirectoryComponentsDescriptor<Computer> {

            /**
             * {@inheritDoc}
             */
            @NonNull
            @Override
            public String getDisplayName() {
                return "Files in Remote Agent Directory";
            }
        }

    }

    @Extension
    public static class ItemDirectoryComponents extends DirectoryComponents<AbstractItem> {

        public ItemDirectoryComponents() {
            super();
        }

        @DataBoundConstructor
        public ItemDirectoryComponents(String includes, String excludes) {
            super(includes, excludes);
        }

        @Override
        public boolean isApplicable(Class<?> clazz) {
            return AbstractItem.class.isAssignableFrom(clazz);
        }

        @Override
        public DescriptorImpl getDescriptor() {
            return Jenkins.get().getDescriptorByType(DescriptorImpl.class);
        }

        @Override
        public void addContents(@NonNull Container container, AbstractItem item) {
            try {
                Files.walk(item.getRootDir().toPath())
                        .filter(path -> !Files.isDirectory(path) && !Files.isSymbolicLink(path))
                        .forEach(filePath -> {
                                    String relativePath = item.getRootDir().toPath().relativize(filePath).toString();
                                    container.add(new FileContent(
                                            "items/{0}/{1}",
                                            new String[]{item.getFullName(), relativePath},
                                            filePath.toFile())
                                    );
                                }
                        );
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Could not list files from root directory of " + item.getFullName(), e);
            }
        }

        @Extension
        @Symbol("itemDirectoryComponent")
        public static class DescriptorImpl extends DirectoryComponentsDescriptor<AbstractItem> {

            /**
             * {@inheritDoc}
             */
            @NonNull
            @Override
            public String getDisplayName() {
                return "Files in Item Directory";
            }
        }

    }

    @Extension
    public static class RunDirectoryComponents extends DirectoryComponents<Run> {

        public RunDirectoryComponents() {
            super();
        }

        @DataBoundConstructor
        public RunDirectoryComponents(String includes, String excludes) {
            super(includes, excludes);
        }

        @Override
        public boolean isApplicable(Class<?> clazz) {
            return Run.class.isAssignableFrom(clazz);
        }
        
        @Override
        public void addContents(@NonNull Container container, Run item) {
            try {
                Files.walk(item.getRootDir().toPath())
                        .filter(path -> !Files.isDirectory(path) && !Files.isSymbolicLink(path))
                        .forEach(filePath -> {
                                    String relativePath = item.getRootDir().toPath().relativize(filePath).toString();
                                    container.add(new FileContent(
                                            "builds/{0}/{1}/{2}",
                                            new String[]{item.getParent().getFullName(), "" + item.getNumber(), relativePath},
                                            filePath.toFile())
                                    );
                                }
                        );
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Could not list files from root directory of " + item.getParent().getFullName() + "#" + item.getNumber(), e);
            }
        }
        
        @Override
        public DescriptorImpl getDescriptor() {
            return Jenkins.get().getDescriptorByType(DescriptorImpl.class);
        }

        @Extension
        @Symbol("runDirectoryComponent")
        public static class DescriptorImpl extends DirectoryComponentsDescriptor<Run> {

            /**
             * {@inheritDoc}
             */
            @NonNull
            @Override
            public String getDisplayName() {
                return "Files in Build Directory";
            }
        }
    }
}
