package com.cloudbees.jenkins.support.api;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;

import java.io.File;
import java.io.FilenameFilter;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An extension that help retrieve files generated by different class of Support Core to contribute to the content of 
 * used by the plugin. Such as log files, slow requests and deadlocks. This extension is used by Support Core to 
 * retrieve, manage or let an administrator manage those files. 
 */
public interface SupportContentContributor extends ExtensionPoint {

    /**
     * Return the parent directory where files are generated
     *
     * @return the directory {@link File}
     */
    @NonNull
    File getDirPath();

    /**
     * Return files currently contributed by this extension.
     *
     * @return the list of {@link File}s
     */
    @NonNull
    default List<File> getFiles() {
        FilenameFilter filter = getFilenameFilter();
        File [] files = filter == null
            ? getDirPath().listFiles()
            : getDirPath().listFiles(filter);
        if(files != null ) {
            return Arrays.stream(files).sorted(Comparator.comparing(File::getName)).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    /**
     * Get the {@link FilenameFilter} to use to retrieve the files 
     * @return the filter
     */
    @CheckForNull
    FilenameFilter getFilenameFilter();

    /**
     * ID that identify the type of content. Default to {@link Class#getName()}
     *
     * @return an ID as String
     */
    @NonNull
    default String getContributorId() {
        return this.getClass().getCanonicalName();
    }

    /**
     * Get the Human readable name for this contributor
     *
     * @return the name
     */
    @NonNull
    String getContributorName();

    /**
     * Get the description for this contributor. What content does it generate.
     * @return
     */
    @NonNull
    String getContributorDescription();
}