/*
 * The MIT License
 *
 * Copyright (c) 2018, CloudBees, Inc.
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
package com.cloudbees.jenkins.support.filter;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.BulkChange;
import hudson.model.FreeStyleProject;
import hudson.model.ListView;
import hudson.model.User;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.WithTimeout;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;

import static org.assertj.core.api.Assertions.assertThat;

public class SensitiveContentFilterTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Issue("JENKINS-21670")
    @Test
    public void anonymizeAgentsAndLabels() throws Exception {
        SensitiveContentFilter filter = SensitiveContentFilter.get();
        // using foo, bar, jar and war could raise flaky test failures. It happened to me when
        // bar was changed by label_barrier :-O So we use stranger words to avoid this test to be flaky
        j.createSlave("foostrange", "barstrange", null);
        j.createSlave("jarstrange", "warstrange", null);
        filter.reload();

        String foo = filter.filter("foostrange");
        assertThat(foo).startsWith("computer_").doesNotContain("foostrange");

        String bar = filter.filter("barstrange");
        assertThat(bar).startsWith("label_").doesNotContain("barstrange");

        String jar = filter.filter("jarstrange");
        assertThat(jar).startsWith("computer_").doesNotContain("jarstrange");

        String war = filter.filter("warstrange");
        assertThat(war).startsWith("label_").doesNotContain("warstrange");
    }

    @Issue("JENKINS-21670")
    @Test
    public void anonymizeItems() throws IOException {
        SensitiveContentFilter filter = SensitiveContentFilter.get();
        FreeStyleProject project = j.createFreeStyleProject();
        filter.reload();
        String name = project.getName();

        String actual = filter.filter(name);

        assertThat(actual).startsWith("item_").doesNotContain(name);
    }

    @Issue("JENKINS-21670")
    @Test
    public void anonymizeViews() throws IOException {
        SensitiveContentFilter filter = SensitiveContentFilter.get();
        j.getInstance().addView(new ListView("foobar"));
        filter.reload();

        String foobar = filter.filter("foobar");

        assertThat(foobar).startsWith("view_").doesNotContain("foobar");
    }

    @Issue("JENKINS-21670")
    @Test
    public void anonymizeUsers() {
        SensitiveContentFilter filter = SensitiveContentFilter.get();
        User.getOrCreateByIdOrFullName("gibson");
        filter.reload();

        String gibson = filter.filter("gibson");

        assertThat(gibson).startsWith("user_").doesNotContain("gibson");
    }

    @Issue("JENKINS-54688")
    @Test
    public void shouldNotFilterOperatingSystem() throws Exception {
        String os = "Linux";
        String label = "fake";
        SensitiveContentFilter filter = SensitiveContentFilter.get();
        j.createSlave("foo", String.format("%s %s", os, label), null);
        filter.reload();
        assertThat(filter.filter(os)).isEqualTo(os);
        assertThat(filter.filter(label)).startsWith("label_").isNotEqualTo(label);
    }

    @Test
    public void shouldAnonymizeVariousNames() throws Exception {
        // Per Jenkins.checkGoodName ?*/\%!@#$^&|<>[]:;
        FreeStyleProject project = j.createFreeStyleProject("qwertyuiopasdfghjklzxcvbnm~ -_=+'");
        SensitiveContentFilter filter = SensitiveContentFilter.get();
        filter.reload();
        assertThat(filter.filter(project.getName())).startsWith("item_").doesNotContain(project.getName());
    }

    @Test
    @WithTimeout(3600)
    public void benchmark() throws Exception {
//        SensitiveContentFilter.setPatternQuoting(1);
//        SensitiveContentFilter.Trie trie = new SensitiveContentFilter.Trie();
//        trie.add("abc");
//        trie.add("ab");
//        trie.add("abcd");
//        trie.add("bcd");
//        trie.add("acdc");
//        trie.add("acd");
//        trie.add("dse+support-team@acme.com");
//        trie.add("test-?*/\\%!@#$^&|<>[]:;-git");
//        trie.add("special-\\\"$;><&#_=@!|.,/test");
//        trie.add("!built-in");
//        trie.add("!built-in node");
//        trie.add("!built-in&&(default||apac)");
//        System.out.println(trie.getRegex());

        createItems();
        createItemsTest();

        benchmarkRun(0, "/tmp/test.txt");
        benchmarkRun(1, "/tmp/test.txt");
//
//        benchmarkRun(0, "/tmp/benchmark.1000.txt");
//        benchmarkRun(0, "/tmp/benchmark.1000.all.txt");
//        benchmarkRun(1, "/tmp/benchmark.1000.txt");
//        benchmarkRun(1, "/tmp/benchmark.1000.all.txt");
//
//        benchmarkRun(0, "/tmp/benchmark.10000.txt");
//        benchmarkRun(0, "/tmp/benchmark.10000.all.txt");
//        benchmarkRun(1, "/tmp/benchmark.10000.txt");
//        benchmarkRun(1, "/tmp/benchmark.10000.all.txt");
//
//        benchmarkRun(0, "/tmp/benchmark.100000.txt");
//        benchmarkRun(0, "/tmp/benchmark.100000.all.txt");
//        benchmarkRun(1, "/tmp/benchmark.100000.txt");
//        benchmarkRun(1, "/tmp/benchmark.100000.all.txt");
//
        SensitiveContentFilter.setPatternQuoting(0);
        for(int i=0; i<5; i++) {
            benchmarkRun(3, "/tmp/benchmark.1000000.txt");
            benchmarkRun(3, "/tmp/benchmark.1000000.all.txt");
        }

        SensitiveContentFilter.setPatternQuoting(1);
        for(int i=0; i<5; i++) {
            benchmarkRun(3, "/tmp/benchmark.1000000.txt");
            benchmarkRun(3, "/tmp/benchmark.1000000.all.txt");
        }

        SensitiveContentFilter.setPatternQuoting(2);
        for(int i=0; i<5; i++) {
            benchmarkRun(3, "/tmp/benchmark.1000000.txt");
            benchmarkRun(3, "/tmp/benchmark.1000000.all.txt");
        }
    }

    @Test
    @WithTimeout(3600)
    public void benchmarkInet() throws Exception {
        benchmarkInetRun(0, "/tmp/benchmark.1000000.txt");
        benchmarkInetRun(0, "/tmp/benchmark.inet.1000000.all.txt");
        benchmarkInetRun(1, "/tmp/benchmark.1000000.txt");
        benchmarkInetRun(1, "/tmp/benchmark.inet.1000000.all.txt");
        benchmarkInetRun(2, "/tmp/benchmark.1000000.txt");
        benchmarkInetRun(2, "/tmp/benchmark.inet.1000000.all.txt");
    }


    private void benchmarkRun(int filterType, String filePath) throws IOException {
        String filteredFilePath = filePath + "." + filterType + ".filtered";
        SensitiveContentFilter.setFilterType(filterType);
        SensitiveContentFilter filter = SensitiveContentFilter.get();

        try (BulkChange change = new BulkChange(ContentMappings.get())) {
            filter.reload();
            change.commit();
        }

        try (OutputStream fos = new FileOutputStream(filteredFilePath);
             OutputStream bos = new BufferedOutputStream(fos)) {
            long startTime = System.currentTimeMillis();
//            try (FileReader reader = new FileReader(filePath);
//                 BufferedReader bufferedReader = new BufferedReader(reader)) {
//                bufferedReader.lines().forEach(line -> {
//                    try {
//                        String filtered = filter.filter(line);
//                        IOUtils.write(filtered, bos, "UTF-8");
//                        IOUtils.write("\n", bos, "UTF-8");
//                    } catch (IOException e) {
//                        throw new RuntimeException(e);
//                    }
//                });
//
//            }
            for (String s : Files.readAllLines(new File(filePath).toPath())) {
                String filtered = filter.filter(s);
                IOUtils.write(filtered, bos, "UTF-8");
                IOUtils.write("\n", bos, "UTF-8");
            }
            System.out.println("Took " + (System.currentTimeMillis() - startTime) + "ms to process file " + filePath + " with filter " + filterType);
        }
    }

    private void benchmarkInetRun(int filterType, String filePath) throws IOException {
        String filteredFilePath = filePath + ".inet." + filterType + ".filtered";
        InetAddressContentFilter.setFilterType(filterType);
        InetAddressContentFilter filter = InetAddressContentFilter.get();

        try (BulkChange change = new BulkChange(ContentMappings.get())) {
            filter.reload();
            change.commit();
        }

        try (OutputStream fos = new FileOutputStream(filteredFilePath);
             OutputStream bos = new BufferedOutputStream(fos)) {
            long startTime = System.currentTimeMillis();
//            try (FileReader reader = new FileReader(filePath);
//                 BufferedReader bufferedReader = new BufferedReader(reader)) {
//                bufferedReader.lines().forEach(line -> {
//                    try {
//                        String filtered = filter.filter(line);
//                        IOUtils.write(filtered, bos, "UTF-8");
//                        IOUtils.write("\n", bos, "UTF-8");
//                    } catch (IOException e) {
//                        throw new RuntimeException(e);
//                    }
//                });
//
//            }
            for (String s : Files.readAllLines(new File(filePath).toPath())) {
                String filtered = filter.filter(s);
                IOUtils.write(filtered, bos, "UTF-8");
                IOUtils.write("\n", bos, "UTF-8");
            }
            System.out.println("Took " + (System.currentTimeMillis() - startTime) + "ms to process file " + filePath + " with filter " + filterType);
        }
    }

    private String randomName(int length, char[] charList) {
        StringBuilder random = new StringBuilder();
        for(int i =0; i < length; i++) {
            int index = (int) (Math.random()*charList.length);
            random.append(charList[index]);
        }
        return random.toString();
    }

    private void createItemsTest() throws IOException {
        j.createProject(hudson.model.FreeStyleProject.class,  "bcde");
        j.createProject(hudson.model.FreeStyleProject.class,  "qRst");
        j.createProject(hudson.model.FreeStyleProject.class,  "abcd");
        j.createProject(hudson.model.FreeStyleProject.class,  "efgh");
        j.createProject(hudson.model.FreeStyleProject.class,  "ijkl");
        j.createProject(hudson.model.FreeStyleProject.class,  "Bcdefg");
        j.createProject(hudson.model.FreeStyleProject.class,  "mNop");
        j.createProject(hudson.model.FreeStyleProject.class,  "agent");
        j.jenkins.getLabel("!built-in&&(default||apac)");
        User.getOrCreateByIdOrFullName("dse+support-team@acme.com");
        User.getOrCreateByIdOrFullName("test-?*/\\%!@#$^&|<>[]:;-git");
        User.getOrCreateByIdOrFullName("special-\\\"$;><&#_=@!|.,/test");
    }

    private void createItems() throws IOException {
        char[] ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
        int alphaNumericInd = 0;

//        for(int i=0; i<ALPHANUMERIC.length; i++) {
//            for(int l=0; l<ALPHANUMERIC.length; l++) {
//                for(int k=0; k<2; k++) {
//                    j.createFreeStyleProject(
//                        ALPHANUMERIC[(alphaNumericInd++) % ALPHANUMERIC.length]
//                            + ALPHANUMERIC[i]
//                            + ALPHANUMERIC[l]
//                            + ALPHANUMERIC[k]
//                            + "freestyle");
//                }
//            }
//        }

        for(int i=0; i<5; i++) {
            Folder topFolder = j.createProject(Folder.class,  ALPHANUMERIC[(alphaNumericInd++)%ALPHANUMERIC.length] + "DeepFolder" + i);
            for(int j=0; j<2; j++) {
                Folder subFolder = topFolder.createProject(com.cloudbees.hudson.plugins.folder.Folder.class,  ALPHANUMERIC[(alphaNumericInd++)%ALPHANUMERIC.length] + "Folder" + i + "" + j);
                for(int k=0; k<2; k++) {
                    Folder subSubFolder = subFolder.createProject(com.cloudbees.hudson.plugins.folder.Folder.class,  ALPHANUMERIC[(alphaNumericInd++)%ALPHANUMERIC.length] + "Folder" + i + "" + j + "" + k);
                    for(int l=0; l<2; l++) {
                        Folder subSubSubFolder = subSubFolder.createProject(com.cloudbees.hudson.plugins.folder.Folder.class,  ALPHANUMERIC[(alphaNumericInd++)%ALPHANUMERIC.length] + "Folder" + i + "" + j + "" + k + "" + l);
                        for(int m=0; m<2; m++) {
                            Folder subSubSubSubFolder = subSubSubFolder.createProject(com.cloudbees.hudson.plugins.folder.Folder.class,  ALPHANUMERIC[(alphaNumericInd++)%ALPHANUMERIC.length] + "Folder" + i + "" + j + "" + k + "" + l + "" + m);
                            for(int n=0; n<2; n++) {
                                Folder subSubSubSubSubFolder = subSubSubSubFolder.createProject(com.cloudbees.hudson.plugins.folder.Folder.class,  ALPHANUMERIC[(alphaNumericInd++)%ALPHANUMERIC.length] + "Folder" + i + "" + j + "" + k + "" + l + "" + m + "" + n);
                                for(int o=0; o<2; o++) {
                                    Folder subSubSubSubSubSubFolder = subSubSubSubSubFolder.createProject(com.cloudbees.hudson.plugins.folder.Folder.class,  ALPHANUMERIC[(alphaNumericInd++)%ALPHANUMERIC.length] + "Folder" + i + "" + j + "" + k + "" + l + "" + m + "" + n + "" + o);
                                    for(int q=0; q<10; q++) {
                                        subSubSubSubSubSubFolder.createProject(hudson.model.FreeStyleProject.class, ALPHANUMERIC[(alphaNumericInd++)%ALPHANUMERIC.length] + "Pipeline" + i + "" + j + "" + k + "" + l + "" + m + "" + n + "" + o + "" + q);
                                    }
                                    for(int q=0; q<5; q++) {
                                        subSubSubSubSubSubFolder.createProject(hudson.model.FreeStyleProject.class,  ALPHANUMERIC[(alphaNumericInd++)%ALPHANUMERIC.length] + "Freestyle" + i + "" + j + "" + k + "" + l + "" + m + "" + n + "" + o + "" + q);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
