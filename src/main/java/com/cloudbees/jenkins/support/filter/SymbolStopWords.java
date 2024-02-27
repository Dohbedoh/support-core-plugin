package com.cloudbees.jenkins.support.filter;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.structs.SymbolLookup;
import org.jvnet.hudson.annotation_indexer.Index;

@Extension
public class SymbolStopWords implements StopWords {
    @NonNull
    @Override
    public Set<String> getWords() {
        try {
            Set<String> symbols = new HashSet<>();
            for (Class<?> e : Index.list(Symbol.class, Jenkins.get().pluginManager.uberClassLoader, Class.class)) {
                if (Descriptor.class.isAssignableFrom(e)) {
                    symbols.addAll(SymbolLookup.getSymbolValue(e));
                }
            }
            return symbols;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
