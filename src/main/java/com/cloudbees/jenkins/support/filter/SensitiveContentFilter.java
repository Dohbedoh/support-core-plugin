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

import com.cloudbees.jenkins.support.util.WordReplacer;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Filters contents based on names provided by all {@linkplain NameProvider known sources}.
 *
 * @see NameProvider
 * @since TODO
 */
@Extension
@Restricted(NoExternalUse.class)
public class SensitiveContentFilter implements ContentFilter {

    private static final Logger LOGGER = Logger.getLogger(SensitiveContentFilter.class.getName());

    private final ThreadLocal<Pattern> mappingsPattern = new ThreadLocal<>();
    private final ThreadLocal<Map<String, String>> replacementsMap = new ThreadLocal<>();

    private static Function<String, String> quoter = new Function<>() {
        @Override
        public String apply(String s) {
            return METACHARACTERS.matcher(s).matches() ? Pattern.quote(s) : s;
        }
    };

    /**
     * @see https://docs.oracle.com/javase/tutorial/essential/regex/literals.html
     */
    private static Pattern ALPHANUM = Pattern.compile("^[A-Za-z0-9_]+$");
    private static Pattern METACHARACTERS = Pattern.compile("[\\x21\\x24\\x28-\\x2B\\x2D-\\x2F\\x3C-\\x3F\\x5B-\\x5E\\x7B-\\x7D]+$");

    public static SensitiveContentFilter get() {
        return ExtensionList.lookupSingleton(SensitiveContentFilter.class);
    }

    private static int FILTER_TYPE = 3;

    static void setFilterType(int filterType) {
        FILTER_TYPE = filterType;
    }

    static void setPatternQuoting(int patternType) {
        if(patternType == 0) {
            quoter = s -> ALPHANUM.matcher(s).matches() ? s : Pattern.quote(s);
        } else if(patternType == 1) {
            quoter = s -> METACHARACTERS.matcher(s).matches() ? Pattern.quote(s) : s;
        } else {
            quoter = Pattern::quote;
        }
    }

//    public static void nextFilterType() {
//        FILTER_TYPE = (FILTER_TYPE + 1) % 4;
//    }

    @Override
    public @NonNull String filter(@NonNull String input) {
        switch (FILTER_TYPE) {
            case 0:
                return filter0(input);
            case 1:
            case 2:
            case 3:
                return filter1(input);
            default:
                throw new IllegalStateException("Unknown filter " + FILTER_TYPE);
        }
    }

    public @NonNull String filter0(@NonNull String input) {
        ContentMappings mappings = ContentMappings.get();
        String filtered = input;
        List<String> searchList = new ArrayList<>();
        List<String> replacementList = new ArrayList<>();

        for (ContentMapping mapping : mappings) {
            searchList.add(mapping.getOriginal());
            replacementList.add(mapping.getReplacement());
        }
        if (!searchList.isEmpty()) {
            filtered = WordReplacer.replaceWordsIgnoreCase(input, searchList.toArray(new String[0]), replacementList.toArray(new String[0]));
        }

        return filtered;
    }

    public @NonNull String filter1(@NonNull String input) {
        StringBuilder replacement = new StringBuilder();
        int lastIndex = 0;

        Matcher matcher = mappingsPattern.get().matcher(input.toLowerCase(Locale.ENGLISH));
        Map<String, String> replacements = replacementsMap.get();

        while (matcher.find()) {
            replacement.append(input, lastIndex, matcher.start());
            replacement.append(replacements.get(matcher.group()));
            lastIndex = matcher.end();
        }

        if (lastIndex < input.length()) {
            replacement.append(input, lastIndex, input.length());
        }

        return replacement.toString();
    }

    @Override
    public synchronized void reload() {
        long startTime = System.currentTimeMillis();
        switch (FILTER_TYPE) {
            case 0:
                reload0();
                break;
            case 1:
                reload1();
                break;
            case 2:
                reload2();
                break;
            case 3:
                reload3();
                break;
            default:
                throw new IllegalStateException("Unknown filter " + FILTER_TYPE);
        }
        LOGGER.log(Level.FINE, "Took " + (System.currentTimeMillis() - startTime) + "ms to reload pattern with filter " + FILTER_TYPE);
    }

    private void reload0() {
        ContentMappings mappings = ContentMappings.get();
        Set<String> stopWords = mappings.getStopWords();
        for (NameProvider provider : NameProvider.all()) {
            provider.names()
                .filter(name -> StringUtils.isNotBlank(name) && !stopWords.contains(name.toLowerCase(Locale.ENGLISH)))
                .forEach(name -> mappings.getMappingOrCreate(name, original -> ContentMapping.of(original, provider.generateFake())));
        }
    }

    private void reload1() {
        final Map<String, String> replacementsMap = new HashMap<>();
        final Set<String> originals = new TreeSet<>();

        ContentMappings mappings = ContentMappings.get();
        Set<String> stopWords = mappings.getStopWords();

        NameProvider.all().forEach(provider -> provider.names()
            .filter(StringUtils::isNotBlank)
            .map(name -> name.toLowerCase(Locale.ENGLISH))
            .filter(name -> !stopWords.contains(name))
            .forEach(name -> {
                ContentMapping mapping = mappings.getMappingOrCreate(name, original -> ContentMapping.of(original, provider.generateFake()));
                replacementsMap.put(mapping.getOriginal(), mapping.getReplacement());
                originals.add(Pattern.quote(mapping.getOriginal()));
            }));

        Pattern pattern = Pattern.compile("\\b(?:" + String.join("|", originals) + ")\\b", Pattern.CASE_INSENSITIVE);

        this.mappingsPattern.set(pattern);
        this.replacementsMap.set(replacementsMap);
    }

    private void reload2() {
        final Map<String, String> replacementsMap = new HashMap<>();
        final Map<Character, Set<String>> alphaNumeric = new TreeMap<>();

        ContentMappings mappings = ContentMappings.get();
        Set<String> stopWords = mappings.getStopWords();
        NameProvider.all().forEach(provider -> provider.names()
            .filter(StringUtils::isNotBlank)
            .map(name -> name.toLowerCase(Locale.ENGLISH))
            .filter(name -> !stopWords.contains(name))
            .forEach(name -> {
                ContentMapping mapping = mappings.getMappingOrCreate(name, original -> ContentMapping.of(original, provider.generateFake()));
                replacementsMap.put(mapping.getOriginal(), mapping.getReplacement());

                char alpha1 = name.charAt(0);
                String alpha1Remaining = name.substring(1);
                Set<String> originals = alphaNumeric.computeIfAbsent(alpha1, k -> new TreeSet<>(Comparator.comparingLong(String::length).reversed().thenComparing(Function.identity())));
                originals.add(Pattern.quote(alpha1Remaining));
            })
        );

        // Need to escape metacharacters https://docs.oracle.com/javase/tutorial/essential/regex/literals.html
        this.mappingsPattern.set(Pattern.compile(
            "(?:\\b(?:" +
                StreamSupport.stream(
                        Spliterators.spliteratorUnknownSize(alphaNumeric.entrySet().iterator(), Spliterator.NONNULL), false)
                    .map(entry -> entry.getValue().size() == 1
                        ? "(?:" + Pattern.quote(entry.getKey() + entry.getValue().iterator().next()) + ")"
                        : (Pattern.quote(String.valueOf(entry.getKey())) + "(?:" + String.join("|", entry.getValue()) + ")"))
                    .collect(Collectors.joining("|")) +
                ")\\b)",
            Pattern.CASE_INSENSITIVE));

        this.replacementsMap.set(replacementsMap);
        this.replacementsMap.set(replacementsMap);
    }

    private void reload3() {
        final Map<String, String> replacementsMap = new HashMap<>();
        final Trie trie = new Trie();
        final ContentMappings mappings = ContentMappings.get();
        Set<String> stopWords = mappings.getStopWords();
        NameProvider.all().forEach(provider ->
            provider.names()
                .filter(StringUtils::isNotBlank)
                .map(name -> name.toLowerCase(Locale.ENGLISH))
                .filter(name -> !stopWords.contains(name))
                .forEach(name -> {
                    ContentMapping mapping = mappings.getMappingOrCreate(name, original -> ContentMapping.of(original, provider.generateFake()));
                    replacementsMap.put(mapping.getOriginal(), mapping.getReplacement());
                    trie.add(mapping.getOriginal());
                }));
        this.mappingsPattern.set(Pattern.compile("(?:\\b(?:" + trie.getRegex() + ")\\b)", Pattern.CASE_INSENSITIVE));
        this.replacementsMap.set(replacementsMap);
        this.replacementsMap.set(replacementsMap);
    }

    static String quote(String s) {
        return quoter.apply(s);
    }

    static class TrieNode {

        private final Map<Character, TrieNode> data = new TreeMap<>();

        /**
         * Mark this node as the end of a word
         */
        private boolean end;

        TrieNode(boolean end) {
            this.end = end;
        }

        /**
         * Produce the regex String of the current TrieNode.
         *
         * * Iterates through all children TrieNode and join their regex String:
         *     * if child is only a characters, handle quoting
         *     * Otherwise, retrieve the child TrieNode regex String
         * * Add a '?' at the end if this is an end node.
         *
         * @return the regex String of the current TrieNode.
         */
        String getRegex() {

            if (this.data.isEmpty()) {
                // No data, stop here
                return null;
            }

            // List of suffix patterns
            final List<String> childPatterns = new ArrayList<>();
            // List of ending characters
            final List<Character> characters = new ArrayList<>();

            for (final Map.Entry<Character, TrieNode> entry : this.data.entrySet()) {
                final String entryRegex = entry.getValue().getRegex();
                if (entryRegex != null) {
                    childPatterns.add(quote(String.valueOf(entry.getKey())) + entryRegex);
                } else {
                    characters.add(entry.getKey());
                }
            }

            final boolean charsOnly = childPatterns.isEmpty();
            if (characters.size() == 1) {
                childPatterns.add(quote(String.valueOf(characters.get(0))));
            } else if (characters.size() > 0) {
                final StringBuilder buf = new StringBuilder("[");
                characters.forEach(character -> buf.append("]"));
                buf.append("]");
                childPatterns.add(buf.toString());
            }

            String result = childPatterns.size() == 1
                ? childPatterns.get(0)
                : "(?:" + String.join("|", childPatterns) + ")";

            // Is this is also a final character of a word, we need to add the ?
            if (end) {
                if (charsOnly) {
                    return result + "?";
                } else {
                    return "(?:" + result + ")?";
                }
            }
            return result;
        }

        public @NonNull TrieNode getOrCreate(@NonNull Character character,
                                             @NonNull Function<Character, TrieNode> generator) {
            return data.computeIfAbsent(character, generator);
        }
    }

    /**
     * Trie implementation to help generate a "Trie regex". A regex that reduce backtracking by following a Trie
     * structure. When searching for a match within a list of words, for example
     * ["go", "goes", "going", "gone", "goose"],  a simple regexp that matches any word would typically look like
     * {code}\b(?:(go|goes|going|gone|goose))\b{code}.
     *  While this works, Such a pattern can be optimized significantly by following a Trie structure in the prefixes
     *  such as {code}\b(?:go(?:(?:es|ing|ne|ose))?)\b{code}.
     *
     */
    static class Trie {

        final TrieNode root;

        public Trie() {
            this.root = new TrieNode(false);
        }

        /**
         * Add a word to the Trie.
         * @param word the word
         */
        public void add(String word) {
            TrieNode ref = root;
            int i = 0;
            while (i < word.length() - 1) {
                // Fill in down the Trie
                ref = ref.getOrCreate(word.charAt(i), s -> new TrieNode(false));
                i++;
            }
            // We need to mark the last node as an end node
            ref.getOrCreate(word.charAt(i), s -> new TrieNode(true)).end = true;
        }

        /**
         * Get the regex String of this Trie.
         *
         * @return the regex String of this Trie.
         */
        public String getRegex() {
            return root.getRegex();
        }
    }
}
