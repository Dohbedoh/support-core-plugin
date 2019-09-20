/*
 * The MIT License
 *
 * Copyright (c) 2013, CloudBees, Inc.
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

package com.cloudbees.jenkins.support.api;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.DescriptorExtensionList;
import hudson.ExtensionPoint;
import hudson.model.Actionable;
import hudson.model.Describable;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;

import java.util.List;
import java.util.stream.Collectors;

public abstract class AbstractComponent<T extends Actionable> extends Component 
        implements Describable<AbstractComponent<T>>, ExtensionPoint {

    /**
     * {@inheritDoc}
     */
    @Override
    public Descriptor<AbstractComponent<T>> getDescriptor() {
        return Jenkins.get().getDescriptorOrDie(this.getClass());
    }

    @Override
    public void addContents(@NonNull Container container) {
        // No op
    }

    public abstract void addContents(@NonNull Container container, T item);

    /**
     * All registered {@link Descriptor <AbstractComponent<?>>}s.
     */
    public static <T extends Actionable> DescriptorExtensionList<AbstractComponent<T>, Descriptor<AbstractComponent<T>>> all() {
        return (DescriptorExtensionList) Jenkins.get().getDescriptorList(AbstractComponent.class);
    }

    /**
     * All applicable {@link Descriptor}s for the class.
     */
    public static <T extends Actionable> List<Descriptor<AbstractComponent<T>>> for_(T item) {
        return Jenkins.get().getExtensionList(AbstractComponent.class).stream()
                .filter(component -> component.isApplicable(item.getClass()))
                .map(component -> ((AbstractComponent<T>)component).getDescriptor())
                .collect(Collectors.toList());
    }
}

