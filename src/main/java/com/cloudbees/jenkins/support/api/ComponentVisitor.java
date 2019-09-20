package com.cloudbees.jenkins.support.api;

import java.util.function.Consumer;

/**
 * @author Allan Burdajewicz
 */
public abstract class ComponentVisitor implements Consumer<Component> {

    private Container container;

    public ComponentVisitor() {}

    public final ComponentVisitor withContainer(Container container) {
        this.container = container;
        return this;
    }
    
    @Override
    public void accept(Component component) {
        visit(component, container);
    }

    @Override
    public Consumer<Component> andThen(Consumer<? super Component> after) {
        return null;
    }
    
    public abstract void visit(Component component, Container container);
}
