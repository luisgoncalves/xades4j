/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.utils;

import com.google.inject.AbstractModule;
import com.google.inject.Module;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/* Test classes/interfaces */
interface A
{
}

class AImpl1 implements A
{
}

class AImpl2 implements A
{
}

interface B
{
}

class BImpl implements B
{
}

interface Action<T>
{
    void doAction(T t);
}

class ActionOfA implements Action<A>
{
    @Override
    public void doAction(A t)
    {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}

class C
{
    public final Action<A> action;

    @Inject
    public C(Action<A> action)
    {
        this.action = action;
    }
}

class D
{
    public Set<A> as;

    @Inject
    public D(Set<A> as)
    {
        this.as = as;
    }

}

class E
{
    public Map<String, A> as;

    @Inject
    public E(Map<String, A> as)
    {
        this.as = as;
    }

}

/**
 * @author Luís
 */
class XadesProfileCoreTest
{
    @Test
    void testGetInstance() throws XadesProfileResolutionException
    {
        Module module = new AbstractModule()
        {
            @Override
            protected void configure()
            {
                bind(A.class).to(AImpl1.class);
            }
        };
        XadesProfileCore instance = new XadesProfileCore();
        A a = instance.getInstance(A.class, new Module[]{module}, new Module[0]);
        assertNotNull(a);
        assertTrue(a instanceof AImpl1);
    }

    @Test
    void testGetInstanceException() throws XadesProfileResolutionException
    {
        XadesProfileCore instance = new XadesProfileCore();
        assertThrows(XadesProfileResolutionException.class, () -> instance.getInstance(A.class, new Module[0], new Module[0]));
    }

    @Test
    void testAddBinding() throws XadesProfileResolutionException
    {
        Module module = new AbstractModule()
        {
            @Override
            protected void configure()
            {
                bind(A.class).to(AImpl1.class);
            }
        };
        XadesProfileCore instance = new XadesProfileCore();
        instance.addBinding(A.class, AImpl2.class);
        A a = instance.getInstance(A.class, new Module[]{module}, new Module[0]);
        assertNotNull(a);
        assertTrue(a instanceof AImpl2);

        B b1 = new BImpl();
        instance.addBinding(B.class, b1);
        B b2 = instance.getInstance(B.class, new Module[]{module}, new Module[0]);
        assertNotNull(a);
        assertEquals(b1, b2);
    }

    @Test
    void testAddGenericBinding() throws XadesProfileResolutionException
    {
        XadesProfileCore instance = new XadesProfileCore();
        instance.addGenericBinding(Action.class, ActionOfA.class, A.class);
        C c = instance.getInstance(C.class, new Module[0], new Module[0]);
        assertTrue(c.action instanceof ActionOfA);
    }

    @Test
    void testAddMultibinding() throws Exception
    {
        XadesProfileCore instance = new XadesProfileCore();
        instance.addMultibinding(A.class, AImpl1.class);
        instance.addMultibinding(A.class, new AImpl1());
        instance.addMultibinding(A.class, AImpl2.class);

        D d = instance.getInstance(D.class, new Module[0], new Module[0]);
        assertEquals(3, d.as.size());
    }

    @Test
     void testAddMapBinding() throws Exception
    {
        XadesProfileCore instance = new XadesProfileCore();
        instance.addMapBinding(A.class, "A1", AImpl1.class);
        instance.addMapBinding(A.class, "A2", AImpl2.class);

        E e = instance.getInstance(E.class, new Module[0], new Module[0]);

        assertEquals(2, e.as.size());
        assertEquals(AImpl1.class, e.as.get("A1").getClass());
        assertEquals(AImpl2.class, e.as.get("A2").getClass());
    }
}
