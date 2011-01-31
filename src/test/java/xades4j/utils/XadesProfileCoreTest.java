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
import com.google.inject.Inject;
import com.google.inject.Module;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

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

/**
 *
 * @author Luís
 */
public class XadesProfileCoreTest
{
    public XadesProfileCoreTest()
    {
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
    }

    @Before
    public void setUp()
    {
    }

    @After
    public void tearDown()
    {
    }

    @Test
    public void testGetInstance() throws XadesProfileResolutionException
    {
        System.out.println("getInstance");
        Module defaultsModule = new AbstractModule()
        {
            @Override
            protected void configure()
            {
                bind(A.class).to(AImpl1.class);
            }
        };
        XadesProfileCore instance = new XadesProfileCore();
        A a = instance.getInstance(A.class, defaultsModule);
        assertNotNull(a);
        assertTrue(a instanceof AImpl1);
    }

    @Test(expected = XadesProfileResolutionException.class)
    public void testGetInstanceException() throws XadesProfileResolutionException
    {
        System.out.println("getInstance_Exception");
        Module defaultsModule = new AbstractModule()
        {
            @Override
            protected void configure()
            {
            }
        };
        XadesProfileCore instance = new XadesProfileCore();
        instance.getInstance(A.class, defaultsModule);
    }

    @Test
    public void testWithBinding() throws XadesProfileResolutionException
    {
        System.out.println("withBinding");
        Module defaultsModule = new AbstractModule()
        {
            @Override
            protected void configure()
            {
                bind(A.class).to(AImpl1.class);
            }
        };
        XadesProfileCore instance = new XadesProfileCore();
        instance.addBinding(A.class, AImpl2.class);
        A a = instance.getInstance(A.class, defaultsModule);
        assertNotNull(a);
        assertTrue(a instanceof AImpl2);

        B b1 = new BImpl();
        instance.addBinding(B.class, b1);
        B b2 = instance.getInstance(B.class, defaultsModule);
        assertNotNull(a);
        assertEquals(b1, b2);
    }

    @Test
    public void testWithGenericBinding() throws XadesProfileResolutionException
    {
        System.out.println("withGenericBinding");
        Module defaultsModule = new AbstractModule()
        {
            @Override
            protected void configure()
            {
            }
        };
        XadesProfileCore instance = new XadesProfileCore();
        instance.addGenericBinding(Action.class, ActionOfA.class, A.class);
        C c = instance.getInstance(C.class, defaultsModule);
        assertTrue(c.action instanceof ActionOfA);
    }
}
