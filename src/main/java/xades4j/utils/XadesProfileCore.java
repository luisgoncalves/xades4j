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

import com.google.inject.Binder;
import com.google.inject.Guice;
import com.google.inject.Key;
import com.google.inject.Module;
import com.google.inject.TypeLiteral;
import com.google.inject.multibindings.MapBinder;
import com.google.inject.multibindings.Multibinder;
import com.google.inject.util.Modules;
import com.google.inject.util.Types;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

/**
 * Helper class that implements the core logic of profile resolution based on a series
 * of dependencies. Profile resultion is based on Google's dependency container
 * (Guice).
 * @see xades4j.production.XadesSigningProfile
 * @see xades4j.verification.XadesVerificationProfile
 * @see xades4j.production.XadesFormatExtenderProfile
 * @author Luís
 */
public final class XadesProfileCore
{
    private static interface BindingAction
    {
        void bind(Binder b);
    }
    /**/
    private final Collection<BindingAction> bindings;

    public XadesProfileCore()
    {
        this.bindings = new ArrayList<BindingAction>();
    }

    /**
     * @throws NullPointerException if {@code from} or {@code to} are null
     */
    public <T> void addBinding(final Class<T> from, final Class<? extends T> to)
    {
        if (null == from || null == to)
            throw new NullPointerException();

        this.bindings.add(new BindingAction()
        {
            @Override
            public void bind(Binder b)
            {
                b.bind(from).to(to);
            }
        });
    }

    /**
     * @throws NullPointerException if {@code from} or {@code to} are null
     */
    public <T> void addBinding(final Class<T> from, final T to)
    {
        if (null == from || null == to)
            throw new NullPointerException();

        this.bindings.add(new BindingAction()
        {
            @Override
            public void bind(Binder b)
            {
                b.bind(from).toInstance(to);
            }
        });
    }

    public void addGenericBinding(
            final Type genericClass,
            final Class to,
            final Type... genericClassParams)
    {
        if (ObjectUtils.anyNull(genericClass, genericClassParams, to))
            throw new NullPointerException();

        this.bindings.add(new BindingAction()
        {
            @Override
            public void bind(Binder b)
            {
                ParameterizedType pt = Types.newParameterizedType(genericClass, genericClassParams);
                Key k = Key.get(TypeLiteral.get(pt));
                b.bind(k).to(to);
            }
        });
    }

    public void addGenericBinding(
            final Type genericClass,
            final Object to,
            final Type... genericClassParams)
    {
        if (ObjectUtils.anyNull(genericClass, genericClassParams, to))
            throw new NullPointerException();

        this.bindings.add(new BindingAction()
        {
            @Override
            public void bind(Binder b)
            {
                ParameterizedType pt = Types.newParameterizedType(genericClass, genericClassParams);
                Key k = Key.get(TypeLiteral.get(pt));
                b.bind(k).toInstance(to);
            }
        });
    }

    public <T> void addMultibinding(final Class<T> from, final Class<? extends T> to)
    {
        if (null == from || null == to)
            throw new NullPointerException();

        this.bindings.add(new BindingAction()
        {
            @Override
            public void bind(Binder b)
            {
                Multibinder multibinder = Multibinder.newSetBinder(b, from);
                multibinder.addBinding().to(to);
            }
        });
    }

    public <T> void addMultibinding(final Class<T> from, final T to)
    {
        if (null == from || null == to)
            throw new NullPointerException();

        this.bindings.add(new BindingAction()
        {
            @Override
            public void bind(Binder b)
            {
                Multibinder multibinder = Multibinder.newSetBinder(b, from);
                multibinder.addBinding().toInstance(to);
            }
        });
    }

    public <T, TV extends T> void addMapBinding(final Class<T> valueClass, final Object key, final TV value)
    {
        if (null == key || null == value)
            throw new NullPointerException();

        this.bindings.add(new BindingAction()
        {
            @Override
            public void bind(Binder b)
            {
                MapBinder mapBinder = MapBinder.newMapBinder(b, key.getClass(), valueClass);
                mapBinder.addBinding(key).toInstance(value);
            }
        });
    }

    public <T> void addMapBinding(final Class<T> valueClass, final Object key, final Class<? extends T> to)
    {
        if (null == key || null == to)
            throw new NullPointerException();

        this.bindings.add(new BindingAction()
        {
            @Override
            public void bind(Binder b)
            {
                MapBinder mapBinder = MapBinder.newMapBinder(b, key.getClass(), valueClass);
                mapBinder.addBinding(key).to(to);
            }
        });
    }

    public <T> T getInstance(
            Class<T> clazz,
            Module[] overridableModules,
            Module[] sealedModules) throws XadesProfileResolutionException
    {
        Module userBindingsModule = new Module()
        {
            @Override
            public void configure(Binder b)
            {
                for (BindingAction ba : bindings)
                {
                    ba.bind(b);
                }
            }
        };
        Module overridesModule = Modules.override(overridableModules).with(userBindingsModule);
        // Concat sealed modules with overrides module
        Module[] finalModules = Arrays.copyOf(sealedModules, sealedModules.length + 1);
        finalModules[finalModules.length - 1] = overridesModule;
        try
        {
            return Guice.createInjector(finalModules).getInstance(clazz);
        }
        catch (RuntimeException ex)
        {
            throw new XadesProfileResolutionException(ex.getMessage(), ex);
        }
    }
}
