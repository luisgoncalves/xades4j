/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */
package xades4j.verification;

import com.google.inject.ConfigurationException;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.ProvisionException;
import com.google.inject.TypeLiteral;
import com.google.inject.util.Types;
import java.lang.reflect.ParameterizedType;
import xades4j.properties.data.PropertyDataObject;

/**
 *
 * @author Luís
 */
class QualifyingPropertyVerifiersMapperImpl implements QualifyingPropertyVerifiersMapper
{
    private final Injector injector;

    @Inject
    public QualifyingPropertyVerifiersMapperImpl(Injector injector)
    {
        this.injector = injector;
    }

    @Override
    public <TData extends PropertyDataObject> QualifyingPropertyVerifier<TData> getVerifier(
            TData p) throws QualifyingPropertyVerifierNotAvailableException
    {
        try
        {
            ParameterizedType pt = Types.newParameterizedType(QualifyingPropertyVerifier.class, p.getClass());
            return (QualifyingPropertyVerifier)injector.getInstance(Key.get(TypeLiteral.get(pt)));
        } catch (ConfigurationException ex)
        {
        } catch (ProvisionException ex)
        {
        }
        throw new QualifyingPropertyVerifierNotAvailableException(p);
    }
}
