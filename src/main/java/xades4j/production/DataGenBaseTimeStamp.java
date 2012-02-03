/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2011 Luis Goncalves.
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

package xades4j.production;

import xades4j.algorithms.Algorithm;
import xades4j.UnsupportedAlgorithmException;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.BaseXAdESTimeStampData;
import xades4j.utils.TimeStampDigestInput;
import xades4j.properties.data.PropertyDataObject;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenProvider.TimeStampTokenRes;
import xades4j.utils.CannotAddDataToDigestInputException;
import xades4j.utils.TimeStampDigestInputFactory;

/**
 *
 * @author Luís
 */
abstract class DataGenBaseTimeStamp<TProp extends QualifyingProperty> implements PropertyDataObjectGenerator<TProp>
{
    private final AlgorithmsProviderEx algsProvider;
    private final TimeStampTokenProvider tsTokenProvider;
    private final TimeStampDigestInputFactory tsInputFactory;

    public DataGenBaseTimeStamp(AlgorithmsProviderEx algsProvider, TimeStampTokenProvider tsTokenProvider, TimeStampDigestInputFactory tsInputFactory)
    {
        this.algsProvider = algsProvider;
        this.tsTokenProvider = tsTokenProvider;
        this.tsInputFactory = tsInputFactory;
    }

    @Override
    public final PropertyDataObject generatePropertyData(TProp prop, PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        Algorithm c14n = this.algsProvider.getCanonicalizationAlgorithmForTimeStampProperties();

        try
        {
            TimeStampDigestInput digestInput = this.tsInputFactory.newTimeStampDigestInput(c14n);
            addPropSpecificTimeStampInput(prop, digestInput, ctx);

            TimeStampTokenRes tsTknRes = this.tsTokenProvider.getTimeStampToken(
                    digestInput.getBytes(),
                    this.algsProvider.getDigestAlgorithmForTimeStampProperties());
            return createPropDataObj(prop, c14n, tsTknRes, ctx);
        }
        catch (UnsupportedAlgorithmException ex)
        {
            throw new PropertyDataGenerationException(prop, ex.getMessage(), ex);
        }
        catch (CannotAddDataToDigestInputException ex)
        {
            throw new PropertyDataGenerationException(prop, "cannot create time stamp input", ex);
        }
        catch (TimeStampTokenGenerationException ex)
        {
            throw new PropertyDataGenerationException(prop, "cannot get a time-stamp", ex);
        }
    }

    protected abstract void addPropSpecificTimeStampInput(
            TProp prop,
            TimeStampDigestInput digestInput,
            PropertiesDataGenerationContext ctx) throws CannotAddDataToDigestInputException, PropertyDataGenerationException;

    protected abstract BaseXAdESTimeStampData createPropDataObj(
            TProp prop,
            Algorithm c14n,
            TimeStampTokenRes tsTknRes,
            PropertiesDataGenerationContext ctx);
}
