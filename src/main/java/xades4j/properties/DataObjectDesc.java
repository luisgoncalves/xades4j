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
package xades4j.properties;

import java.util.Collection;
import xades4j.algorithms.Algorithm;
import xades4j.production.DataObjectReference;
import xades4j.production.EnvelopedXmlObject;
import xades4j.utils.CollectionUtils;
import xades4j.utils.PropertiesSet;

// This class is in this package instead of "xades4j" because it is tightly coupled
// with DataObjectProperty. It needs to invoke the private-package appliesTo method.

/**
 * Base class for descriptions of the signed data objects. Each data object can
 * be characterized by a set of transforms and a set of properties, specified
 * via a fluent interface.
 * class.
 *
 * @see EnvelopedXmlObject
 * @see DataObjectReference
 *
 * @author Luís
 */
public abstract class DataObjectDesc
{
    private Collection<Algorithm> transforms;
    private final PropertiesSet<SignedDataObjectProperty> signedDataObjProps;
    private final PropertiesSet<UnsignedDataObjectProperty> unsignedDataObjProps;

    protected DataObjectDesc()
    {
        signedDataObjProps = new PropertiesSet<SignedDataObjectProperty>(2);
        unsignedDataObjProps = new PropertiesSet<UnsignedDataObjectProperty>(0);
    }

    /**
     * Registers a transform to be applied to the data object at the signature
     * generation. Each transform will result in a {@code ds:Transform} element
     * within the {@code ds:Reference} resulting from the current data object
     * description.
     *
     * @param transf the transform to be applied
     * @return the current instance
     *
     * @throws NullPointerException if {@code transf} is {@code null}
     * @throws IllegalStateException if the transform (instance) is already
     *                                  present
     */
    public final DataObjectDesc withTransform(Algorithm transf)
    {
        if (null == transf)
            throw new NullPointerException("Transform cannot be null");

        transforms = CollectionUtils.newIfNull(transforms, 2);
        if (!transforms.add(transf))
            throw new IllegalStateException("Transform was already added");

        return this;
    }

    public Collection<Algorithm> getTransforms()
    {
        return CollectionUtils.emptyIfNull(transforms);
    }

    /**************************************************************************/
    /**
     * Adds a DataObjectFormat signed property to the current data object description.
     * The {@code ObjectReference} of the resulting property in the XAdES signature
     * will refer the {@code ds:Reference} resulting from the current data object
     * description.
     *
     * This property can only be defined once.
     *
     * @param format DataObjectFormat property
     * @return the current instance
     *
     * @throws NullPointerException if {@code format} is {@code null}
     * @throws PropertyTargetException if a DataObjectFormat property is already
     *                                  present or {@code format} is already applied
     *                                  to another data object
     */
    public final DataObjectDesc withDataObjectFormat(
            DataObjectFormatProperty format)
    {
        this.signedDataObjProps.put(format);
        applyProperty(format, signedDataObjProps);
        return this;
    }

    /**
     * Adds a CommitmentType signed property to the current data object description.
     * The {@code ObjectReference} of the resulting property in the XAdES signature
     * will refer the {@code ds:Reference} resulting from the current data object
     * description.
     *
     * This method can be invoked multiple times with different properties since
     * the signer may express multiple commitments towards the current data object.
     * Furthermore, the same property instance can be added to different data object
     * descriptions, since the signed can express the same commitment towards them.
     *
     * @param commitment CommitmentType property
     * @return the current instance
     *
     * @throws NullPointerException if {@code commitment} is {@code null}
     * @throws PropertyTargetException if the property (instance) is already present
     */
    public final DataObjectDesc withCommitmentType(
            CommitmentTypeProperty commitment)
    {
        return addSignedDataObjProp(commitment);
    }

    /**
     * Add a IndividualDataObjectsTimeStamp signed property to the current data
     * object description. The {@code Include} list of the resulting property in
     * the XAdES signature will refer the {@code ds:Reference} resulting from the
     * current data object description.
     *
     * This method can be invoked multiple times with different properties since
     * multiple instances of the property may exist in the signature and be applied
     * to the current data object. Furthermore, the same property instance can be
     * added to different data object descriptions since a single time-stamp may
     * cover multiple data objects.
     *
     * @param timestamp the IndividualDataObjectsTimeStamp property
     * @return the current instance
     *
     * @throws NullPointerException if {@code timestamp} is {@code null}
     * @throws PropertyTargetException if the property (instance) is already present
     */
    public final DataObjectDesc withDataObjectTimeStamp(
            IndividualDataObjsTimeStampProperty timestamp)
    {
        return addSignedDataObjProp(timestamp);
    }

    /**
     * Add a new IndividualDataObjectsTimeStamp signed property to the current data
     * object description. This method is a shorcut for {@link DataObjectDesc#withDataObjectTimeStamp(xades4j.properties.IndividualDataObjsTimeStampProperty)}
     * that can be used when the time-stamp is not applied to other data objects.
     * @return the current instance
     */
    public final DataObjectDesc withDataObjectTimeStamp()
    {
        return addSignedDataObjProp(new IndividualDataObjsTimeStampProperty());
    }

    /**
     * Adds a custom signed property to the current data object description. The
     * purpose of this method is extensibility.
     * <p>
     * Each custom property needs a corresponding {@link xades4j.production.PropertyDataObjectGenerator}
     * which can be supplied through {@link xades4j.production.XadesSigningProfile}.
     * 
     * @param otherSignedDataObjProp the custom property
     * @return the current instance
     * @throws NullPointerException if {@code otherSignedDataObjProp} is {@code null}
     * @throws PropertyTargetException if the property is already present
     *                      or is already applied to another data object (if it can't)
     * @throws IllegalArgumentException if the property is not properly annotated
     */
    public final DataObjectDesc withOtherDataObjectProperty(
            OtherSignedDataObjectProperty otherSignedDataObjProp)
    {
        return addSignedDataObjProp(otherSignedDataObjProp);
    }

    /**
     * Use ONLY with properties that can be applied to multiple data objects.
     *
     * @throws NullPointerException if the property is {@code null}
     * @throws PropertyTargetException if the given property (instance) is already
     *                                  present
     */
    private DataObjectDesc addSignedDataObjProp(SignedDataObjectProperty prop)
    {
        addDataObjProp(signedDataObjProps, prop);
        return this;
    }
    /**/

    /**
     * Adds a custom unsigned property to the current data object description. The
     * purpose of this method is extensibility.
     * <p>
     * Each custom property needs a corresponding {@link xades4j.production.PropertyDataObjectGenerator}
     * which can be supplied through {@link xades4j.production.XadesSigningProfile}.
     *
     * @param otherUnsignedDataObjProp the custom property
     * @return the current instance
     *
     * @throws NullPointerException if {@code otherUnsignedProp} is {@code null}
     * @throws PropertyTargetException if the property is already present
     *                          or is already applied to another data object (if it can't)
     * @throws IllegalArgumentException if the property is not properly annotated
     */
    public final DataObjectDesc withOtherDataObjectProperty(
            OtherUnsignedDataObjectProperty otherUnsignedDataObjProp)
    {
        addDataObjProp(unsignedDataObjProps, otherUnsignedDataObjProp);
        return this;
    }
    /**/

    /**
     * Use ONLY with properties that can be applied to multiple data objects.
     * 
     * @throws NullPointerException if the property is {@code null}
     * @throws PropertyTargetException if the given property (instance)
     *                                  is already present
     */
    private <TProp extends DataObjectProperty> void addDataObjProp(
            PropertiesSet<TProp> bag, TProp prop)
    {
        bag.add(prop); // Throws exception if the property is repeated.
        applyProperty(prop, bag);
    }

    /**
     * Must be invoked after adding {@code prop} to {@code bag}. Even if the property
     * is not present in the current data object description it may not be possible
     * to apply it because it is already applie to other data object(s). In this
     * case, the property is removed, leaving the bag unchanged.
     *
     * @throws PropertyTargetException if the property cannot be applied to more
     *                                  data objects
     */
    private <TProp extends DataObjectProperty> void applyProperty(
            TProp prop,
            PropertiesSet<TProp> bag)
    {
        try
        {
            prop.appliesTo(this);
        } catch (PropertyTargetException ex)
        {
            // Property cannot be applied to more data objects
            bag.remove(prop);
            throw ex;
        }
    }

    /**************************************************************************/
    public boolean hasProperties()
    {
        return !signedDataObjProps.isEmpty() || !unsignedDataObjProps.isEmpty();
    }

    public Collection<SignedDataObjectProperty> getSignedDataObjProps()
    {
        return signedDataObjProps.getProperties();
    }

    public Collection<UnsignedDataObjectProperty> getUnsignedDataObjProps()
    {
        return unsignedDataObjProps.getProperties();
    }
}
