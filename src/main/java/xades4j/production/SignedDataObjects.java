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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.AllDataObjsTimeStampProperty;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.OtherSignedDataObjectProperty;
import xades4j.properties.OtherUnsignedDataObjectProperty;
import xades4j.properties.PropertyTargetException;
import xades4j.properties.SignedDataObjectProperty;
import xades4j.properties.UnsignedDataObjectProperty;
import xades4j.utils.PropertiesSet;
import org.apache.xml.security.utils.resolver.ResourceResolver;

/**
 * Represents a set of data objects to be signed. Besides the data objects themselves,
 * this class can be used to specify:
 * <ul>
 *  <li>Properties that apply to ALL the signed data objects</li>
 *  <li>A base URI for the data object references</li>
 *  <li>{@link ResourceResolver}s to be used when processing the current set of
 *      data objects, in addition to the globally registered resolvers
 *  </li>
 * </ul>
 *
 * A set of objects to be signed. Properties that apply to ALL the signed data
 * objects can be specified via this class. This class checks for duplicate
 * data object descriptions (not allowed).
 *
 * @see DataObjectDesc
 * @see DataObjectReference
 * @see EnvelopedXmlObject
 *
 * @author Luís
 */
public final class SignedDataObjects
{

    private final List<DataObjectDesc> dataObjs;
    private String baseUriForRelativeReferences;
    private boolean hasNullURIReference;
    private final List<ResourceResolver> resourceResolvers;

    private final PropertiesSet<SignedDataObjectProperty> signedDataObjsProperties;
    private final PropertiesSet<UnsignedDataObjectProperty> unsignedDataObjsProperties;

    /**
     * Creates an empty container.
     */
    public SignedDataObjects()
    {
        this.dataObjs = new ArrayList<DataObjectDesc>();
        this.baseUriForRelativeReferences = null;
        this.hasNullURIReference = false;
        this.resourceResolvers = new ArrayList<ResourceResolver>(0);

        this.signedDataObjsProperties = new PropertiesSet<SignedDataObjectProperty>(0);
        this.unsignedDataObjsProperties = new PropertiesSet<UnsignedDataObjectProperty>(0);
    }

    /**
     * Creates a container with the given data objects.
     * @param dataObjs the signed data objects
     * @throws NullPointerException if {@code dataObjs} or any of the objects is null
     */
    public SignedDataObjects(Iterable<DataObjectDesc> dataObjs)
    {
        this();
        this.withSignedDataObjects(dataObjs);
    }

    /**
     * Creates a container with the given data objects.
     * @param dataObjs the signed data objects
     * @throws NullPointerException if {@code dataObjs} or any of the objects is null
     */
    public SignedDataObjects(DataObjectDesc... dataObjs)
    {
        this();
        for (int i = 0; i < dataObjs.length; i++)
        {
            this.withSignedDataObject(dataObjs[i]);

        }
    }

    /**************************************************************************/
    /**
     * Sets the base URI for <b>all/b> the relative references. Fragment references
     * (starting with '#') are not afected.
     * @param baseUri the references' base uri
     * @return the current instance
     */
    public SignedDataObjects withBaseUri(String baseUri)
    {
        this.baseUriForRelativeReferences = baseUri;
        return this;
    }

    String getBaseUri()
    {
        return this.baseUriForRelativeReferences;
    }

    /**************************************************************************/
    /**
     * Adds a CommitmentType signed property shared among all data objects. The
     * resulting property in the XAdES signature will contain the {@code AllSignedDataObjects}
     * element.
     *
     * This method can be invoked multiple times with different properties since
     * the signer may express multiple commitments towards the data objects.
     *
     * @param commitment the CommitmentType property
     * @return the current instance
     *
     * @throws PropertyTargetException if the given property (instance) is already present
     * @throws NullPointerException if the given property is {@code null}
     */
    public SignedDataObjects withCommitmentType(
            AllDataObjsCommitmentTypeProperty commitment)
    {
        return addSignedDataObjProp(commitment);
    }

    /**
     * Adds a AllDataObjectsTimeStamp signed property applied to all data objects.
     * This method can be invoked multiple times since multiple times-stamps can
     * be present.
     *
     * @return the current instance
     *
     */
    public SignedDataObjects withDataObjectsTimeStamp()
    {
        return addSignedDataObjProp(new AllDataObjsTimeStampProperty());
    }

    /**
     * Adds a custom global signed data object property. The purpose of this
     * method is extensibility.
     * <p>
     * Each custom property needs a corresponding {@link xades4j.production.PropertyDataObjectGenerator}
     * which can be supplied through {@link xades4j.production.XadesSigningProfile}.
     *
     * @param otherSignedDataObjProp the custom property
     * @return the current instance
     *
     * @throws NullPointerException if {@code otherSignedDataObjProp} is {@code null}
     * @throws PropertyTargetException if the property is already present
     * @throws IllegalArgumentException if the property if not properly annotated
     */
    public SignedDataObjects withOtherDataObjectProperty(
            OtherSignedDataObjectProperty otherSignedDataObjProp)
    {
        return addSignedDataObjProp(otherSignedDataObjProp);
    }

    /**
     * @throws PropertyTargetException if the given property (instance) is already present
     * @throws NullPointerException if the given property is {@code null}
     */
    private SignedDataObjects addSignedDataObjProp(SignedDataObjectProperty prop)
    {
        this.signedDataObjsProperties.add(prop);
        return this;
    }

    /**
     * Adds a custom global unsigned data object property. The purpose of this
     * method is extensibility.
     * <p>
     * Each custom property needs a corresponding {@link xades4j.production.PropertyDataObjectGenerator}
     * which can be supplied through {@link xades4j.production.XadesSigningProfile}.
     *
     * @param otherUnsignedDataObjProp the custom property
     * @return the current instance
     * 
     * @throws NullPointerException if {@code otherUnsignedDataObjProp} is {@code null}
     * @throws PropertyTargetException if the property is already present
     * @throws IllegalArgumentException if the property if not properly annotated
     */
    public SignedDataObjects withOtherDataObjectProperty(
            OtherUnsignedDataObjectProperty otherUnsignedDataObjProp)
    {
        this.unsignedDataObjsProperties.add(otherUnsignedDataObjProp);
        return this;
    }

    Collection<SignedDataObjectProperty> getSignedDataObjsProperties()
    {
        return this.signedDataObjsProperties.getProperties();
    }

    Collection<UnsignedDataObjectProperty> getUnsignedDataObjsProperties()
    {
        return this.unsignedDataObjsProperties.getProperties();
    }

    /**************************************************************************/
    /**
     * Adds a set of data objects to be signed. Each data object description will
     * result in a {@code ds:Reference} element in the final XAdES signature.
     *
     * @param objsInfo the data objects
     * @return the current instance
     *
     * @throws NullPointerException if {@code objsInfo} or any of the objects is {@code null}
     * @throws IllegalStateException if any of the data object descriptions is already present
     */
    public SignedDataObjects withSignedDataObjects(
            Iterable<DataObjectDesc> objsInfo)
    {
        for (DataObjectDesc obj : objsInfo)
        {
            this.withSignedDataObject(obj);
        }
        return this;
    }

    /**
     * Adds a data object to be signed. Each data object description will result
     * in a {@code ds:Reference} element in the final XAdES signature.
     *
     * @param object the data object
     * @return the current instance
     *
     * @throws NullPointerException if {@code object} is {@code null}
     * @throws IllegalStateException if the data object description is already present
     */
    public SignedDataObjects withSignedDataObject(DataObjectDesc object)
    {
        if (null == object)
        {
            throw new NullPointerException("Signed object description cannot be null");
        }

        if(this.dataObjs.contains(object))
        {
            throw new IllegalStateException("Data object description was already added");
        }

        if (object instanceof AnonymousDataObjectReference)
        {
            if (this.hasNullURIReference)
            {
                throw new IllegalStateException("An AnonymousDataObjectReference is already present");
            }
            this.hasNullURIReference = true;
        }

        this.dataObjs.add(object);
        return this;
    }

    boolean isEmpty()
    {
        return this.dataObjs.isEmpty();
    }

    Collection<DataObjectDesc> getDataObjectsDescs()
    {
        return this.dataObjs;
    }

    /**************************************************************************/
    /**
     * Registers a {@link ResourceResolver} to be used when signing the current
     * set of data objects. The resolvers are considered in the same order they
     * are added and have priority over the globally registered resolvers.
     *
     * @param resolver the resolver
     * @return the current instance
     *
     * @throws NullPointerException if {@code resolver} is {@code null}
     */
    public SignedDataObjects withResourceResolver(ResourceResolver resolver)
    {
        if (null == resolver)
        {
            throw new NullPointerException("Resolver cannot be null");
        }
        
        this.resourceResolvers.add(resolver);
        return this;
    }

    List<ResourceResolver> getResourceResolvers()
    {
        return resourceResolvers;
    }
}
