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
package xades4j.properties.data;

import xades4j.utils.DataGetterImpl;
import xades4j.utils.DataGetter;
import com.google.inject.Inject;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import xades4j.properties.AllDataObjsTimeStampProperty;
import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.SigningCertificateProperty;

/**
 *
 * @author Luís
 */
public class PropertiesDataObjectsStructureVerifier
{
    /**/
    private static final Map<Class<? extends PropertyDataObject>, PropertyDataObjectStructureVerifier> structureVerifiers;

    static
    {
        structureVerifiers = new HashMap<Class<? extends PropertyDataObject>, PropertyDataObjectStructureVerifier>(10);
        structureVerifiers.put(CommitmentTypeData.class,
                new CommitmentTypeDataStructureVerifier());

        structureVerifiers.put(DataObjectFormatData.class,
                new DataObjectFormatDataStructureVerifier());

        structureVerifiers.put(IndividualDataObjsTimeStampData.class,
                new IndividualDataObjsTimeStampDataStructureVerifier());

        structureVerifiers.put(AllDataObjsTimeStampData.class,
                new BaseXAdESTimeStampDataStructureVerifier(AllDataObjsTimeStampProperty.PROP_NAME));

        structureVerifiers.put(SignatureProdPlaceData.class,
                new SignatureProdPlaceDataStructureVerifier());

        structureVerifiers.put(SigningCertificateData.class,
                new BaseCertRefsDataStructureVerifier(SigningCertificateProperty.PROP_NAME));

        structureVerifiers.put(SigningTimeData.class,
                new SigningTimeDataStructureVerifier());

        structureVerifiers.put(SignerRoleData.class,
                new SignerRoleDataStructureVerifier());

        structureVerifiers.put(SignaturePolicyData.class,
                new SignaturePolicyDataStructureVerifier());

        structureVerifiers.put(SignatureTimeStampData.class,
                new BaseXAdESTimeStampDataStructureVerifier(SignatureTimeStampProperty.PROP_NAME));

        structureVerifiers.put(CompleteCertificateRefsData.class,
                new BaseCertRefsDataStructureVerifier(CompleteCertificateRefsProperty.PROP_NAME));

        structureVerifiers.put(CompleteRevocationRefsData.class,
                new CompleteRevocationRefsDataStructureVerifier());

        structureVerifiers.put(SigAndRefsTimeStampData.class,
                new BaseXAdESTimeStampDataStructureVerifier(SigAndRefsTimeStampProperty.PROP_NAME));

        structureVerifiers.put(CertificateValuesData.class,
                new BaseEncapsulatedPKIDataStructureVerifier(CertificateValuesProperty.PROP_NAME));

        structureVerifiers.put(RevocationValuesData.class,
                new BaseEncapsulatedPKIDataStructureVerifier(RevocationValuesProperty.PROP_NAME));

        structureVerifiers.put(ArchiveTimeStampData.class,
                new BaseXAdESTimeStampDataStructureVerifier(ArchiveTimeStampProperty.PROP_NAME));

        structureVerifiers.put(GenericDOMData.class,
                new GenericDOMDataStructureVerifier());
    }
    /**/
    /**/
    private final Set<CustomPropertiesDataObjsStructureVerifier> customGlobalVerifiers;

    @Inject
    public PropertiesDataObjectsStructureVerifier(
            Set<CustomPropertiesDataObjsStructureVerifier> customVerifiers)
    {
        this.customGlobalVerifiers = customVerifiers;
    }

    public void verifiyPropertiesDataStructure(
            SigAndDataObjsPropertiesData propsData) throws PropertyDataStructureException
    {
        verifiyPropertiesDataStructure(propsData.getSigProps());
        verifiyPropertiesDataStructure(propsData.getDataObjProps());
    }

    public void verifiyPropertiesDataStructure(
            Collection<PropertyDataObject> propsData) throws PropertyDataStructureException
    {
        for (PropertyDataObject propData : propsData)
        {
            getVerifier(propData).verifyStructure(propData);
        }

        if (customGlobalVerifiers.isEmpty())
            return;

        DataGetter<PropertyDataObject> dataGetter = new DataGetterImpl<PropertyDataObject>(propsData);

        for (CustomPropertiesDataObjsStructureVerifier customVer : customGlobalVerifiers)
        {
            customVer.verifiy(dataGetter);
        }
    }

    /**
     * Gets a structure verifier for the given property data object. If no verifier
     * is found in the map, the property data object's type is check for the appropriate
     * annotation.
     * 
     * The structure verifiers aren't configured through the profiles because a
     * structure verifier has a very tight relation with the corresponding data
     * object (when one is used, the other is necessarily used too). The property
     * verifiers are different because the developer may or may not want to support
     * a given property in a profile, even if the unmarshaller produces the corresponding
     * data objects.
     */
    private static PropertyDataObjectStructureVerifier getVerifier(
            PropertyDataObject propData) throws PropertyDataStructureException
    {
        PropertyDataObjectStructureVerifier v = structureVerifiers.get(propData.getClass());
        if (v != null)
            return v;

        PropDataStructVerifier verifierAnnot = propData.getClass().getAnnotation(PropDataStructVerifier.class);
        if (null == verifierAnnot || null == verifierAnnot.value())
            throw new PropertyDataStructureVerifierNotAvailableException(propData.getClass().getSimpleName());
        try
        {
            v = verifierAnnot.value().newInstance();
            structureVerifiers.put(propData.getClass(), v);
            return v;
        } catch (InstantiationException ex)
        {
        } catch (IllegalAccessException ex)
        {
        }
        throw new PropertyDataStructureException("cannot create data structure verifier", propData.getClass().getSimpleName());
    }
}
