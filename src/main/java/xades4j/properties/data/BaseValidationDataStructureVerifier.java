package xades4j.properties.data;

import java.util.Collection;

public class BaseValidationDataStructureVerifier implements
        PropertyDataObjectStructureVerifier
{
    private final String propName;

    BaseValidationDataStructureVerifier(String propName)
    {
        this.propName = propName;
    }

    @Override
    public void verifyStructure(PropertyDataObject propData)
            throws PropertyDataStructureException
    {
        BaseValidationDataData validationData = (BaseValidationDataData) propData;

        Collection<byte[]> certData = validationData.getCertificateData();
        Collection<byte[]> revocData = validationData.getCRLData();
        if ((certData == null || certData.isEmpty()) && (revocData == null || revocData.isEmpty()))
            throw new PropertyDataStructureException(
                    "Neither certificate nor revocation data provided", propName);

        for (byte[] d : certData)
        {
            if (d == null)
                throw new PropertyDataStructureException("null cert data", propName);
        }
        for (byte[] d : revocData)
        {
            if (d == null)
                throw new PropertyDataStructureException("null revoc data", propName);
        }
    }
}
