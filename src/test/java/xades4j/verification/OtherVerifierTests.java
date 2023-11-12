/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2012 Luis Goncalves.
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
package xades4j.verification;

import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.SigningTimeData;
import xades4j.utils.BuiltIn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SigningTimeVerifierThatDependsOnBuiltInVerifier implements QualifyingPropertyVerifier<SigningTimeData>
{
    private final QualifyingPropertyVerifier<SigningTimeData> builtInVerifier;

    @Inject
    public SigningTimeVerifierThatDependsOnBuiltInVerifier(
            @BuiltIn QualifyingPropertyVerifier<SigningTimeData> builtInVerifier)
    {
        this.builtInVerifier = builtInVerifier;
    }

    @Override
    public QualifyingProperty verify(SigningTimeData propData, QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
    {
        builtInVerifier.verify(propData, ctx);
        throw new SigningTimeVerificationException(null, null);
    }
}

/**
 * @author Luís
 */
class OtherVerifierTests extends VerifierTestBase
{
    XadesVerificationProfile mySigsVerificationProfile;

    @BeforeEach
    public void initialize()
    {
        mySigsVerificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs);
    }

    @Test
    void testVerifyBESCustomPropVer() throws Exception
    {
        mySigsVerificationProfile.withQualifyingPropertyVerifier(SigningTimeData.class, new QualifyingPropertyVerifier<SigningTimeData>()
        {

            @Override
            public QualifyingProperty verify(
                    SigningTimeData propData,
                    QualifyingPropertyVerificationContext ctx)
            {
                throw new UnsupportedOperationException("Yeah!");
            }
        });

        Exception e = assertThrows(UnsupportedOperationException.class, () -> {
            verifySignature("document.signed.bes.xml", mySigsVerificationProfile);
        });

        assertEquals("Yeah!", e.getMessage());
    }

    @Test
    void testCustomVerifierCanUseBuiltInVerifier() throws Exception
    {
        mySigsVerificationProfile.withQualifyingPropertyVerifier(
                SigningTimeData.class,
                SigningTimeVerifierThatDependsOnBuiltInVerifier.class);

        assertThrows(SigningTimeVerificationException.class, () -> {
            verifySignature("document.signed.bes.xml", mySigsVerificationProfile);
        });
    }

    @Test
    void testVerifyWithManifest() throws Exception
    {
        SignatureSpecificVerificationOptions options = new SignatureSpecificVerificationOptions()
                .followManifests(true);
        verifySignature("document.signed.bes.manifest.xml", mySigsVerificationProfile, options);
    }
}
