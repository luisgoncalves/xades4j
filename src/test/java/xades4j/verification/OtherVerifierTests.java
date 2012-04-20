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

import xades4j.utils.BuiltIn;
import com.google.inject.Inject;
import org.junit.Before;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.data.SigningTimeData;
import org.junit.Test;

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
 *
 * @author Luís
 */
public class OtherVerifierTests extends VerifierTestBase
{
    XadesVerificationProfile mySigsVerificationProfile;

    @Before
    public void initialize()
    {
        mySigsVerificationProfile = new XadesVerificationProfile(VerifierTestBase.validationProviderMySigs);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testVerifyBESCustomPropVer() throws Exception
    {
        System.out.println("verifyBESCustomPropVer");
        mySigsVerificationProfile.withQualifyingPropertyVerifier(SigningTimeData.class, new QualifyingPropertyVerifier<SigningTimeData>()
        {

            @Override
            public QualifyingProperty verify(
                    SigningTimeData propData,
                    QualifyingPropertyVerificationContext ctx) throws InvalidPropertyException
            {
                throw new UnsupportedOperationException("Yeah!");
            }
        });
        verifySignature("document.signed.bes.xml", mySigsVerificationProfile);
    }

    @Test(expected = SigningTimeVerificationException.class)
    public void testCustomVerifierCanUseBuiltInVerifier() throws Exception
    {
        System.out.println("customVerifierCanUseBuiltInVerifier");
        mySigsVerificationProfile.withQualifyingPropertyVerifier(
                SigningTimeData.class,
                SigningTimeVerifierThatDependsOnBuiltInVerifier.class);
        verifySignature("document.signed.bes.xml", mySigsVerificationProfile);
    }
}
