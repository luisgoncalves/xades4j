/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2019 Luis Goncalves.
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

import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author luis
 */
class XAdESFormCheckerTest
{
    @Test
    void checkFormThrowsIfMinimumPropertiesAreNotPresent() throws InvalidXAdESFormException
    {
        assertThrows(InvalidXAdESFormException.class, () -> XAdESFormChecker.checkForm(new ArrayList<PropertyInfo>(0), true));
    }

    @Test
    void identifiesXadesBesWhenSigningCertificateIsNotPresentAndNotRequired() throws InvalidXAdESFormException
    {
        XAdESForm form = XAdESFormChecker.checkForm(new ArrayList<PropertyInfo>(0), false);

        assertEquals(XAdESForm.BES, form);
    }
}
