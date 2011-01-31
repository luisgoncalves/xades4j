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
package xades4j.verification;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import xades4j.properties.ArchiveTimeStampProperty;
import xades4j.properties.CertificateValuesProperty;
import xades4j.properties.CompleteCertificateRefsProperty;
import xades4j.properties.CompleteRevocationRefsProperty;
import xades4j.properties.RevocationValuesProperty;
import xades4j.properties.SigAndRefsTimeStampProperty;
import xades4j.properties.SignaturePolicyBase;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.SigningCertificateProperty;

/**
 *
 * @author Luís
 */
class XAdESFormChecker
{
    private XAdESFormChecker()
    {
    }

    static XAdESForm checkForm(Collection<PropertyInfo> props) throws InvalidXAdESFormException
    {
        Set<String> availablePropsNames = new HashSet<String>();
        for (PropertyInfo propInfo : props)
        {
            availablePropsNames.add(propInfo.getProperty().getName());
        }

        XAdESFormDesc formDesc = XADES_C_DESC;
        do
        {
            if (formDesc.check(availablePropsNames))
                return formDesc.getForm();
        } while ((formDesc = formDesc.getPrevious()) != null);

        // XAdES G.2.2.1: "The verification process should assess whether the signature
        // is a XAdES signature and if so, identify the specific form, by inspecting
        // the different qualifying properties present. The verification process
        // should not accept as XAdES signature any combination not aligned with
        // those established in the normative part of the present document or the
        // extended forms defined in the informative annex B."

        throw new InvalidXAdESFormException("Signature doesn't follow any of the XAdES forms");

    }
    static final XAdESFormDesc XADES_BES_DESC = new XAdES_BES_Desc(),
            XADES_EPES_DESC = new XAdES_EPES_Desc(),
            XADES_T_DESC = new XAdES_T_Desc(),
            XADES_C_DESC = new XAdES_C_Desc(),
            XADES_X_DESC = new XAdES_X_Desc(),
            XADES_X_L_DESC = new XAdES_X_L_Desc();

    /**************************************************************************/
    /**/
    private static abstract class XAdESFormDesc
    {
        private XAdESFormDesc[] baseForms;

        // Ordered from the top format to the lower format.
        public XAdESFormDesc(XAdESFormDesc... baseForms)
        {
            this.baseForms = baseForms;
        }

        boolean check(Set<String> availablePropsNames) throws InvalidXAdESFormException
        {
            // Check the properties for the current form.
            if (!checkProps(availablePropsNames))
                return false;

            // If the properties of the current form are available, at least one
            // of the base forms has to be well-formed.

            if (baseForms.length == 0)
                return true;

            for (int i = 0; i < baseForms.length; i++)
            {
                if (baseForms[i].check(availablePropsNames))
                    return true;
            }

            throw new InvalidXAdESFormException(String.format("Required base forms for %s are not present", this.getForm().toString()));
        }

        XAdESFormDesc getPrevious()
        {
            return baseForms[0];
        }

        /**
         * Checks the properties for the current form. Should throw an exception
         * when the form is malformed.
         * @return true if the format specific properties are available; false otherwise
         */
        protected abstract boolean checkProps(Set<String> availablePropsNames) throws InvalidXAdESFormException;

        abstract XAdESForm getForm();
    }
    /**/

    static class XAdES_BES_Desc extends XAdESFormDesc
    {
        @Override
        protected boolean checkProps(Set<String> availablePropsNames)
        {
            return availablePropsNames.contains(SigningCertificateProperty.PROP_NAME);
        }

        @Override
        XAdESForm getForm()
        {
            return XAdESForm.BES;
        }
    }

    /**/
    static class XAdES_EPES_Desc extends XAdESFormDesc
    {
        public XAdES_EPES_Desc()
        {
            super(XADES_BES_DESC);
        }

        @Override
        protected boolean checkProps(Set<String> availablePropsNames)
        {
            return availablePropsNames.contains(SignaturePolicyBase.PROP_NAME);
        }

        @Override
        XAdESForm getForm()
        {
            return XAdESForm.EPES;
        }
    }

    /**/
    static class XAdES_T_Desc extends XAdESFormDesc
    {
        public XAdES_T_Desc()
        {
            super(XADES_EPES_DESC, XADES_BES_DESC);
        }

        @Override
        protected boolean checkProps(Set<String> availablePropsNames)
        {
            return availablePropsNames.contains(SignatureTimeStampProperty.PROP_NAME);
        }

        @Override
        XAdESForm getForm()
        {
            return XAdESForm.T;
        }
    }

    /**/
    static class XAdES_C_Desc extends XAdESFormDesc
    {
        public XAdES_C_Desc()
        {
            super(XADES_T_DESC);
        }

        @Override
        protected boolean checkProps(Set<String> availablePropsNames) throws InvalidXAdESFormException
        {
            boolean hasCompCertRefs = availablePropsNames.contains(CompleteCertificateRefsProperty.PROP_NAME);
            boolean hasCompRevocRefs = availablePropsNames.contains(CompleteRevocationRefsProperty.PROP_NAME);
            boolean xor = hasCompCertRefs ^ hasCompRevocRefs;
            if (xor)
                throw new InvalidXAdESFormException(String.format(
                        "Both %s and %s have to be present in %s form",
                        CompleteCertificateRefsProperty.PROP_NAME,
                        CompleteRevocationRefsProperty.PROP_NAME,
                        this.getForm().toString()));

            // If has both props, it's C form.
            if (hasCompCertRefs)
                return true;

            // Can't have attr properties if the other 2 are not present.
            if (availablePropsNames.contains("AttributeCertificateRefs") || availablePropsNames.contains("AttributeRevocationRefs"))
                throw new InvalidXAdESFormException("Attr properties cannot be present without the base C form properties");

            return false;
        }

        @Override
        XAdESForm getForm()
        {
            return XAdESForm.C;
        }
    }

    /**/
    static class XAdES_X_Desc extends XAdESFormDesc
    {
        public XAdES_X_Desc()
        {
            super(XADES_C_DESC);
        }

        @Override
        protected boolean checkProps(Set<String> availablePropsNames) throws InvalidXAdESFormException
        {
            return availablePropsNames.contains(SigAndRefsTimeStampProperty.PROP_NAME) ||
                    availablePropsNames.contains("RefsOnlyTimeStamp");
        }

        @Override
        XAdESForm getForm()
        {
            return XAdESForm.X;
        }
    }

    /**/
    static class XAdES_X_L_Desc extends XAdESFormDesc
    {
        public XAdES_X_L_Desc()
        {
            super(XADES_X_DESC);
        }

        @Override
        protected boolean checkProps(Set<String> availablePropsNames) throws InvalidXAdESFormException
        {
            boolean hasCompCert = availablePropsNames.contains(CertificateValuesProperty.PROP_NAME);
            boolean hasCompRevoc = availablePropsNames.contains(RevocationValuesProperty.PROP_NAME);
            boolean xor = hasCompCert ^ hasCompRevoc;
            if (xor)
                throw new InvalidXAdESFormException(String.format(
                        "Both %s and %s have to be present in %s form",
                        "CertificateValues",
                        "RevocationValues",
                        this.getForm().toString()));

            return hasCompCert;
        }

        @Override
        XAdESForm getForm()
        {
            return XAdESForm.X_L;
        }
    }

    /**/
    static class XAdES_A_Desc extends XAdESFormDesc
    {
        public XAdES_A_Desc()
        {
            super(XADES_X_L_DESC);
        }

        @Override
        protected boolean checkProps(Set<String> availablePropsNames) throws InvalidXAdESFormException
        {
            return availablePropsNames.contains(ArchiveTimeStampProperty.PROP_NAME);
        }

        @Override
        XAdESForm getForm()
        {
            return XAdESForm.A;
        }
    }
}
