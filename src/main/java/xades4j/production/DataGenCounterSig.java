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
package xades4j.production;

import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.QualifyingProperty;
import xades4j.XAdES4jException;
import xades4j.properties.data.GenericDOMData;
import xades4j.properties.data.PropertyDataObject;
import xades4j.utils.DOMHelper;

/**
 *
 * @author Luís
 */
class DataGenCounterSig implements PropertyDataObjectGenerator<CounterSignatureProperty>
{
    /*
     * XAdES section 7.2.4.2:
     * "The content of this property is a XMLDSIG or XAdES signature whose ds:SignedInfo
     * MUST contain one ds:Reference element referencing the ds:SignatureValue element
     * of the embedding and countersigned XAdES signature. The content of the ds:DigestValue
     * in the aforementioned ds:Reference element of the countersignature MUST be the
     * base-64 encoded digest of the complete (and canonicalized) ds:SignatureValue
     * element (i.e. including the starting and closing tags) of the embedding and
     * countersigned XAdES signature."
     */

    /* The ds:Reference element described above can be obtained with the default
     * XML-DSIG behaviour. We just need to reference the ds:SignatureValue element.
     */
    @Override
    public PropertyDataObject generatePropertyData(
            CounterSignatureProperty prop,
            PropertiesDataGenerationContext ctx) throws PropertyDataGenerationException
    {
        // The element has to be in the document tree for the references to be
        // resolved. UGLY WORKAROUND.
        Element qPs = DOMHelper.getFirstDescendant(ctx.getTargetXmlSignature().getElement(),
                QualifyingProperty.XADES_XMLNS, QualifyingProperty.QUALIFYING_PROPS_TAG);

        // Create the CounterSignature property element.
        Element counterSigElem = ctx.createElementInSignatureDoc(
                "CounterSignature",
                qPs.getPrefix(),
                QualifyingProperty.XADES_XMLNS);

        qPs.appendChild(counterSigElem);

        try
        {
            // Rerence to the ds:SignatureValue element. This assumes that the
            // QualifyingProperties are in the signature's document and that the
            // SignatureValue element has an Id.
            Element sigValueElem = DOMHelper.getFirstDescendant(
                    ctx.getTargetXmlSignature().getElement(),
                    Constants.SignatureSpecNS, Constants._TAG_SIGNATUREVALUE);
            String sigValueId = sigValueElem.getAttribute(Constants._ATT_ID);
            DataObjectReference sigValueRef = new DataObjectReference('#' + sigValueId);

            XadesSigner counterSigner = prop.getCounterSigSigner();
            if (null == counterSigner)
                throw new PropertyDataGenerationException(prop, "signer not specified");

            try
            {
                counterSigner.sign(
                        new SignedDataObjects().withSignedDataObject(sigValueRef),
                        counterSigElem);
            } catch (XAdES4jException ex)
            {
                throw new PropertyDataGenerationException(prop, "cannot apply counter signature", ex);
            }
        } finally
        {
            qPs.removeChild(counterSigElem);
        }

        return new GenericDOMData(counterSigElem);
    }
}
