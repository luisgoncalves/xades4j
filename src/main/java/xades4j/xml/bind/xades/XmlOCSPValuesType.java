//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 in JDK 6 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2010.04.09 at 09:56:29 PM BST 
//


package xades4j.xml.bind.xades;

import java.util.ArrayList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for OCSPValuesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="OCSPValuesType"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="EncapsulatedOCSPValue" type="{http://uri.etsi.org/01903/v1.3.2#}EncapsulatedPKIDataType" maxOccurs="unbounded"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "OCSPValuesType", propOrder = {
    "encapsulatedOCSPValue"
})
public class XmlOCSPValuesType {

    @XmlElement(name = "EncapsulatedOCSPValue", required = true)
    protected List<XmlEncapsulatedPKIDataType> encapsulatedOCSPValue;

    /**
     * Gets the value of the encapsulatedOCSPValue property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the encapsulatedOCSPValue property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getEncapsulatedOCSPValue().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link XmlEncapsulatedPKIDataType }
     * 
     * 
     */
    public List<XmlEncapsulatedPKIDataType> getEncapsulatedOCSPValue() {
        if (encapsulatedOCSPValue == null) {
            encapsulatedOCSPValue = new ArrayList<>();
        }
        return this.encapsulatedOCSPValue;
    }

}
