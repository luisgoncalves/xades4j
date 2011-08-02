The default marshal and unmarshal processes use JAXB classes generated from the XAdES schema using the XJC compiler:

	* xjc -episode sun-jaxb.episode XAdESv141.xsd -b bindings.xjb

The schema for UnsignedSignatureProperties was adapted to better fit to JAXB:

	* <choice maxOccurs = "unbounded"> was replaced by a <sequence>
	* Each child element has minOccurs = "0" and maxOccurs = "1" or maxOccurs = "unbounded", depending on the property

The original schema version allows any order on the elements but doesn't validate the number of occurences of each element. With this adjustment the order is restricted, but the number of occurences is checked. The only difference is that the "new schema" allows the element to be empty, but this is controlled by the library. JAXB wouldn't check this in the previous version, anyway.

This results in a better JAXB class (separate properties instead of a single getXXXOrYYYOrZZZ method). Furthermore, after some tests the ordering appears to only be considered by JAXB to marshal the properties. When unmarshalling, the bindings are applied independently of the order. To sum up, the adjustment has no impact on signature validation but makes the classes far easier to use (and also does occurences check).