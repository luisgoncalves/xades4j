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
/**
 * Low-level representation of the qualifying properties information and corresponing
 * structural verification. These types are intermediate representations (data objects)
 * of the properties between the XML tree and the high-level types.
 * <p>
 * The diference for the types in {@code xades4j.properties} is that data objects
 * contain all the data that is needed to create the final XML structure. For instance,
 * the high-level {@code SigningCertificate} contains a list of {@code X509Certificate}
 * while the corresponding data object contains a list of {@code CertRef} with the
 * certificate's digest and issuer/serial.
 * <p>
 * Data objects enable the clear separation of gathering the data needed for a property
 * and generating its actual XML structure (marshalling). Also, they allow the
 * separation between the unmarshalling and property verification.
 * <p>
 * Data objects are also the appropriate subject to structural verification, i.e.
 * checking if all the required fields are present, if needed collections aren't empty,
 * and so on. This has to be done after unmarshalling because the unmarshaller can
 * be replaced. Also, in signature production some properties have data supplied
 * by the user, which needs be validated. Data objects and the corresponding structure
 * verifiers are the central point for these checks.
 * <p>
 * The library provides a property data object and the corresponding strucutre
 * verifier for all the supported properties. In addition, there is a generic DOM
 * container (that is also supported by the default properties marshaller) and a
 * extension point for new property data objects (@link OtherPropertyData}.
 * <p>
 * The types on this package are not heavily documented because they are simple
 * data containers. No checks are made on the data objects themselves, as the
 * corresponding structure verifiers handle that task.
 * <p>
 * An important note is that <b>whenever a byte[] is used</b> to represent an octet stream
 * that is base-64 encoded in XAdES <b>it should NOT be encoded in base-64 in the property
 * data object</b>.
 */
package xades4j.properties.data;

