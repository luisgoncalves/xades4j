<p align='right'><img src='https://github.com/luisgoncalves/xades4j/blob/gh-pages/images/logo-02.png' /></p>

![Build Status](https://github.com/luisgoncalves/xades4j/workflows/Build/badge.svg)

_XAdES4j_ is a high-level, configurable and extensible Java implementation of XML Advanced Electronic Signatures (XAdES 1.3.2 and 1.4.1). It enables producing, verifying and extending signatures in the main XAdES forms: XAdES-BES, XAdES-EPES, XAdES-T and XAdES-C. Also, extended forms are supported through the enrichment of an existing signature.

The API provides a high level of abstraction, handling all the structural details of XAdES.
The library relies on Apache XML Security for the core XML-DSIG processing
and uses Guice to assemble the different configurable components.

# Package

The library is available on [Maven](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.googlecode.xades4j%22).

```
<dependency>
  <groupId>com.googlecode.xades4j</groupId>
  <artifactId>xades4j</artifactId>
  <version>{version}</version>
</dependency>
```

# Example

```java
Document doc = /* parse XML document */;
// Define the signing key/certificate
KeyingDataProvider kp = FileSystemKeyStoreKeyingDataProvider
        .builder(/* key store location and type */)
        .build();
// Define the signed object
DataObjectDesc obj = new DataObjectReference("")
        .withTransform(new EnvelopedSignatureTransform())
        .withDataObjectFormat(new DataObjectFormatProperty("text/xml"));
// Create the signature
XadesSigner signer = new XadesBesSigningProfile(kp).newSigner();
signer.sign(new SignedDataObjects(obj), doc.getDocumentElement());
```

# Docs and Q&A

- General usage documentation can be found on the project's [wiki](https://github.com/luisgoncalves/xades4j/wiki).
- Javadocs for the latest version can be found [here](http://luisgoncalves.github.io/xades4j/javadocs/2.4.0).
- Unit tests in the source code illustrate all the features.
- Overview of the architecture and implementation on the [XAdES4j Prezi](http://prezi.com/06vyxbgohncv/xades4j-en/).
- `xades4j` tag on [Stack Overflow](http://stackoverflow.com/questions/tagged/xades4j).

----

If _XAdES4j_ has been useful to you, consider supporting it!

<a href="https://www.buymeacoffee.com/luisgoncalves" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" width="170px"></a>
