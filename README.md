<p align='right'><img src='https://github.com/luisgoncalves/xades4j/blob/gh-pages/images/logo-02.png' /></p>

[![Build Status](https://travis-ci.org/luisgoncalves/xades4j.svg?branch=master)](https://travis-ci.org/luisgoncalves/xades4j)

_XAdES4j_ is an high-level, configurable and extensible Java implementation of XML Advanced Electronic Signatures (XAdES 1.3.2 and 1.4.1). It enables producing, verifying and extending signatures in the main XAdES forms: XAdES-BES, XAdES-EPES, XAdES-T and XAdES-C. Also, extended forms are supported through the enrichment of an existing signature.

The API provides an high level of abstraction, handling all the structural details of XAdES. The library relies on Apache XML Security for the core XML-DSIG processing and uses Guice to assemble the different configurable components.

There are multiple implementations of XML-DSIG, namely the one bundled with the Java platform and the one in Apache XML Security. However, Java doesn't have support for XAdES and solid/complete/public implementations are hard to find. The motivation for this project emerges directly from those facts.

# Package

The library is available on [Maven](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.googlecode.xades4j%22) (the current release is still using the google code group).

```
<dependency>
  <groupId>com.googlecode.xades4j</groupId>
  <artifactId>xades4j</artifactId>
  <version>1.3.2</version>
</dependency>
```

# Docs

General usage documentation can be found on the project's [wiki](https://github.com/luisgoncalves/xades4j/wiki). Javadocs for the latest version can be found [here](http://luisgoncalves.github.io/xades4j/javadocs/1.4.0/reference/packages.html). 

If you can't find the information you need on the wiki and/or javadocs please refer to the tests in the source code, which illustrate all the features. Also, feel free to give some feedback, as it will be useful for further improvements.

For an overview of the library's architecture and implementation you can watch the [XAdES4j Prezi](http://prezi.com/06vyxbgohncv/xades4j-en/).

# Q & A

Use the _xades4j_ tag on [Stack Overflow](http://stackoverflow.com/questions/tagged/xades4j).
