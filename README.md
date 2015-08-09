<p align='right'><img src='https://xades4j.googlecode.com/svn/wiki/logo-02.png' /></p>
## The Project ##
The _XAdES4j_ library is an high-level, configurable and extensible Java implementation of XML Advanced Electronic Signatures (XAdES 1.3.2 and 1.4.1). It enables producing, verifying and extending signatures in the main XAdES forms: XAdES-BES, XAdES-EPES, XAdES-T and XAdES-C. Also, extended forms are supported through the enrichment of an existing signature.

The API provides an high level of abstraction, handling all the structural details of XAdES. The library relies on Apache XML Security for the core XML-DSIG processing and uses Guice to assemble the different configurable components.

There are multiple implementations of XML-DSIG, namely the one bundled with the Java platform and the one in Apache XML Security. However, Java doesn't have support for XAdES and solid/complete/public implementations are hard to find. The motivation for this project emerges directly from those facts.

For an overview of the library's architecture and implementation you can watch the [XAdES4j Prezi](http://prezi.com/06vyxbgohncv/xades4j-en/).
If you can't find the information you need on the wiki and/or javadocs please refer to the tests in the source code, which illustrate all the features. Also, feel free to give some feedback, as it will be useful for further improvements.

_XAdES4j_ started in 2009/10 as the final project of my Master's degree on Computer Engineering at [Instituto Superior de Engenharia de Lisboa](http://www.isel.pt) but it now is a personal project that will be improved overtime.

## Q & A ##

Use the _xades4j_ tag on [Stack Overflow](http://stackoverflow.com/questions/tagged/xades4j). I'll be following the tag regularly.

## News ##

**2014-10-05** - Version 1.3.2 has been released [[maven](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.googlecode.xades4j%22) / [download](https://drive.google.com/#folders/0B8VrIuiaQ0atTjlMZmNKX3hRdlk) /  [change log](https://code.google.com/p/xades4j/wiki/ChangeLog#1.3.2)]. This release includes an important bug fix.

2014-09-29 - A new project dedicated to [interop tests](https://code.google.com/p/xades4j/source/checkout?repo=interop) has been added.

2014-09-12 - The main Git repository had to be reset in order to import the old SVN commit history. Sorry about the inconvenience.

2014-06-23 - XAdES4j is now available on Maven central repository under the group [com.googlecode.xades4j](http://search.maven.org/#search%7Cga%7C1%7Ccom.googlecode.xades4j)

2014-06-11 - Now using Maven and Git.

2014-04-12 - Version 1.3.1 has been released [[download](https://drive.google.com/folderview?id=0B8VrIuiaQ0atRTJmVm45cU9xUFk) / [docs](http://xades4j.googlecode.com/svn/release/1.3.1/javadoc/index.html) / [change log](https://code.google.com/p/xades4j/wiki/ChangeLog#1.3.1)]. This release includes the pending minor/non-breaking updates before starting new developments.