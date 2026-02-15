---
layout: default
title: Home
---

<h1>Welcome</h1>

<b>libspf2</b> implements the Sender Policy Framework, a part of the
SPF/<a href="http://www.libsrs2.net/">SRS</a> protocol pair. libspf2 is
a library which allows email systems such as Sendmail, Postfix, Exim,
Zmailer and MS Exchange to check <a href="http://www.open-spf.org">SPF
records</a> and make sure that the email is authorized by the domain
name that it is coming from.  This prevents email forgery, commonly
used by spammers, scammers and email viruses/worms.

<h1>News</h1>

{% comment %}
<b>June 10th, 2013:</b>
libspf2 version 1.2.10 has beeen released, and is available <a
href="spf/libspf2-1.2.10.tar.gz">here</a>. This fixes IPv6-related
issues. An update is recommended.

<b>November 4th, 2008:</b>
libspf2 version 1.2.9 has beeen released, and is available <a
href="spf/libspf2-1.2.9.tar.gz">here</a>. This fixes aborts when
generating explanations for mails with a long envelope sender,
amongst other issues. An update is recommended.

<b>October 15th, 2008:</b>
After a long hiatus, new releases of libspf2! Development work from
a number of contributors has resulted in the release of versions up
to <a href="spf/libspf2-1.2.8.tar.gz">1.2.8</a>. It is recommended
that all users upgrade as soon as possible, since this release
fixes some significant bugs. This release also comes with new <a
href="docs/html/">doxygen documentation</a> which should make the
code easier to understand and cross-reference.

<b>If you were emailed an md5sum for libspf2-1.2.8, note that this
file has changed due to a bug in the release. If in doubt, please
reply to the email asking for a new checksum.</b>
{% endcomment %}

libspf2 is now a <b>fully thread safe SPF implementation</b>.
The latest release of libspf2 is available from the <a
href="download.html">download page</a>.
Developers should be using this as the reference for new SPF
applications. This release includes:

<ul>
<li>New server/request/response API</li>
<li>Simplification of all allocation</li>
<li>Updates to match draft RFC specification</li>
<li>Complete error message and diagnostics overhaul</li>
<li>Numerous protocol, error and bug-fixes</li>
<li>Thread safety in all resolvers</li>
<li>Complete spfd and spfquery rewrite</li>
<li>New cache algorithm</li>
<li>Fixes for alignment on Sparc systems</li>
</ul>

{% comment %}
	<p>
Features yet to be included are:
	</p>

<ul>
<li>best guess</li>
<li>thread safety in all resolvers</li>
<li>spfd and spfquery rewrite</li>
<li>windows support</li>
</ul>
{% endcomment %}

<h1>What is SPF?</h1>

SMTP
has a security hole: any connecting client can assert any sender
address. This flaw has been exploited by spammers to forge mail. The
result: your mailbox fills up with bounces to messages that you
didn't send. Close the hole, and we can easily block spammers by
sender domain.

<ul>
<li>SPF fights email address forgery and</li>
<li>makes it easier to identify spams, worms, and viruses</li>
<li>when domain owners designate sending mail servers in DNS,
	so that</li>
<li>SMTP receivers can distinguish legitimate mail from spam</li>
<li>by verifying the envelope sender address against client IP</li>
<li><i>before</i> any message data is transmitted.</li>
</ul>

<h1>Why use libspf2?</h1>

SPF is a moderately complex system, and it is critical that SPF
deployments from different vendors be able to interoperate correctly.
libspf2 is a complete, ground-up rewritten "second generation"
implementation of SPF. It is being actively maintained to track the
standards process by experienced programmers involved in developing the
standards. The license (LGPL or 2-clause BSD) permits its inclusion
in commercial products. It is feature-complete and thread safe. It
is also thoroughly tested; the source code is freely available to
anybody who wishes to inspect, contribute to, or test the library before
deployment.

{% comment %}
I started my first C implementation back in December
of 2003, but it was ugly and I didn't get very far. Using what
I learned from writing my first SPF implementation, plus what I
learned by studying the perl and libspf implementations and the
SPF test suite, I decided to try writing a new one, and it all just
kind of fell in place nicely.
{% endcomment %}

Libspf2 is designed to be secure, correct, portable, flexible, and
fast (in that order). A great deal of effort has been put into the
design and testing of libspf2. It is, to the best of our knowledge, the
most feature complete, bug free and standard compliant implementation
available. Unlike most other developers of SPF implementations, our
extensive work on the SPF test suite has given us a broad understanding
of the state of art of SPF implementations.
