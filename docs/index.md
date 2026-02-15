---
layout: default
title: Documentation
---

<h1>Documentation for libspf2 Users</h1>

See the <a href="html/">API documentation page</a>.

{% comment %}
<h1>Documentation for MTA Coders</h1>

See the <a href="mta-patches.html">MTA patches page</a>.

<h1>Documentation for MTA Users</h1>

See the <a href="mta-users.html">MTA users page</a>.

<h1>Documentation for Testers</h1>

See the <a href="testers.html">testers page</a>.

<h1>Third party documentation</h1>

	<p>
SPF is a large project and there are many major organisations
contributing to it. Some of these produce documentation:
	</p>

<ul>
% foreach (@TPDOCS) {
<li><a href="<% $_->[0] %>"><% $_->[1] %></a></li>
% }
</ul>

<%once>
my @TPDOCS = (
	[ 'http://www.openspf.org/',
		'www.openspf.org the home of SPF' ],
#	[ 'http://spftools.infinitepenguins.net/',
#		'SPFTools at infinitepenguins.net' ],
);
</%once>
{% endcomment %}
