---
layout: default
title: Download
src:
    - libspf2-1.2.10.tar.gz
    - libspf2-1.2.9.tar.gz
    - libspf2-1.2.8.tar.gz
    - libspf2-1.2.7.tar.gz
    - libspf2-1.2.6.tar.gz
    - libspf2-1.2.5.tar.gz
    - libspf2-1.2.4.tar.gz
    - libspf2-1.2.3.tar.gz
    - libspf2-1.2.1.tar.gz
    - libspf2-1.0.4.tar.gz
    - libspf2-1.0.3.tar.gz
    - libspf2-1.0.2.tar.gz
    - libspf_alt-0.4.0.tar.gz
---

<h1>Source code</h1>

The complete libspf2 source code may be downloaded here:

<ul>
{% for _ in page.src %}
<li><a href="spf/{{_}}">{{_}}</a></li>
{% endfor %}
</ul>

<h1>Developers</h1>

Check the code out from github:

<ul>
<li><a href="https://github.com/shevek/libspf2/">https://github.com/shevek/libspf2/</a></li>
</ul>

{% comment %}
<h1>MTA Support</h1>

<%doc>
% if (@PATCHES) {
<ul>
% foreach (@PATCHES) {
<li><a href="<% $_->[0] %>"><% $_->[0] %></a>: <% $_->[1] %>
	<% length $_->[2] ? "($_->[2])" : "" %></li>
% }
</ul>
% }
</%doc>

	<p>
A simple list of patches and plugins became too complex to read,
thus we have moved to a new format. This is really an extract
from the <a href="http://www.libsrs2.net/status.html">status
page</a>. <!-- If the plugin or patch you are looking for is not here,
please mail <a href="mailto:libspf2 [ta] rt.anarres.org">libspf2 [ta]
rt.anarres.org</a> to submit or request it. -->
	</p>

%# <!-- <% Dumper(\%MTAS) %> -->

<center>
<table border="1" width="80%" cellspacing="0" cellpadding="2">
<tr>
	<td width="15%"><b>MTA (alphabetical)</b></td>
% foreach (qw(Plugin Patch)) {
	<td><b><% $_ %></b></td>
% }
</tr>
% foreach my $mta (sort keys %MTAS) {
	<!-- mta <% $mta %> -->
<tr>
	<td valign="top"><% $mta %></td>
%	foreach (qw(Plugin Patch)) {
%		my $data = $MTAS{$mta}->{$_};
	<!-- data <% $data %> -->
	<td valign="top">
		<% libspf2_mta_status($data) %>
	</td>
%	}
</tr>
% }
</table>
</center>

<h1>Distribution packages</h1>

	<p>
Distribution packages are contributed, and may be out of date. If
in doubt, use the source. If you can contribute a distribution
package, please mail <a href="mailto:spf [ta] anarres.org">spf [ta]
anarres.org</a>.
	</p>

<ul>
% foreach (sort keys %DISTROS) {
	<!-- distro <% $_ %> -->
%	my @data = @{ $DISTROS{$_} };
	<!-- data <% @data %> -->
%	next unless @data;
	<li><b><% $_ %></b></li>
%	foreach (@data) {
%		unless ($_->[0]) {
	<li><% $_->[1] %></li>
%		} else {
	<li><a href="<% $_->[0] %>"><% $_->[1] %></a></li>
%		}
%	}
% }
</ul>


<h1>Third Party SPF Software</h1>

	<p>
Several other people have written SPF implementations. This is by
no means a comprehensive list, and the libspf2 developers are not
responsible for these projects. However, they may help to fill the
gaps in a growing portfolio of implementations.
	</p>

<ul>
% foreach (@THIRD) {
<li><b><% $_->[1] %></b>: <a href="<% $_->[0] %>"><% $_->[0] %></a></li>
% }
</ul>

<%once>
use Data::Dumper;

my @SRC = reverse qw(
	libspf_alt-0.4.0.tar.gz
	libspf2-1.0.2.tar.gz
	libspf2-1.0.3.tar.gz
	libspf2-1.0.4.tar.gz
	libspf2-1.2.1.tar.gz
	libspf2-1.2.3.tar.gz
	libspf2-1.2.4.tar.gz
	libspf2-1.2.5.tar.gz
	libspf2-1.2.6.tar.gz
	libspf2-1.2.7.tar.gz
	libspf2-1.2.8.tar.gz
	libspf2-1.2.9.tar.gz
	libspf2-1.2.10.tar.gz
);

#	libspf_alt-0.1.tar.gz  libspf_alt-0.3.tar.gz
#	libspf2-1.0.0.tar.gz libspf2-1.0.1.tar.gz

my @PATCHES = (
	[ 'patch/spfmilter-1.0.8.tar.gz',
		'Sendmail milter for libspf2', 'stable' ],
	[ 'patch/policyd-1.0.1.tar.gz',
		'Postfix policy daemon for libspf2', 'stable' ],
	[ 'patch/postfix-libspf2-2.1.3-4.patch',
		'Postfix patch for libspf2', 'stable' ],
	[ 'patch/postfix-libspf2.README',
		'README for Postfix patch', '' ],
	[ 'patch/postfix-libspf2-2.1.1-4.MiB.1.patch.bz2',
		'Postfix patch for libspf2, tweaked for Mandrake', 'in testing' ],
	[ 'http://www.libsrs2.net/patch/exim-libspf2+libsrs2-4.32-nslm-2.patch',
		'Combined SPF and SRS patch for exim', 'in testing' ],
	[ 'patch/25_exim4-config_spf',
		'Exim configuration fragment for libspf2', 'in testing' ],
	[ 'patch/zmailer.info',
		'Information for zmailer users', ''],
	[ 'patch/milter-greylist.info',
		'Information for sendmail users', ''],
	[ 'http://www.michaelbrumm.com/smtpspffilter.html',
		'An SPF filter for Exchange', '' ],
	[ 'http://www.ipnet6.org/postfix/spf/',
		"Dean's postfix-libspf2 page", '' ],
);

my %MTAS = (

	courier		=> {
	},

	exchange	=> {
		Plugin	=> {
			Name	=> 'SPF Filter',
			File	=> 'http://www.michaelbrumm.com/smtpspffilter.html',
			Desc	=> 'An SPF filter for Exchange',
			Status	=> 'stable',
		},
		Patch	=> {
			Desc	=> '(n/a)',
		},
	},

	exim		=> {
		Plugin	=> {
			Name	=> 'SPF ACL',
			File	=> 'patch/25_exim4-config_spf',
			Desc	=> 'Exim configuration fragment for libspf2',
			Status	=> 'stable',
		},
		Patch	=> {
			Name	=> 'exim-libspf2+libsrs2',
#			File	=> 'http://www.libsrs2.net/patch/exim-libspf2+libsrs2-4.32-nslm-2.patch',
			File	=> 'http://www.nslm.org/Projects/SPF/',
			Desc	=> 'Combined libspf2 and libsrs2 patch for exim',
			Status	=> 'testing',
#			Extra	=> [
#				[ "The maintainer's page",
#					'http://www.nslm.org/Projects/SPF/',
#						],
#			],
		},
	},

	hermes		=> {
		Plugin	=> {
			Name	=> 'spf',
			File	=> 'http://www.hermes-project.com/',
			Status	=> 'included by default',
		},
		Patch	=> {
			Desc	=> '(n/a)',
		},
	},

	postfix		=> {
		Plugin	=> {
			Name	=> 'policyd',
			File	=> 'patch/policyd-1.0.1.tar.gz',
			Version	=> '1.0.1',
			Desc	=> 'Postfix policy daemon for libspf2',
			Status	=> 'stable',
		},
		Patch	=> {
			Name	=> 'postfix-libspf2',
#			File	=> 'patch/postfix-libspf2-2.1.3-4.patch',
			File	=> 'http://www.ipnet6.org/postfix/spf/',
#			Version	=> '2.1.3-4',
			Desc	=> 'Postfix patch for libspf2',
			Readme	=> 'patch/postfix-libspf2.README',
			Status	=> 'stable',
			Extra	=> [
#				[ "The maintainer's page",
#					'http://www.ipnet6.org/postfix/spf/',
#						],
				[ 'Mandrake patch',
					'patch/postfix-libspf2-2.1.1-4.MiB.1.patch.bz2',
						],
				[ 'Mandrake RPMs',
					'http://www.bouissou.net/spftools/',
						],
			],
		},
	},

	sendmail	=> {
		Plugin	=> {
			Name	=> 'spfmilter',
			File	=> 'patch/spfmilter-1.0.8.tar.gz',
			Version	=> '1.0.8',
			Desc	=> 'Sendmail milter for libspf2',
			Status	=> 'stable',
			Extra	=> [
				[ "Jef Poskanzer's spfmilter site",
					'http://www.acme.com/software/spfmilter/'
						],
				[ 'An alternative SPF milter',
					'patch/milter-greylist.info',
						],
			],
		},
		Patch	=> {
			Name	=> 'sendmail-libspf2',
#			File	=> 'patch/sendmail-libspf2-8.13.1-2.patch',
			File	=> 'http://www.sonologic.nl/spf.html',
#			Version	=> '8.13.1-2',
			Desc	=> 'Sendmail patch for libspf2',
			# Readme	=> 'patch/postfix-libspf2.README',
			Status	=> 'testing',
			Extra	=> [
				[ "Koen Martens' sendmail page",
					'http://www.sonologic.nl/spf.html'
						],
			],
		},
	},

	zmailer		=> {
		Plugin	=> {
			Desc	=> '(n/a)',
		},
		Patch	=> {
			Name	=> 'zmailer info',
			File	=> 'patch/zmailer.info',
			Desc	=> 'Information for zmailer users',
		},
	},

);

my %DISTROS = (
	Gentoo	=> [
		['', 'libspf2 and libsrs2 are in the standard portage tree' ],
	],
	'Red Hat'	=> [
		[ 'http://www.city-fan.org/ftp/contrib/libraries/',
				'RPMs for libspf2 by HTTP' ],
		[ 'ftp://www.city-fan.org/pub/contrib/libraries/',
				'RPMs for libspf2 by FTP' ],
		[ 'http://www.city-fan.org/ftp/contrib/mail/',
				'RPMs for spfmilter by HTTP' ],
		[ 'ftp://www.city-fan.org/pub/contrib/mail/',
				'RPMs for spfmilter by FTP' ],
	],
	'Mandrake'	=> [
		[ 'http://www.bouissou.net/spftools/',
				'RPMs for libspf2 and postfix' ],
	],
);

my @THIRD = (
	[ 'http://www.saout.de/misc/spf/',
					=> 'A standalone SPF implementation for qmail' ],
	[ 'http://www.logsat.com/spamfilter/pub/SPFTest-Delphi.zip',
					=> 'An open source Delpi implementation (unsupported)' ],
	[ 'http://hcpnet.free.fr/milter-greylist',
					=> 'milter-greylist for sendmail supports SPF' ],
	[ 'http://duncanthrax.net/exiscan-acl/',
					=> 'exiscan supports SPF' ],
#	[ 'http://www.acme.com/software/spfmilter/',
#					=> 'A sendmail milter for libspf2' ],
	[ 'http://www.pamho.net/source/',
					=> 'An alternative implementation for Windows only' ],
#	[ 'http://www.libspf.org/',
#					=> 'An older SPF library' ],
);

sub libspf2_mta_status {
	my ($data) = @_;
	return '' unless $data;
	my $out;
	$out .= "<a href=\"$data->{File}\">" if $data->{File};
	$out .= "<b>$data->{Name}</b>";
	$out .= "</a>\n" if $data->{File};
	$out .= " (version $data->{Version})\n" if $data->{Version};
	$out .= "<br />\n$data->{Desc}" if $data->{Desc};
	$out .= "<br />\n$data->{Status}" if $data->{Status};

	$out .= "<br /><i>$data->{Notes}</i>" if $data->{Notes};

	$out .= "<br />\n<a href=\"$data->{Readme}\">README</a>"
					if $data->{Readme};

	if ($data->{Extra}) {
		foreach (@{ $data->{Extra} }) {
			$out .= "<br /><a href=\"$_->[1]\">$_->[0]</a>\n";
		}
	}

	return $out;

}
</%once>
{% endcomment %}
