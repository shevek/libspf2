use strict;
use warnings;
use blib;
use Test::More tests => 5;

use_ok('Mail::SPF_XS');

my $srv = new Mail::SPF_XS::Server({ debug => 4 });
my $rec;

my %records = (
	'a%%b%%c%'		=> 'a%b%c%',
	'%%'			=> '%',
);

for (keys %records) {
	$rec = $srv->compile("v=spf1 macro=$_");
	# XXX This nees to use a modifier, and use get_mod_value
	ok(1, "Parsed $_");

	$rec = $srv->compile("v=spf1 macro=$_ -all");
	# XXX This nees to use a modifier, and use get_mod_value
	ok(1, "Parsed $_");
}
