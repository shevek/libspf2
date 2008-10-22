use strict;
use warnings;
use blib;
use Test::More tests => 13;

use_ok('Mail::SPF_XS');

my $srv = new Mail::SPF_XS::Server({ debug => 0 });

my %records = (
	'a%%b%%c%'		=> 'a%b%c%',
	'%%'			=> '%',
	'foo'	=> 'foo',
);

for (keys %records) {
	my $exp = $srv->expand($_);
	is($exp, $records{$_}, "Expanded $_ as a macro");

	my $rec = $srv->compile("v=spf1 macro=$_");

	my $str = $rec->string;
	ok(1, "Compiled v=spf1 macro=$_ as a record");
	is($str, "v=spf1 macro=$_", "Stringified the record");

	my $value = $rec->modifier('macro');
	is($value, $records{$_}, "Expanded $_ as a modifier");

#	$rec = $srv->compile("v=spf1 macro=$_ -all");
#	$value = $rec->modifier('macro');
#	is($value, $records{$_}, "Parsed $_ -all");
}
