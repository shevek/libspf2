use strict;
use warnings;
use blib;
use Test::More tests => 4;

use_ok('Mail::SPF_XS');

my $srv = new Mail::SPF_XS::Server({ debug => 4 });
my $rec;

my %records = (
	'include:a%%b%%c%' => 'some-test-value',
	'include:%%' => 'some-test-value',
);

for (keys %records) {
	$rec = $srv->compile("v=spf1 $_");
}
