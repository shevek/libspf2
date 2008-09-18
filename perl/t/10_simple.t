use strict;
use warnings;
use blib;
use Test::More tests => 1;

use_ok('Mail::SPF_XS');

my $srv = new Mail::SPF_XS::Server({});
my $req = new Mail::SPF_XS::Request({
	ip_address	=> '62.49.9.82',
	identity	=> 'shevek@anarres.org',
});
my $res = $srv->process($req);
print $res->code, "\n";
