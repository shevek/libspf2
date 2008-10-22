use strict;
use warnings;
use blib;
use Test::More tests => 1;

use_ok('Mail::SPF_XS');

my $srv = new Mail::SPF_XS::Server({});
my $rec;

$rec = $srv->compile("v=spf1 include:1234567");
ok(2, 'parse_cidr did not run off start of data');

$rec = $srv->compile("v=spf1 include:" . ('A' x 5120) . " -all");
ok(3, 'compile did not overrun buffer');
