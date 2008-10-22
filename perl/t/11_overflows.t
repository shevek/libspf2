use strict;
use warnings;
use blib;
use Test::More tests => 3;

use_ok('Mail::SPF_XS');

my $srv = new Mail::SPF_XS::Server({ debug => 4 });
my $rec;

$rec = $srv->compile("v=spf1 include:1234567");
ok(1, 'parse_cidr did not run off start of data');

eval { $rec = $srv->compile("v=spf1 include:" . ('A' x 5120) . " -all"); };
ok(1, 'compile did not overrun buffer');
