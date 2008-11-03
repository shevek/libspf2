use strict;
use warnings;
use blib;
use Test::More tests => 5;

use_ok('Mail::SPF_XS');

my $srv = new Mail::SPF_XS::Server({ debug => 0 });
my $rec;

$rec = $srv->compile("v=spf1 include:1234567");
ok(1, 'parse_cidr did not run off start of data');

eval { $rec = $srv->compile("v=spf1 include:" . ('A' x 5120) . " -all"); };
ok(1, 'compile did not overrun buffer');
ok(defined $@, 'compile at least threw an error');

my $in = join("%{s}", (0..20));
my $out = $srv->expand($in);
ok(1, 'expand did not overrun buffer');
