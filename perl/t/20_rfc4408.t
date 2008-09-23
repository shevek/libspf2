use strict;
use warnings;
use Test::More;
eval "use Mail::SPF::Test";
plan skip_all => "Mail::SPF::Test required for testing SPF code" if $@;

use Mail::SPF_XS;

my $suite = new_from_yaml_file Mail::SPF::Test('t/rfc4408-tests.yml');

my $tests = 0;
$tests += scalar($_->test_cases) foreach $suite->scenarios;
plan tests => $tests;

foreach my $scenario ($suite->scenarios) {
	my $server = new Mail::SPF_XS::Server({});
}
