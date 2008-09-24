use strict;
use warnings;
use Test::More;
eval "use Mail::SPF::Test";
plan skip_all => "Mail::SPF::Test required for testing SPF code" if $@;

use Mail::SPF_XS qw(:all);

my $suite = new_from_yaml_file Mail::SPF::Test('t/rfc4408-tests.yml');

my $tests = 0;
$tests += scalar($_->test_cases) foreach $suite->scenarios;
plan tests => $tests;

foreach my $scenario ($suite->scenarios) {
	my $server = new Mail::SPF_XS::Server({
		dnstype	=> SPF_DNS_ZONE,
	});
	$server->resolver->add('test.com', ns_t_a, NETDB_SUCCESS, '127.0.0.8');
	foreach my $case ($scenario->test_cases) {
		print "Test case ", $case->name, "\n";

		# use Data::Dumper;
		# print Dumper([ $scenario->records ]);
		for my $record ($scenario->records) {
			print "Adding record " . $record->string . "\n";
			$server->resolver->add($record->name,
					Net::DNS::typesbyname($record->type),
					NETDB_SUCCESS,
					$record->rdatastr);
		}

		my $request = Mail::SPF_XS::Request->new({
			scope           => $case->scope,
			identity        => $case->identity,
			ip_address      => $case->ip_address,
			helo_identity   => $case->helo_identity
		});

		my $response = $server->process($request);

		print "Response is $response\n";

		my $ok = $case->is_expected_result($response->code);
		diag(
			$case->name . " result:\n" .
			"Expected: " .  join(' or ', map("'$_'", $case->expected_results)) . "\n" .
			" Got: " .  "'" .  $response->code .  "'")
				if not $ok;
		ok($ok);

	}
}
