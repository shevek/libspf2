use strict;
use warnings;
use Test::More;
eval "use Mail::SPF::Test";
plan skip_all => "Mail::SPF::Test required for testing SPF code" if $@;
use String::Escape qw(unquote);

use Mail::SPF_XS qw(:all);

my $suite = new_from_yaml_file Mail::SPF::Test('t/rfc4408-tests.yml');

my $tests = 0;
$tests += scalar($_->test_cases) * 2 foreach $suite->scenarios;
plan tests => $tests;

my $casename = undef;
# $casename = 'alltimeout';
$casename = 'multispf2';

foreach my $scenario ($suite->scenarios) {
	if ($casename) {
		my $found = undef;
		foreach my $case ($scenario->test_cases) {
			$found = 1 if $case->name eq $casename;
		}
		next unless $found;
	}

	my $server = new Mail::SPF_XS::Server({
		dnstype	=> SPF_DNS_ZONE,
		debug	=> 4,
	});
	# $server->resolver->add('test.com', ns_t_a, NETDB_SUCCESS, '127.0.0.8');

	for my $record ($scenario->records) {
		print "Adding record " . $record->string . "\n";
		my $type = $record->type;
		# $type = 'TXT' if $type eq 'SPF';
		# TRY_AGAIN if it's a timeout
		$server->resolver->add($record->name,
				Net::DNS::typesbyname($type),
				NETDB_SUCCESS,
				unquote($record->rdatastr));
	}

	foreach my $case ($scenario->test_cases) {
		if ($casename) {
			next unless $case->name eq $casename;
		}
		print "Test case ", $case->name, "\n";

		# use Data::Dumper;
		# print Dumper([ $scenario->records ]);

		my $request = Mail::SPF_XS::Request->new({
			scope           => $case->scope,
			identity        => $case->identity,
			ip_address      => $case->ip_address,
			helo_identity   => $case->helo_identity
		});

		print "Request is " . $request->string, "\n";

		my $response = $server->process($request);

		print "Response is " . $response->string, "\n";

		my $ok = $case->is_expected_result($response->code);
		diag(
			$case->name . " result:\n" .
			"Expected: " .  join(' or ', map("'$_'", $case->expected_results)) . "\n" .
			" Got: " . $response->code)
				if not $ok;
		ok($ok);

#		$ok = $case->expected_explanation eq $response->explanation;
#		diag(
#			$case->name . " explanation:\n" .
#			"Expected: " .  $case->expected_explanation . "\n" .
#			" Got: " . $response->explanation)
#				if not $ok;
#		ok($ok);
	}
}
