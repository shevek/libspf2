#!/usr/bin/perl

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

# Shevek rewrote this. It still isn't elegant, but it'll do.
# This script is now far more Perlish. It:
#   * Performs all tests using ok() or like(), not skip().
#   * Doesn't require a fixed set of tests per query.
#   * Unifies multiple preexisting parsers.
#   * Contains much less code.
#   * Implements --todo

# Examples of --todo:
# ./test.pl -todo 65="not yet implemented"
#   Marks all output of execution 65 as 'todo'
# ./test.pl -todo 65.err-msg="this is wrong"
#   Marks the err-msg step of execution 65 as 'todo'

#########################

use strict;
use warnings;
use Test::More;
use Getopt::Long;
use IPC::Open2;
use Text::ParseWords;

my $HELP = 0;
my $SPFTEST = "./spftest";
$SPFTEST = "../src/spftest/spftest_static" unless -f $SPFTEST;
$SPFTEST = "../win32/spftest/Debug/spftest.exe" unless -f $SPFTEST;
my @SPFTEST_OUTPUT = ('rec-in', 'err-msg', 'spf-header', 'rec-out');
my $SPFQUERY = "./spfquery";
$SPFQUERY = "../src/spfquery/spfquery_static" unless -f $SPFQUERY;
$SPFQUERY = "../win32/spfquery/Debug/spfquery.exe" unless -f $SPFQUERY;
my @SPFQUERY_OUTPUT = ('result', 'smtp-comment', 'header-comment',
				'received-spf');
my $TESTFILE = "test_parser.txt";
my $TESTOPTS = "";
my $VALGRIND = join(" ", qw(
		valgrind
			--logfile=.valgrind/log
			--tool=memcheck
			--leak-check=yes
			--show-reachable=yes
			--num-callers=8
				));
my %TODO = ();
my $PIPE = undef;

my $IMPLNAME = "libspf2";
my $run_valgrind;

my $result = GetOptions(
				'help'          => \$HELP,
				'test-opt=s'    => \$TESTOPTS,
				'spftest=s'     => \$SPFTEST,
				'spfquery=s'    => \$SPFQUERY,
				'data=s'        => \$TESTFILE,
				'todo=s'		=> \%TODO,
				'impl=s'		=> \$IMPLNAME,
				'valgrind=s'	=> \$run_valgrind,
				'pipe'			=> \$PIPE,
					);

if ($HELP  || !$result) {
	print <<"EOH";
Usage: test_parser.pl [options]

      --help                     Help on the options.

      --impl=pascal              Set the SPF implemenation.
      --spftest=/path/program    Use an alternate spftest command.
      --spfquery=/path/program   Use an alternate spfquery command.
      --test-opt=-read-my-mind   Additional spftest options
      --data=/path/test.txt      Use an alternate test data set.
	  --valgrind=[1|/path/to/vg] Run valgrind underneath programs
	  --todo=<cmdnum>[.<test>]   Mark a test as TODO and ignore fails
EOH

    exit(0);
}

VALGRIND: {
	# We ditch the flag and just set up $VALGRIND
	if ($run_valgrind) {
		$VALGRIND = $run_valgrind if $run_valgrind =~ m,/,;
		mkdir(".valgrind") unless -d ".valgrind";
		system("rm -f .valgrind/*");
	}
	else {
		$VALGRIND = "";	# Clobber it!
	}
}

my @TESTDATA;

READ: {
	local *FH;
	open(FH, $TESTFILE) or die "Could not open $TESTFILE: $!\n";
	@TESTDATA = <FH>;
	chomp @TESTDATA;
	close FH;
}

PLAN: {
	my @tests = grep { /^\s*[a-z]/ } @TESTDATA;
	plan tests => scalar(@tests);
}

#########################

my $default = '';
my $options;
my $ok = 1;
my $record;
my %output = ();
my %checked = ();

local *RDFH;
local *WRFH;
my $command;
my $cmdcounter = 0;


sub read_result {
	my @params = @_;

	my $result = <RDFH>;
	if (defined $result) {
		ok(1, "Command $cmdcounter: '$command'");
		chomp($output{shift(@params)}   = $result);
		print "<-- $result\n";
		foreach (@params) {
			chomp($output{$_}   = <RDFH>);
			redo if
				($_ ne 'err-msg') &&
				($output{$_} =~ /^(?:Error|Warning):/); 
			print "$_ <-- $output{$_}\n";
		}
	}
	else {
		fail("Failed on command $cmdcounter: '$command'");
	}
}

sub execute_command {
	my ($program, $options, $answers) = @_;

	%output = ();
	%checked = ();

	$cmdcounter++;

	TODO: {
		local $TODO = $TODO{$cmdcounter};
		$TODO = $TODO{$cmdcounter.exec} unless $TODO;

		$command = "$VALGRIND $program $default $options $TESTOPTS";
		$command =~ s/^\s*//g;
		my @command = shellwords($command);
		open(RDFH, "-|", @command)
				or die "Failed to execute command " .
						"$cmdcounter: '$command'";

		read_result(@$answers);

		close(RDFH);
	}
}

sub pipe_command {
	my ($program, $options, $answers) = @_;

	%output = ();
	%checked = ();

	$cmdcounter++;

	TODO: {
		local $TODO = $TODO{$cmdcounter};
		$TODO = $TODO{$cmdcounter.exec} unless $TODO;

		if ($cmdcounter == 1) {
			$command = "$VALGRIND $program $default -file - $TESTOPTS";
			$command =~ s/^\s*//g;
			my @command = shellwords($command);
			open2(\*RDFH, \*WRFH, @command)
					or die "Failed to execute command " .
							"$cmdcounter: '$command'";
		}
		my ($ip, $sender, $helo, $rcpt_to) = ('', '', '', '');
		$options =~ m/-ip=([^ ][^ ]*)/          and $ip = $1;
		$options =~ m/-sender=([^ ][^ ]*)/      and $sender = $1;
		$options =~ m/-helo=([^ ][^ ]*)/        and $helo = $1;
		$options =~ m/-rcpt-to=\"([^ ][^ ]*)\"/ and $rcpt_to = $1;
		# print "--> $ip $sender $helo $rcpt_to\n";
		print WRFH "$ip $sender $helo $rcpt_to\n";

		read_result(@$answers);
	}
}

foreach (@TESTDATA) {
	s/^\s*//;
	next if /^$/;
	next if /^#/;

	if (s/^default\s+//) {
		$default = $_;
		ok(1, 'Found "default" line.');
	}
	elsif (s/^spftest\s+//) {
		$record = $_;
		execute_command($SPFTEST, $record, \@SPFTEST_OUTPUT);
	}
	elsif (s/^spfquery\s+//) {
		$record = $_;
		if ($PIPE) {
			pipe_command($SPFQUERY, $record, \@SPFQUERY_OUTPUT);
		}
		else {
			execute_command($SPFQUERY, $record, \@SPFQUERY_OUTPUT);
		}

	}
	elsif (s/^rec-out-auto\s+//) {
		SKIP: {
			skip('Failed to execute command', 1) unless scalar %output;
		}
		# Check rec-in eq rec-out
		my $in = $output{'rec-in'};
		$in =~ s/record in:/record:/;
		is($output{'rec-out'}, $in, "rec-out-auto (equality)");
	}
	else {
		my ($command, $implre, $matchre) = split(/\s+/, $_, 3);

		SKIP: {
			if ($implre =~ s,^/(.*)/$,$1,) {
				skip("Not a $IMPLNAME test (=~ /$implre/)", 1)
								if $IMPLNAME !~ /$implre/;
			}
			elsif ($IMPLNAME ne $implre) {
				skip("Not a $IMPLNAME test (eq '$implre')", 1);
			}

			skip("Already checked $command for $checked{$command}",
							1) if exists $checked{$command};

			skip('Failed to execute command', 1) unless scalar %output;

			# print "TEST: $output{$command}\n";
			# print "GOOD: $matchre\n";

			TODO: {
				local $TODO = $TODO{$cmdcounter};
				$TODO = $TODO{"$cmdcounter.$command"} unless $TODO;

				if ($matchre =~ s,^/(.*)/$,$1,) {
					like($output{$command}, qr/$matchre/,
							"$cmdcounter.$command check (regex)");
				}
				else {
					is($output{$command}, $matchre,
							"$cmdcounter.$command check (equality)");
				}
				$checked{$command} = $implre;
			}
		}
	}
}

if ($run_valgrind) {
	foreach (<.valgrind/log.pid*>) {
		local *FH;
		open(FH, "<$_") or die "Failed to open logfile $_";
		my @data = <FH>;
		close(FH);
		@data = grep { /== ERROR SUMMARY/ } @data;
		@data = grep { $_ !~ /0 errors from 0 contexts/ } @data;
		print @data;
	}
}
