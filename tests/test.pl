# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

use Test;
use strict;

use Getopt::Long;

my $HELP = 0;
my $SPFIMPL = "any";
my $SPFPROG = "./spfquery";
my $SPFDATA = "test.txt";
my %TODO = ();
my $QUERY_OPT = "";
my $PIPE_OUT = 0;
my $PIPE_IN = 0;

my $result = GetOptions('help'          => \$HELP,
			'impl=s'        => \$SPFIMPL,
			'query-opt=s'   => \$QUERY_OPT,
			'program=s'     => \$SPFPROG,
			'data=s'        => \$SPFDATA,
			'todo=i'        => \%TODO,
			'-pipe-out'     => \$PIPE_OUT,
			'-pipe-in'      => \$PIPE_IN,
		       );

if ($HELP  || !$result) {
  print <<EOF;
Usage: test.pl [options]

      -help	Help on the options.

      -impl=pascal              Set the SPF implemenation.
      -program=/path/program    Use an alternate spfquery command.
      -query-opt=-read-my-mind  Additional spfquery options
      -data=/path/test.txt      Use an alternate test data set.
      -todo=[1-4,99]            TODO list
      -pipe-out                 Do not check answers, send spfquery output
                                to stdout.  Only one spfquery process is
                                used, so this tests the implementation's
                                handling of multiple queries.
      -pipe-in                  Check the answers sent via stdin.
EOF

    exit(0);
}

local *SPFQUERY;
my $spfquery_init = 0;

my @test_table;

open(TESTFILE, $SPFDATA) || die "Could not open $SPFDATA: $!\n";
@test_table = <TESTFILE>;
chomp @test_table;
close TESTFILE;


# this is supposed to be in a BEGIN clause, but I don't know perl
# well enough to get the -data option to work that way.  -wayne
my @tests = grep { /^\s*spfquery / } @test_table;

if ( $SPFIMPL eq "libspf2" ) {
  plan tests => 1 + @tests*3, todo => [362 .. 364, 503 .. 508];
} else {
  plan tests => 1 + @tests*3;

# the TODO option doesn't work, and I don't understand why   -wayne
#  plan tests => 1 + @tests*3, %TODO;
}


# 1: did the library load okay?
ok(1);

#########################

sub check_last_command {
  my ($ok, $default, $options, $result, $smtp_comment, $header_comment, $received_spf ) = @_;

  if (!$ok && !$Test::todo{$Test::ntest - 1})
  {
    print "$SPFPROG $default $options $QUERY_OPT\n";

    printf "Result:         %s\n", $result;
    printf "SMTP comment:   %s\n", $smtp_comment;
    printf "Header comment: %s\n", $header_comment;
    printf "Received-SPF:   %s\n", $received_spf;

    open( SPFQUERY_DEBUG, "$SPFPROG $default $options $QUERY_OPT -debug=1 |" );
    while (<SPFQUERY_DEBUG>) {
      print $_;
    }
    close( SPFQUERY_DEBUG );
    if ($@) {
      print "  trapped error: $@\n";
      next;
    }
  }
}


my $default;
my $options;
my ($result, $smtp_comment, $header_comment, $received_spf);
my ($found_result, $found_smtp_comment, $found_header_comment, $found_received_spf);
my $command_checked = 1;
my $ok = 1;

if ( $PIPE_IN ) {
  *SPFQUERY = \*STDIN;

  while (<SPFQUERY>) {
    print "skipping: $_";
    last if $_ eq "ok 1\n";
  }
}

foreach my $line (@test_table) {

  $line =~ s/^\s*//;

  next if $line =~ /^$/;
  next if $line =~ /^#/;

  my ($command, $implre, $matchre) = split( ' ', $line, 3 );

  if ( $command eq "default" ) {
    $default = $implre . " " . $matchre;
  }
  elsif ( $command eq "spfquery" ) {

    my $prev_options = $options;
    $options = $implre . " " . $matchre;

    if ( $PIPE_OUT ) {

      next if $options =~ /-local=/;

      if ( !$spfquery_init ) {
	open( SPFQUERY, "| $SPFPROG $default $QUERY_OPT -file -" );
	$spfquery_init = 1;
      }

      my ($ip, $sender, $helo, $rcpt_to);

      ($ip) = ($options =~ m/-ip=([^ ][^ ]*)/);
      ($sender) = ($options =~ m/-sender=([^ ][^ ]*)/);
      ($helo) = ($options =~ m/-helo=([^ ][^ ]*)/);
      ($rcpt_to) = ($options =~ m/-rcpt-to=\"([^ ][^ ]*)\"/);
      printf SPFQUERY "$ip $sender $helo $rcpt_to\n";

    } else {

      $found_result = $found_smtp_comment = $found_header_comment = $found_received_spf = 0;

      if ( !$command_checked ) {
	check_last_command($ok, $default, $prev_options, $result, $smtp_comment, $header_comment, $received_spf);
	$command_checked = 1;
      }

      next if $PIPE_IN && $options =~ /-local=/;

      open( SPFQUERY, "$SPFPROG $default $options $QUERY_OPT |" ) if ( !$PIPE_IN );

      $ok = 1;

      chomp( $result = <SPFQUERY> );
      chomp( $smtp_comment = <SPFQUERY> );
      chomp( $header_comment = <SPFQUERY> );
      chomp( $received_spf = <SPFQUERY> );
      close( SPFQUERY ) if !$PIPE_IN;

      $command_checked = 0;
    }

  } else {

    next if $PIPE_OUT;

    if ( $implre =~ m,^/.*/$, ) {
      $implre =~ s,^/(.*)/$,$1,;
      next if $SPFIMPL !~ /$implre/;
    } else {
      next if $SPFIMPL ne $implre;
    }

    my $skip_test = !$ok || ($PIPE_IN && $options =~ /-local=/);


    if ( $command eq "result" ) {
      if ( !$found_result ) {
	$ok &= skip($skip_test, $result, $matchre);
      }
      $found_result = 1;
    } elsif ( $command eq "smtp-comment" ) {
      if ( !$found_smtp_comment ) {
	$ok &= skip($skip_test, $smtp_comment, $matchre);
      }
      $found_smtp_comment = 1;
    } elsif ( $command eq "header-comment" ) {
      if ( !$found_header_comment ) {
	$ok &= skip($skip_test, $header_comment, $matchre);
      }
      $found_header_comment = 1;
    } elsif ( $command eq "received-spf" ) {
      if ( !$found_received_spf ) {
	# $ok &= skip($skip_test, $received_spf, $matchre);
	# $ok &= skip($skip_test, $received_spf, "/^Received-SPF:  *$result \\($header_comment\\)/" );
      }
      $found_received_spf = 1;
    } else {
      $ok &= ok( $command, "", "invalid test command" );
    }

  }

}

if ( !$command_checked ) {
  check_last_command($ok, $default, $options, $result, $smtp_comment, $header_comment, $received_spf);
  $command_checked = 1;
}

close( SPFQUERY ) if $PIPE_OUT;

