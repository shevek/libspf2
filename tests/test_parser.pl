# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

use Test;
use strict;

use Getopt::Long;

my $HELP = 0;
my $SPFIMPL = "any";
my $SPFPROG = "./spftest";
my $SPFDATA = "test_parser.txt";
my %TODO = ();
my $TEST_OPT = "";

my $result = GetOptions('help'          => \$HELP,
			'impl=s'        => \$SPFIMPL,
			'test-opt=s'    => \$TEST_OPT,
			'program=s'     => \$SPFPROG,
			'data=s'        => \$SPFDATA,
			'todo=i'        => \%TODO,
		       );

if ($HELP  || !$result) {
  print <<EOF;
Usage: test_parser.pl [options]

      -help	Help on the options.

      -impl=pascal              Set the SPF implemenation.
      -program=/path/program    Use an alternate spftest command.
      -test-opt=-read-my-mind   Additional spftest options
      -data=/path/test.txt      Use an alternate test data set.
      -todo=[1-4,99]            TODO list
EOF

    exit(0);
}

local *SPFTEST;
my $spftest_init = 0;

my @test_table;

open(TESTFILE, $SPFDATA) || die "Could not open $SPFDATA: $!\n";
@test_table = <TESTFILE>;
chomp @test_table;
close TESTFILE;


# this is supposed to be in a BEGIN clause, but I don't know perl
# well enough to get the -data option to work that way.  -wayne
my @tests = grep { /^\s*spftest / } @test_table;

if ( $SPFIMPL eq "libspf-alt" ) {
  plan tests => 1 + @tests*3;
} else {
  plan tests => 1 + @tests*3;

# the TODO option doesn't work, and I don't understand why   -wayne
#  plan tests => 1 + @tests*3, %TODO;
}


# 1: did the library load okay?
ok(1);

#########################

sub check_last_command {
  my ($ok, $default, $options, $rec_in, $err_msg, $spf_header, $rec_out ) = @_;

  if (!$ok && !$Test::todo{$Test::ntest - 1})
  {
    print "$SPFPROG $default $options $TEST_OPT\n";

    open( SPFTEST_DEBUG, "$SPFPROG $default $options $TEST_OPT -debug=1 |" );
    while (<SPFTEST_DEBUG>) {
      print $_;
    }
    close( SPFTEST_DEBUG );
    if ($@) {
      print "  trapped error: $@\n";
      next;
    }
  }
}


my $default;
my $options;
my ($rec_in, $err_msg, $spf_header, $rec_out);
my ($found_rec_in, $found_err_msg, $found_spf_header, $found_rec_out);
my $command_checked = 1;
my $ok = 1;


foreach my $line (@test_table) {

  $line =~ s/^\s*//;

  next if $line =~ /^$/;
  next if $line =~ /^#/;

  my ($command, $implre, $matchre) = split( ' ', $line, 3 );

  if ( $command eq "default" ) {
    $default = $implre . " " . $matchre;
  }
  elsif ( $command eq "spftest" ) {

    my $prev_options = $options;
    $options = $implre . " " . $matchre;

    $found_rec_in = $found_err_msg = $found_spf_header = $found_rec_out = 0;

    if ( !$command_checked ) {
      check_last_command($ok, $default, $prev_options, $rec_in, $err_msg, $spf_header, $rec_out);
      $command_checked = 1;
    }

    open( SPFTEST, "$SPFPROG $default $options $TEST_OPT |" );

    $ok = 1;

    chomp( $rec_in = <SPFTEST> );
    chomp( $err_msg = <SPFTEST> );
    chomp( $spf_header = <SPFTEST> );
    chomp( $rec_out = <SPFTEST> );
    close( SPFTEST );

    $command_checked = 0;

  } else {

    if ( $implre =~ m,^/.*/$, ) {
      $implre =~ s,^/(.*)/$,$1,;
      next if $SPFIMPL !~ /$implre/;
    } else {
      next if $SPFIMPL ne $implre;
    }

    my $skip_test = !$ok;


    if ( $command eq "rec-in" ) {
      if ( !$found_rec_in ) {
	$ok &= skip($skip_test, $rec_in, $matchre);
      }
      $found_rec_in = 1;
    } elsif ( $command eq "err-msg" ) {
      if ( !$found_err_msg ) {
	$ok &= skip($skip_test, $err_msg, $matchre);
      }
      $found_err_msg = 1;
    } elsif ( $command eq "spf-header" ) {
      if ( !$found_spf_header ) {
	$ok &= skip($skip_test, $spf_header, $matchre);
      }
      $found_spf_header = 1;
    } elsif ( $command eq "rec-out" ) {
      if ( !$found_rec_out ) {
	$ok &= skip($skip_test, $rec_out, $matchre);
      }
      $found_rec_out = 1;
    } elsif ( $command eq "rec-out-auto" ) {
      if ( !$found_rec_out ) {
	$rec_in =~ s/^SPF record in:  //;
	$rec_out =~ s/^SPF record:  //;
	$ok &= skip($skip_test, $rec_out, $rec_in );
      }
      $found_rec_out = 1;
    } else {
      $ok &= ok( $command, "", "invalid test command" );
    }

  }

}

if ( !$command_checked ) {
  check_last_command($ok, $default, $options, $rec_in, $err_msg, $spf_header, $rec_out);
  $command_checked = 1;
}
