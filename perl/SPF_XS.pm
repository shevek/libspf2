package Mail::SPF_XS;

use strict;
use warnings;
use vars qw($VERSION @ISA @EXPORT_OK %EXPORT_TAGS);
use Exporter;

require DynaLoader;

$VERSION = "0.01";
@ISA = qw(DynaLoader Exporter);
@EXPORT_OK = ();
%EXPORT_TAGS = (
	all	=> \@EXPORT_OK,
		);

bootstrap Mail::SPF_XS;

=head1 NAME

Mail::SPF_XS - An XS implementation of Mail::SPF

=head1 DESCRIPTION

This is an interface to the C library libsrs2 for the purpose of
testing. While it can be used as an SPF implementation, you can also
use L<Mail::SPF>, available from CPAN, which is a little more perlish.

=head1 SUPPORT

Mail the author at <cpan@anarres.org>

=head1 AUTHOR

	Shevek
	CPAN ID: SHEVEK
	cpan@anarres.org
	http://www.anarres.org/projects/

=head1 COPYRIGHT

Copyright (c) 2008 Shevek. All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

Mail::SPF, Mail::SRS, perl(1).

=cut

1;
