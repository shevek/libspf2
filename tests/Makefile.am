# Makefile prototype

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST              = $(TESTS) README \
	test.pl test_parser.pl \
	run run_tdns run_vallog run.mtrace \
	trun trun.mtrace \
	tests_single_valgrind tests_many_valgrind \
	test_parser.txt test_adopt_roll.txt \
	test.txt test_rfc_examples.txt


testsubdir              = testSubDir

TESTS_ENVIRONMENT       = top_builddir=$(top_builddir)

TESTS                   = tests_parser tests_adopt_roll \
			tests_single_tdns tests_many_tdns \
			tests_single tests_many \
			tests_rfc_examples
# also tests_single_valgrind tests_many_valgrind

distclean-local:
	-rm -rf $(testsubdir)
