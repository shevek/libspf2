# Makefile prototype

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST              = $(TESTS) README \
	run_all test test.pl \
	mtrace_wrapper valgrind_wrapper \
	test_parser.txt test_adopt_roll.txt \
	test_rfc_examples.txt test_live.txt

TESTS_ENVIRONMENT       = top_srcdir=$(top_srcdir) \
				top_builddir=$(top_builddir)

TESTS = run_single_parser \
		run_single_adopt_roll \
		run_single_rfc_examples \
		run_single_tdns run_many_tdns \
		run_single_live run_many_live
# also tests_single_valgrind tests_many_valgrind

distclean-local:
	-rm -rf .valgrind *.out
