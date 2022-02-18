AC_INIT(GNU Aspell Fuzzer, [-])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIRS([m4])

AC_SUBST(OUT)

AC_ARG_WITH(aspell,
  AS_HELP_STRING([--with-aspell=DIR],[the directory in which aspell is installed]),
  aspell_dir=$with_aspell, aspell_dir=$OUT)
AC_SUBST(aspell_dir)

AC_CHECK_FILE([$aspell_dir/lib/libaspell.a],
              [],
              AC_MSG_ERROR([could not find $aspell_dir/lib/libaspell.a]))

AC_SUBST([LIB_FUZZING_ENGINE])
AM_CONDITIONAL([USE_OSSFUZZ_FLAG], [test "x$LIB_FUZZING_ENGINE" = "x-fsanitize=fuzzer"])
AM_CONDITIONAL([USE_OSSFUZZ_STATIC], [test -f "$LIB_FUZZING_ENGINE"])

AC_PROG_CXX
AC_LANG([C++])
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
