#!/bin/bash
# test script #1

# One test would verify that your program handles command line interface
# (CLI) options correctly.  This includes testing for illegal/missing CLI
# options (e.g., -d and -e can't be given together).

echo initializing test script 1

echo Testing that -d and -e cant be given together
./filesec -d -e tests/decrypted1.txt testOutput/output1a.txt
if test $? != 0 ; then
	echo this test PASSED
else
	echo this test FAILED
fi

echo Testing that -d or -e must be given
./filesec -v tests/decrypted1.txt testOutput/output1b.txt
if test $? != 0 ; then
	echo this test PASSED
else
	echo this test FAILED
fi
