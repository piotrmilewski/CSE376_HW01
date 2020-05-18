#!/bin/bash
# test script #2

# Test the code that verifies that the decryption key is the same as the
# encryption key.

echo initializing test script 3

echo Test if decrypting with a different password results in an error
./filesec -e -p tests/password1.txt tests/decrypted1.txt tests/output3ae.txt
./filesec -d -p tests/password2.txt tests/output3ae.txt tests/output3ad.txt
if test $? != 0 ; then
        echo this test PASSED
else
        echo this test FAILED
fi

echo Test if decrypting with the same password results in successful decryption
./filesec -e -p tests/password1.txt tests/decrypted1.txt tests/output3be.txt
./filesec -d -p tests/password1.txt tests/output3be.txt tests/output3bd.txt
if test $? = 0 ; then
        echo this test PASSED
else
        echo this test FAILED
fi

