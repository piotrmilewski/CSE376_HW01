#!/bin/bash
# test script #2

# Test to ensure that you preserve the output file exactly as it was
# before, in case a failure happened mid-way in reading the infile or
# writing the outfile.

echo initializing test script 2

echo Testing that the output file is preserved exactly as it was before in case of failure happening mid-way in reading the infile or writing the outfile
echo A file modification time will be printed before and after the test runs
echo If the file modification times match then the test passes
stat -c '%Y' tests/sampleEncrypted.txt
./filesec -e -i -p tests/password1.txt tests/decrypted2.txt tests/sampleEncrypted.txt
stat -c '%Y' tests/sampleEncrypted.txt
