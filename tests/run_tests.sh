#!/bin/bash
# Make sure none of the commands return a negative

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

output=$(cat $DIR/TESTS | grep -v ";" | $DIR/../build/bpfd)
ret=$(echo $output | grep "ret=-")

if [ x${ret} == "x" ]; then
	echo "All tests pass"
	if [ x$1 == "x-v" ]; then
		echo ${output}
	fi
else
	echo "Some tests failed, output: ${ret}"
fi
