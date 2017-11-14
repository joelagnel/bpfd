#!/bin/bash
# Make sure none of the commands return a negative

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

ret=$(cat $DIR/TESTS | $DIR/../run_bpfd.sh | grep "ret=-")

if [ x${ret} == "x" ]; then
	echo "All tests pass"
else
	echo "Some tests failed, output: ${ret}"
fi
