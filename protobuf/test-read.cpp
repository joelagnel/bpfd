#include <stdio.h>
#include <iostream>
#include <fstream>
#include "bpfd.pb.h"

#define strbuff "\xde\xea\xad\xbe\xef"

int main()
{
	bpfd::LoadProgram prog;
	std::ifstream bpffile;

	bpffile.open("bpffile.bin");

	prog.ParseFromIstream(&bpffile);

	bpffile.close();

	printf("prog type: %d\n", prog.bpf_prog_type());

	return 0;
}
