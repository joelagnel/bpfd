#include <stdio.h>
#include <iostream>
#include <fstream>
#include "bpfd.pb.h"

#define strbuff "\xde\xea\xad\xbe\xef"

int main()
{
	bpfd::LoadProgram prog;
	std::ofstream bpffile;

	bpffile.open("bpffile.bin");

	prog.set_bpf_prog_type(55);
	prog.set_bpf_insn(strbuff, strlen(strbuff));
	prog.SerializeToOstream(&bpffile);

	bpffile.close();

	return 0;
}
