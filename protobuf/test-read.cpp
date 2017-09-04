#include <stdio.h>
#include <iostream>
#include <fstream>
#include "bpfd.pb.h"

#define strbuff "\xde\xea\xad\xbe\xef"

int main()
{
	bpfd::LoadProgram prog;
	std::ifstream bpffile;
	char insn[5];

	bpffile.open("bpffile.bin");

	prog.ParseFromIstream(&bpffile);

	bpffile.close();

	printf("prog type: %d\n", prog.bpf_prog_type());
	std::string bpf_insn = prog.bpf_insn();
	memcpy(insn, bpf_insn.data(), bpf_insn.size());

	for (int i = 0; i < bpf_insn.size(); i++) {
		printf("insn: %x\n", insn[i]);
	}

	return 0;
}
