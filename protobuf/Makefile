CC := g++

test: test-write.cpp test-read.cpp
	protoc bpfd.proto --cpp_out=./
	g++  -o bpfd.pb.o bpfd.pb.cc -c
	g++  -o test.o test-write.cpp -c
	g++  -o test-write bpfd.pb.o test.o -lprotobuf
	g++  -o test.o test-read.cpp -c
	g++  -o test-read bpfd.pb.o test.o -lprotobuf

