/*
 * eBPF library header borrowed from BCC project
 */

#include<stdio.h>
#include<iostream>
#include<vector>
#include<set>
using namespace std;

static vector<string> splitpath(const string &str,
	       		 const set<char> delimiters)
{
	vector<string> result;
	char const* pch = str.c_str();
	char const* start = pch;

	for(; *pch; ++pch) {
		if (delimiters.find(*pch) != delimiters.end()) {
			if (start != pch) {
				string str(start, pch);
				result.push_back(str);
			}
			else {
				result.push_back("");
			}
			start = pch + 1;
		}
	}
	result.push_back(start);

	return result;
}

static string path_filename(string path, bool noext = false)
{
	const set<char> delims{'\\', '/'};
	vector<string> spath = splitpath(path, delims);
	string ret;

	ret = spath.back();

	if (noext) {
		size_t lastindex = ret.find_last_of(".");
		return ret.substr(0, lastindex);
	}
	return ret;
}

static int get_machine_kvers(void)
{
	struct utsname un;
	char *uname_out;
	int nums[3]; // maj, min, sub

	if (uname(&un))
		return -1;
	uname_out = un.release;

	string s = uname_out;
	string token, delim = ".", delim2 = "-";
	size_t pos = 0;
	int cur_num = 0;

	while ((pos = s.find(delim)) != string::npos && cur_num < 3) {
		token = s.substr(0, pos);
		s.erase(0, pos + delim.length());

		if ((pos = token.find(delim2)) != string::npos)
			token = token.substr(0, pos);

		nums[cur_num++] = stoi(token);
	}

	if ((pos = s.find(delim2)) != string::npos)
		token = s.substr(0, pos);
	else
		token = s;

	if (token.length() > 0 && cur_num < 3)
		nums[cur_num++] = stoi(token);

	if (cur_num != 3)
		return -1;
	else
		return (65536 * nums[0] + 256 * nums[1] + nums[2]);
}

static void deslash(char *s)
{
	if (!s)
		return;

	for (unsigned int i = 0; i < strlen(s); i++) {
		if (s[i] == '/')
			s[i] = '_';
	}
}
