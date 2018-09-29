// Test-program for reading time_in_state

#include <iostream>
#include <unistd.h>
#include "libbpf.h"

using namespace android::bpf;

typedef struct {
	uint32_t uid;
	uint32_t freq;
} time_key_t;

typedef struct {
	uint64_t ar[100];
} val_t;

int main(void) {
	int ret, prog_fd, map_fd;

	ret = load_prog("timeinstate/bpf_kern.o");
	printf("bpf prog loaded... %d\n", ret);

	prog_fd = bpf_obj_get("/sys/fs/bpf/prog_bpf_kern_tracepoint_sched_sched_switch");
	ret = bpf_attach_tracepoint(prog_fd, "sched", "sched_switch");
	printf("tp sched sw attached prog %d to %d\n", prog_fd, ret);

	prog_fd = bpf_obj_get("/sys/fs/bpf/prog_bpf_kern_tracepoint_power_cpu_frequency");
	ret = bpf_attach_tracepoint(prog_fd, "power", "cpu_frequency");
	printf("tp power attached prog %d to %d\n", prog_fd, ret);

	map_fd = bpf_obj_get("/sys/fs/bpf/map_bpf_kern_uid_times");
	printf("got map %d\n", map_fd);

	sleep(5);

	BpfMap<time_key_t, val_t> m(map_fd);
        const auto iterf = [](const time_key_t& key,
			      const val_t& val,
			      const BpfMap<time_key_t, val_t>& map) {
		printf("Iter key %u %u, val %d\n", key.uid, key.freq, val.ar[0]);
		return 0;
	};
        m.iterateWithValue(iterf);



	sleep(3);

	BpfMapPerCpu<int, int> m(map_fd);
        const auto iterf = [](const int& key,
			      const std::vector<int>& vals,
			      const BpfMap<int, int>& map) {
		printf("Iter key %d\n", key);
		for (auto i = vals.begin(); i != vals.end(); ++i) {
			std::cout << *i << ' ';
		}
		printf("\n");

		return 0;
	};
        m.iterateWithValues(iterf);

	return 0;

}
