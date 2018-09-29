#include "helpers.h"

struct time_key {
    uint32_t uid;
    uint32_t freq;
};

struct bpf_map_def SEC("maps") uid_times = {
        .type = BPF_MAP_TYPE_PERCPU_HASH,
        .key_size = sizeof(struct time_key),
        .value_size = sizeof(uint64_t),
        .max_entries = 10240,
};

struct bpf_map_def SEC("maps") cpu_last_update = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(uint64_t),
        .max_entries = 1,
};

struct bpf_map_def SEC("maps") cpu_freq = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(uint32_t),
	/* Assume max of 1024 CPUs */
        .max_entries = 1024,
};

struct switch_args {
        unsigned long long ignore;
        char prev_comm[16];
        int prev_pid;
        int prev_prio;
        long long prev_state;
        char next_comm[16];
        int next_pid;
        int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct switch_args *args)
{
    char s[] = { "testprog %u\\n" };
    bpf_trace_printk(s, 5);

    uint32_t zero = 0;
    uint64_t *last = bpf_map_lookup_elem(&cpu_last_update, &zero);
    if (!last)
        return 0;
    uint64_t old_last = *last;
    uint64_t time = bpf_ktime_get_ns();
    *last = time;
    uint32_t cpu = bpf_get_smp_processor_id();
    uint32_t *freq = bpf_map_lookup_elem(&cpu_freq, &cpu);
    if (args->prev_pid && *last && freq && *freq) {
        uint32_t uid = bpf_get_current_uid_gid();
        struct time_key key = { .uid = uid, .freq = *freq };
        uint64_t *tot_time = bpf_map_lookup_elem(&uid_times, &key);
        uint64_t delta = time - old_last;
        if (!tot_time)
            bpf_map_update_elem(&uid_times, &key, &delta, BPF_ANY);
        else
            *tot_time += delta;
    }
    return 0;
}

struct cpufreq_args {
        unsigned long long ignore;
        unsigned int cpu_id;
        unsigned int state;
};

SEC("tracepoint/power/cpu_frequency")
int tp_cpufreq(struct cpufreq_args *args)
{
    unsigned int cpu = args->cpu_id;
    unsigned int new = args->state;
    bpf_map_update_elem(&cpu_freq, &cpu, &new, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
