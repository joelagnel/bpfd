from bcc import BPF
import time
import glob
import os
from collections import defaultdict

def readIntList(path):
  with open(path, 'r') as f:
    return [int(x) for x in f.read().split()]


def getPolicyData():
  policy_freqs = defaultdict(list)
  cpu_policies = {}
  policies = glob.glob('/sys/devices/system/cpu/cpufreq/policy*')

  for policy in policies:
    cpu = int(os.path.basename(policy).replace('policy', ''))

    freq_paths = glob.glob(policy + '/scaling_*_frequencies')
    for path in freq_paths:
      policy_freqs[cpu] += readIntList(path)
    policy_freqs[cpu].sort()

    rcpus = readIntList(os.path.join(policy, 'related_cpus'))
    for rcpu in rcpus:
      cpu_policies[rcpu] = cpu

  return policy_freqs, cpu_policies

policy_freqs, cpu_policies = getPolicyData()

bpf = BPF('tracetimeinstate.c')

print 'Tracing UID time-in-state, hit Ctrl-C to stop'

while True:
  try:
    time.sleep(1)
  except KeyboardInterrupt:
    break
print '\n'


table = bpf.get_table('uid_times')

uid_dict = defaultdict(lambda: defaultdict(dict))

for k, v in table.items():
  for cpu, time in enumerate(v):
    policy = cpu_policies[cpu]
    if not k.freq in uid_dict[k.uid][policy]:
      uid_dict[k.uid][policy][k.freq] = time
    else:
      uid_dict[k.uid][policy][k.freq] += time

for uid, data in sorted(uid_dict.items()):
  times = []
  for policy in policy_freqs:
    if policy not in data:
      times += [0] * len(policy_freqs[policy])
    else:
      freqs = data[policy]
      for i, freq in enumerate(policy_freqs[policy]):
        if freq in freqs:
          times.append(freqs[freq] / int(1e7))
        else:
          times.append(0)
  all_times = ' '.join(str(time) for time in times)
  print '{}: {}'.format(uid, all_times)
