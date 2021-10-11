
import sys
import os
import re

from datetime import datetime, timedelta
import matplotlib.pyplot as plt

def parse(filepath):
	if not os.path.exists(filepath):
		print("%s does not exists" % filepath)
		sys.exit(1)

	ents = []
	covs = set()
	with open(filepath, "r") as fp:
		for line in fp:
			m = re.search(r'(2021/\d+/\d+) (\d+:\d+:\d+) VMs [01], executed \d+, corpus cover (\d+),', line)
			if m:
				# print(m.group(1), m.group(2), m.group(3))
				t = datetime.strptime("%s %s" % (m.group(1), m.group(2)), "%Y/%m/%d %H:%M:%S")
				ents.append((t, int(m.group(3))))
			else:
				m = re.search(r'2021/\d+/\d+ \d+:\d+:\d+ cov: (0x[\da-f]+)', line)
				if m:
					covs.add(int(m.group(1), 16))

	return ents, covs

def filter(filepath, num=48):
	ents, covs = parse(filepath)
	print(len(ents), len(covs))
	hour = timedelta(hours=1)
	minute = timedelta(minutes=2)
	t = ents[0][0]
	idx = 0
	data = []
	while idx < len(ents):
		# print(ents[idx][0], t, abs(ents[idx][0] - t), abs(ents[idx][0] - t) < minute)
		if abs(ents[idx][0] - t) < minute:
			print(t.ctime(), ents[idx][1])
			data.append(ents[idx][1])
			t = t + hour
		idx += 1
	return data[:num+1], covs

def coverage(filepaths):
	_, cov1 = filter(filepaths[0])
	_, cov2 = filter(filepaths[1])
	print(cov1-cov2)
	print(cov2-cov1)


def main(filepaths):
	coverage(filepaths)

	markers = ['--ro', '--bs', '--g^']
	legends = ['TOOL', 'TOOL-Base', 'Other']
	for i, filepath in enumerate(filepaths):
		data, _ = filter(filepath)
		print(data)
		plt.plot(range(len(data)), data, markers[i], label=legends[i])

	plt.ylabel("Block Coverage")
	plt.xlabel("Time(hour)")
	plt.legend()
	plt.show()

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
