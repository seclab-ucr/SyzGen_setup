
import os

WORKDIR = "workdir"
ServicePath = os.path.join(WORKDIR, "services")
ModelPath = os.path.join(WORKDIR, "model")
TestCasePath = os.path.join(WORKDIR, "testcases")
ResourcePath = os.path.join(WORKDIR, "resources")
CoveragePath = os.path.join(WORKDIR, "cov")
PoCPath = os.path.join(WORKDIR, "poc")

if not os.path.exists(WORKDIR):
	os.mkdir(WORKDIR)
	
for path in (ServicePath, ModelPath, TestCasePath, ResourcePath, PoCPath):
	if not os.path.exists(path):
		os.mkdir(path)


DEBUG = False

class Options:
	_instance = None

	def __init__(self):
		self.infer_dependence = True
		self.debug = False
		
	def __new__(cls):
		if cls._instance is None:
			cls._instance = super(Options, cls).__new__(cls)
		return cls._instance