
## Prerequisite
Please follow [this](setup_vm.md) first to setup the proper environment and then proceed.

Note it is only tested on macOS 10.15.

## Find Loaded Services
One driver (kext) consists of multiple services. In this step, we aim to find all valid service names.

```
python main.py --find_service --dir path/to/all/kexts
```

All valid services would be printed out to terminal and saved to `workdir/services.json`.

## Find Required Entitlements (Options)
Some drivers requires special privilege to be accessed. Therefore, we provide some basic static analysis tool to extract all entitlements. Note that the analysis is neither sound nor complete. If we failed to analyse some services in later steps, please manually check those binaries to see if any entitlements are required.

```
python main.py --find_entitlement
```
The above command should output all entitlements it found, and then we need to add those to the following two files if they are not present there already:
1. libs/ent.plist
2. config

## Find UserClient
Each service may provide multiple types of clients, we need to figure their types and corresponding id.

```
python main.py --find_client --service seriveName
```

e.g., `python main.py --find_client --service IOBluetoothHCIController`

At the end of the output, you can find all user clients it found:
```
Service: IOBluetoothHCIController user
func newUserClient: 0x2fc8
	IOBluetoothHCIUserClient: 0 user
	externalMethod: 0x10bca
	getTargetAndMethodForIndex: 0x1097e
```

## Find Functionalities
Once user client can provide different functionalities depending on the given input (i.e., command identifier). In this step, we would like to analyze the dispatch function (e.g., `externalMethod` to get all valid values for the command identifier and their corresponding functionalities (i.e., function addresses, we assume each functionality corresponds to a function)).

```
python main.py --find_table --service seriveName (or --client clientName to be more specific)
```

e.g., `python main.py --find_table --client IOBluetoothHCIUserClient`

In the output below, you can find the total number of functionalities, command identifier and info regarding each functionality including address, function name and some input/output constraints. A common practice for macOS driver to provide different functionalities is to implement a function dispatch table, which also contains the constraints for input/output. We also extract those info if applicable.

```
IOBluetoothHCIUserClient: 213 methods      <-- Total number of functionalities
cmd: <BV32 structInput_4_8192[7295:7264]>  <-- command identifier
Method 0 at 0x16bd6 __ZN24IOBluetoothHCIUserClient24DispatchHCIRequestCreateEPS_PjS1_P31BluetoothHCIRequestCallbackInfoPvS1_
	scalarInputCount: -1, structInputSize: -1, scalarOutputCount: -1, structOutputSize: -1

Method 1 at 0x16c4c __ZN24IOBluetoothHCIUserClient24DispatchHCIRequestDeleteEPS_Pj
	scalarInputCount: -1, structInputSize: -1, scalarOutputCount: -1, structOutputSize: -1
... ...
```

## Generate Default Template
```
python main.py --gen_template --client clientName --no_async (optional)
```

e.g., `python main.py --gen_template --client IOBluetoothHCIUserClient --no_async`
You can find the generated specification for IOBluetoothHCIUserClient at `${GOPATH}/src/github.com/google/syzkaller/sys/darwin/IOBluetoothHCIUserClient_gen.txt`. Now you can already start fuzzing despite the specification is too coarse-grained.

Additionally, we can leverage traces collected from existing applications that invoke the target driver to refine the specification.

Please refer to [macOS-tools](https://github.com/CvvT/macOS-tools) to learn how to generate traces from running applications.

In the sample folder, we provide some examples.

Note that those samples were collected when running bluetooth with my personal device, and thus the generated specifications would use the corresponding MAC address, causing fuzzing to fail make a connection. However, you can use my samples in this step to get some sense of the difference.

```
mkdir workdir/testcases/IOBluetoothHCIUserClient
cp samples/* workdir/testcases/IOBluetoothHCIUserClient/
```

Note you may find there is file named `extra_dep.json` in the sample file. The file containing the constant of MAC address is critical because we also consider it as a depdendency despite it is a constant in our setup.

Now if we run `python main.py --gen_template --client IOBluetoothHCIUserClient --no_async` again, you can find additional resources defined in the specifications compared to the previous one as follows:

```
resource IOBluetoothHCIUserClient_connection_0[int32]
IOBluetoothHCIUserClient_connection_2 {
    field0  const[0x4eb80450, int32]
    field1  const[0xb962, int16]
} [packed]
resource IOBluetoothHCIUserClient_connection_1[int16]
```

## Interface Inference
Before we proceed to the next step, we need to analyze the driver first to get signatures of all functions. Angr poorly handles macOS drivers and thus we again rely on IDA Pro. All generated results should be stored in `workdir/cc`.

```
python scripts/ida.py --dir /path/to/all/kexts
```

You need to adjust the path to the IDA Pro executable in `script/ida.py`.

Now we can go ahead to run the final step:

```
python main.py --infer_type --client clientName
```