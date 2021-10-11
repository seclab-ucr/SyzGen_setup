# macOS hook tool

This tool is part of [SyzGen](https://github.com/seclab-ucr/SyzGen_setup) to hook some key functions (ie, externalMethod and withAddressRange), enabling collection of inputs and outputs of the IOKit call (IOConnectCallMethod).

# How to build
1. Run the following command to generate a header file containing addresses we would like to hook.
  `python script/gen.py --kext bundle_id_of_target_driver --clazz name_of_target_user_client`
2. Load the project hook in Xcode to build it
3. Build the client to receive records from the hooker\
  `cd client ; make`
4. Upload the client and hook.kext (you can find it at DerivedData/hook/Build/Products/Debug/hook.kext) to the tested machine
5. `sudo chown -R root:wheel hook.kext`

# How to run
1. `sudo kextload kcov.kext` to load the driver.
2. `./client` to start collecting traces.
3. Run any application to trigger syscall to our target driver.
3. Ctrl+C to stop the client 
4. You can find the complete logs at `/tmp/kernel_hook.txt`

The generated file can be used by [SyzGen](https://github.com/seclab-ucr/SyzGen_setup) to infer explicit dependencies.
