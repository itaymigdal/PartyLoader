# About

PartyLoader is a threadless injector weaponizing [Pool Party injection](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/) variant 7.

## Installation
Built with Nim 1.6.12.
```
nimble install winim nimprotect supersnappy argparse
```

## Usage
```
Usage:
   [options] shellcode_file

Arguments:
  shellcode_file   Raw shellcode file to load

Options:
  -h, --help
  -n, --process-name=PROCESS_NAME
                             Process name to inject (default: explorer.exe)
  -w, --wait-for-process     Wait for the target process to start (default: exit if target process isn't found)
  -f, --format=FORMAT        Loader format Possible values: [exe, dll] (default: exe)
  -e, --export=EXPORT        DLL export name (relevant only for Dll format) (default: DllRegisterServer)
  -p, --split                Split and hide the payload blob in loader (takes long to compile!)
  -t, --sleep=SLEEP          Number of seconds to sleep before injection (default: 0)
  -g, --anti-debug=ANTI_DEBUG
                             Action to perform upon debugger detection Possible values: [none, die, troll] (default: none)
  -k, --key=KEY              RC4 key to [en/de]crypt the payload (supplied as a command line argument to the loader) (default: )
  -v, --veh                  Injection will occur within VEH
```

## Credits
1. My friend and Ex-coworker [_0xDeku](https://twitter.com/_0xDeku) for the great Pool Party research
  
