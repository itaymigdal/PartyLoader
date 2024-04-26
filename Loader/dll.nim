import main
import params

proc NimMain() {.cdecl, importc.}

proc DllRegisterServer(): void {.stdcall, exportc, dynlib.} =
    NimMain()
    main()
        