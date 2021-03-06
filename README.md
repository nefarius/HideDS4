# HideDS4
A small helper-library which prevents a process from accessing a connected DualShock 4 controller

## What's this?
A Proof-of-Concept, nothing more, nothing less. It's a small DLL which hides the Sony DualShock 4 Controller from any Windows process it gets injected into. It accomplishes this by hooking the [`CreateFile`](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx) Windows API using [MinHook](https://github.com/TsudaKageyu/minhook).

## How to use
1. Either clone this repository and compile the library yourself or [download the latest release](../../releases/latest).
2. [Get my DLL injector utility](../../../Injector/releases/latest) or use you own.
3. Put Injector and DLL in the same directory (**caution:** only use 64-Bit injector with 64-Bit DLL on 64-Bit target process, likewise with 32-Bit builds).
4. Launch your target process (the game).
5. Enter command line `Injector.exe --inject --module-name HideDS4.dll --process-name witcher3.exe` to load the DLL into the game.
6. If the DualShock 4 is connected, re-connect it for the fix to kick in.
7. Enjoy!
