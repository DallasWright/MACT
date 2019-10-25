# MACT
Malware Analysis and Artifact Capture Tool

<h2><b>Overview</b><h2>
<hr></hr>
<p>
Full Dissertation at https://scholar.dsu.edu/theses/327/
  
MACT is an interacive API Malware Analysis tool for 32-bit Windows.

The following files are provided:
1. mact32.dll - 32 bit version of MACT
2. serverc.dll - Server used in conjunction with MACT
3. mact.res

verify.cpp from Microsoft Detours is also required unless you remove the Verify calls. They are only informational.
</p>

<h2><b>Requirements</b><h2>
<hr></hr>
<p>
Microsoft Detours - For DLL injection and API interception.
SQLite - To log API calls to a database.
</p>

<h2><b>Compilation Command</b><h2>
<hr></hr>
<p>
del mact32.dll
del mact.obj
cl /EHsc /nologo /Zi /MT /Gm- /WX /O2 /I..\..\include /Fo /c mact.cpp
cl /LD /EHsc /nologo /Zi /MT /Gm- /WX /O2 /I..\..\include /Fe./mact32.dll /Fd./mact32.pdb mact.obj mact.res /link /release /incremental:no /profile /nodefaultlib:oldnames.lib /subsystem:console  /export:DetourFinishHelperProcess,@1,NONAME c:\research\lib.X86\detours.lib kernel32.lib
</p>

<h2><b>Notes</b><h2>
<hr></hr>
<p>
  
1. MACT is still being developed and fine tuned.
2. Some malware samples require certain intercepted functions to Sleep to allow all of the logging to finish before the malware continues executing. These sleeps and duration should be added as a command within MACT. Currently this requires a special compile for some samples. 
3. Currently only tested with 32-bit Windows 7.
4. It is recommended to run MACT in a 32-bit Windows 7 virtual machine.

</p>

<h2><b>How to Use</b><h2>
<hr></hr>
<p>
  
1. Start a 32-bit Windows 7 VM.
2. Take precations as you would with any malware sample.
3. Create a directory containing serverc.exe, mact32.dll, withdll.exe, sqlite.exe, and the malware sample.
4. Open a command prompt and run serverc.exe
5. Open another command prompt and run "withdll.exe -d:mact32.dll <malware sample>". withdll.exe injects the DLL and is provided with Microsoft Detours.
6. Issue the command "D C" to display the available commands.
7. Artifacts will be written to C:\MACT with a new directory created for each execution of the injected sample.
8. There is a good DB Browser for SQLlite databases at http://sqlitebrowser.org/
  
</p>
