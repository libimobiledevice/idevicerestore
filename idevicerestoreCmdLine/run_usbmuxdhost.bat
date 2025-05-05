@echo off
REM Set the environment variables (same as in run_idevicerestore.bat)
set MCE_USBMUXD_PORT=37326
set DEBUG=mce*
set USBMUXD_PID_37326=9780
set MceRoot=C:\Program Files (x86)\MCE-100
set mceBox=311
set MCEHOME=C:\Program Files (x86)\MCE-100
set TMPDIR=C:\ProgramData\MCE-100\Tmp\1fb4c2469c238c

REM Display the environment variables for verification
echo Environment variables set:
echo MCE_USBMUXD_PORT=%MCE_USBMUXD_PORT%
echo DEBUG=%DEBUG%
echo USBMUXD_PID_37326=%USBMUXD_PID_37326%
echo MceRoot=%MceRoot%
echo mceBox=%mceBox%
echo MCEHOME=%MCEHOME%
echo TMPDIR=%TMPDIR%

REM Run the usbmuxdhost command
echo.
echo Running usbmuxdhost command...
"c:\program files (x86)\mce-100\usbmuxdhost.exe" 37326 311 Global\MCE_OBJECT_{890ac237-b523-4617-8cd0-2bd1a33bb2b8} Global\MCE_{49facbfc-b65c-4bc5-85b0-7ac10307ec5f}_37326 "C:\Program Files (x86)\MCE-100\usbmuxdComPlugin.dll" AutoShutdownTRUE

REM Pause to see the output before the window closes
echo.
echo Command execution completed.
pause 