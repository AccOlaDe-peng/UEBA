@echo off
REM --------------------------------------------------------
REM Copyright (C) 2021 Splunk Inc. All Rights Reserved.
REM --------------------------------------------------------

setlocal EnableDelayedExpansion

REM Get the time service configuration and timezone.

REM Get the date & time
for /f "usebackq delims=" %%i in (`powershell.exe -NoProfile -Command "(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')" 2^>nul`) do set "date_time=%%i"

REM Print the date and time. This will be the timestamp of the event.
echo Current time: %date_time%

REM Print the Windows time service configuration
w32tm /query /configuration /verbose

REM Print the Windows time zone information
w32tm /tz
