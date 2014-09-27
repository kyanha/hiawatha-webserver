@ECHO OFF

ECHO Wigwam:
"INSTALL_DIR\bin\wigwam.exe"
IF ERRORLEVEL 1 GOTO ERROR
ECHO.
ECHO Hiawatha:
"INSTALL_DIR\bin\hiawatha.exe" -k

:ERROR
ECHO.
PAUSE
