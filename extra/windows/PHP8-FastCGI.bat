@ECHO OFF

"C:\Program Files\PHP8\php-cgi.exe" -b localhost:2005
IF ERRORLEVEL 1 PAUSE
