@echo off
title This is the cleanup script!
echo This will clean all .exe files and the stored keys!
rmdir sender\store /s
del sender\sender.exe 
rmdir receiver\store /s
del receiver\receiver.exe 