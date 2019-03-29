@echo off
title This is the initialize script!
echo This will initialize the project executables!
cd sender
go build
cd ..\receiver
go build 