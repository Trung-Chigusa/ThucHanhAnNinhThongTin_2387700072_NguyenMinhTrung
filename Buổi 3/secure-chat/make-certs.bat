@echo off
setlocal EnableExtensions

set "SCRIPT_DIR=%~dp0"
set "CERT_DIR=%SCRIPT_DIR%certs"
set "CONFIG=%SCRIPT_DIR%openssl.cnf"
set "OPENSSL_EXE="

for /f "delims=" %%I in ('where openssl 2^>nul') do if not defined OPENSSL_EXE set "OPENSSL_EXE=%%I"
if not defined OPENSSL_EXE if exist "%ProgramFiles%\Git\usr\bin\openssl.exe" set "OPENSSL_EXE=%ProgramFiles%\Git\usr\bin\openssl.exe"
if not defined OPENSSL_EXE if exist "%ProgramFiles%\Git\mingw64\bin\openssl.exe" set "OPENSSL_EXE=%ProgramFiles%\Git\mingw64\bin\openssl.exe"
if not defined OPENSSL_EXE if defined ProgramFiles(x86) if exist "%ProgramFiles(x86)%\Git\usr\bin\openssl.exe" set "OPENSSL_EXE=%ProgramFiles(x86)%\Git\usr\bin\openssl.exe"

if not defined OPENSSL_EXE (
    echo ERROR: OpenSSL was not found in PATH or the common Git for Windows folders.
    exit /b 1
)
if not exist "%CONFIG%" (
    echo ERROR: openssl.cnf is missing.
    exit /b 1
)
if not exist "%CERT_DIR%" mkdir "%CERT_DIR%"
if errorlevel 1 goto :failed

for %%F in (ca.key ca.pem server.key server.pem alice.key alice.pem bob.key bob.pem) do if exist "%CERT_DIR%\%%F" goto :existing

echo Creating a local SecureChat CA and demo certificates with "%OPENSSL_EXE%"...
"%OPENSSL_EXE%" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "%CERT_DIR%\ca.key"
if errorlevel 1 goto :failed
"%OPENSSL_EXE%" req -x509 -new -key "%CERT_DIR%\ca.key" -sha256 -days 3650 -out "%CERT_DIR%\ca.pem" -config "%CONFIG%" -extensions v3_ca -subj "/CN=SecureChat Local CA"
if errorlevel 1 goto :failed

"%OPENSSL_EXE%" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "%CERT_DIR%\server.key"
if errorlevel 1 goto :failed
"%OPENSSL_EXE%" req -new -key "%CERT_DIR%\server.key" -out "%CERT_DIR%\server.csr" -config "%CONFIG%" -subj "/CN=localhost"
if errorlevel 1 goto :failed
"%OPENSSL_EXE%" x509 -req -in "%CERT_DIR%\server.csr" -CA "%CERT_DIR%\ca.pem" -CAkey "%CERT_DIR%\ca.key" -CAcreateserial -out "%CERT_DIR%\server.pem" -days 825 -sha256 -extfile "%CONFIG%" -extensions server_cert
if errorlevel 1 goto :failed

"%OPENSSL_EXE%" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "%CERT_DIR%\alice.key"
if errorlevel 1 goto :failed
"%OPENSSL_EXE%" req -new -key "%CERT_DIR%\alice.key" -out "%CERT_DIR%\alice.csr" -config "%CONFIG%" -subj "/CN=alice"
if errorlevel 1 goto :failed
"%OPENSSL_EXE%" x509 -req -in "%CERT_DIR%\alice.csr" -CA "%CERT_DIR%\ca.pem" -CAkey "%CERT_DIR%\ca.key" -CAserial "%CERT_DIR%\ca.srl" -out "%CERT_DIR%\alice.pem" -days 825 -sha256 -extfile "%CONFIG%" -extensions client_cert
if errorlevel 1 goto :failed

"%OPENSSL_EXE%" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "%CERT_DIR%\bob.key"
if errorlevel 1 goto :failed
"%OPENSSL_EXE%" req -new -key "%CERT_DIR%\bob.key" -out "%CERT_DIR%\bob.csr" -config "%CONFIG%" -subj "/CN=bob"
if errorlevel 1 goto :failed
"%OPENSSL_EXE%" x509 -req -in "%CERT_DIR%\bob.csr" -CA "%CERT_DIR%\ca.pem" -CAkey "%CERT_DIR%\ca.key" -CAserial "%CERT_DIR%\ca.srl" -out "%CERT_DIR%\bob.pem" -days 825 -sha256 -extfile "%CONFIG%" -extensions client_cert
if errorlevel 1 goto :failed

del "%CERT_DIR%\*.csr" "%CERT_DIR%\ca.srl" >nul 2>nul
echo Created certificates in "%CERT_DIR%".
exit /b 0

:existing
echo ERROR: A CA key or demo certificate already exists in "%CERT_DIR%". Move the existing files aside before generating a new set.
exit /b 1

:failed
echo ERROR: Certificate generation failed. Existing files were left in place; inspect the output above.
exit /b 1
