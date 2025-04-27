Build (win): `msbuild tcphs.vcxproj /p:Configuration=Release /p:Platform=x64` in win folder

Build (linux): `make` in linux folder

Server:
tcphs.exe -s -p 5555

Client:
tcphs.exe -c 127.0.0.1 -p 5555
