Build (win):
msbuild tcphs.vcxproj /p:Configuration=Release /p:Platform=x64

Build (linux):
In linux folder, run `make`.

Server:
tcphs.exe -s -p 5555

Client:
tcphs.exe -c 127.0.0.1 -p 5555