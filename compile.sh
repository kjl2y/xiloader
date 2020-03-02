#!/bin/sh
i686-w64-mingw32-g++ -Os -s -static -static-libgcc -static-libstdc++ --std=c++11 -Wno-write-strings xiloader/*.cpp -lws2_32 -lole32 -lpsapi -L`pwd` -liphlpapi -o edenxi.exe
#i686-w64-mingw32-g++ -D EDENMAIN_EXPORTS -shared -Os -s -static -static-libgcc -static-libstdc++ --std=c++11 -Wno-write-strings xiloader/*.cpp -lws2_32 -lole32 -lpsapi -L`pwd`/xiloader/detours -ldetours -L`pwd` -liphlpapi -o edenxi.dll
