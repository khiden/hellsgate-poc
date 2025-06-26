# PoC for Hell’s Gate technique
walks process memory to grab live syscall IDs, then performs direct syscalls (no use windows APIs layers).

# build
ml64 /c /Fo hellsgate.obj hellsgate.asm

x86_64-w64-mingw32-gcc main.c hellsgate.obj -o hellsgate.exe -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc '-Wl,-subsystem,console'
