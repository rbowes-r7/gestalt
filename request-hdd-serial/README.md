Globalscape EFT 8.1.0.11 has a message id (0x138) that returns an obfuscated
base64 hash of the harddrive's serial number. This hash is easily reversable,
so we wrote a tool to do that!

The parsed request looks like this:

```
{:length=>132,
 :msgid=>312,
 :args=>
  {"HASH"=>
    {:type=>:string,
     :length=>50,
     :data=>"+k4VG0AT5CU04BD60ZW5vm0GM4CJWpmeLS/Q8FFi0jPP4Ctxg="},
   "ERRR"=>{:type=>:int, :value=>0}}}
```

The `HASH` value looks like a base64 string, because it is - kinda. It's
actually obfuscated by adding the digits 0, 8, 0, 0, 0, and 0 at offsets
0x0e, 0x21, 0x05, 0x26, 0x15, and 0x0b, respectively.

If we replace those with spaces, we can see the actual base64 string:

```
+k4VG AT5CU 4BD6 ZW5vm GM4CJWpmeLS/Q FFi jPP4Ctxg=
```

That string decodes to:

```
$ echo -ne '+k4VGAT5CU4BD6ZW5vmGM4CJWpmeLS/QFFijPP4Ctxg=' | base64 -d | hexdump -C
00000000  fa 4e 15 18 04 f9 09 4e  01 0f a6 56 e6 f9 86 33  |.N.....N...V...3|
00000010  80 89 5a 99 9e 2d 2f d0  14 58 a3 3c fe 02 b7 18  |..Z..-/..X.<....|
```

Which is the base64 of my harddrive's id value:

```
$ echo -ne '418934929' | sha256sum
fa4e151804f9094e010fa656e6f9863380895a999e2d2fd01458a33cfe02b718  -
```
