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

  
The function which prints the flag is located at `0x080485AB`. It is not called anywhere by the program. We have to somehow redirect the execution flow to there so that it prints our flag.

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



