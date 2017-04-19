# Write-up

![](/assets/problem-statement.png)

Format string vulnerability

**gigem{F0RM@1NG\_1S\_H4RD}**

### Analysis

Suppose we run  the program with the string `AAAAAAAAAAAAAA`

When the program is on `printf`,

![](/assets/at-printf.png)

The stack looks like

`BFFFEDC0  BFFFEDD0  MEMORY:BFFFEDD0  <--- ESP (Pointer to our string)  
BFFFEDC4  00000002  MEMORY:00000002  Dword 1  
BFFFEDC8  00000000  MEMORY:00000000  Dword 2  
BFFFEDCC  00000000  MEMORY:00000000  Dword 3  
BFFFEDD0  41414141  MEMORY:41414141  <--- Our entered string  
BFFFEDD4  41414141  MEMORY:41414141  
BFFFEDD8  41414141  MEMORY:41414141  
BFFFEDDC  00004141  MEMORY:00004141`  


