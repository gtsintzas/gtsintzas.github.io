---
title: Gaslight CTF 2026
date: 2026-08-17
categories: [misc, rev]
summary: "Placeholder "
published: true
---

The two writeups below are super rushed and not that well written. Will be fixed at a later time. (Soon™)
## rev

### Compiled Source Sheets

#### Description
My new VM is Spectre-proof! It's also guaranteed race-condition free, and runs on every major OS<sup>[1]</sup>. Try it out!

<sup>[1] that supports Chrom(e\|ium)</sup>

#### Solution
We are given an HTML file `vm.html` that contains an x86 emulator written in CSS... (wtf)

Now, after spending one hour simply looking at it in amazement, and questioning reality (cause of course we do that, who wouldn't after looking at a x86 emulator written in CSS 😆) we analyze the situation.

It seems to be a program that checks for a password. Alright, that seems straight forward. We find the password, we enter it, and hopefully we get the flag. (or maybe the password is the flag. We'll see.)

Now, the first thing we need to do is figure out where the program being loaded lives. Hopefully we won't have to look at implementation details of the emu. 

Now, reading through the FaQ include in the file, we notice this line, which is probably going to be useful: `The program gets loaded at memory address 0x100`.

Looking into the code, and CTRL-F some educated guesses, and also keeping in mind that `0x100 = 256 (in decimal)`, we find that memory locations are represented with `--m<number>`. So, we are looking for `--m256`.

Looking for that we can't find the program code, but we find this interesting piece of code:
`--m256: calc(if(style(--addrDestA:256):var(--addrValA1);style(--addrDestA:255) and style(--isWordWrite:1):var(--addrValA2);style(--addrDestB:256):var(--addrValB);else:var(--__1m256)));`

Now, we write this a bit more cleanly structured:

```css
--m256: calc(
    if(
        style(--addrDestA: 256): var(--addrValA1);
        style(--addrDestA: 255) and style(--isWordWrite: 1): var(--addrValA2);
        style(--addrDestB: 256): var(--addrValB);
        else: var(--__1m256)
    )
);
```
it seems to be some sort of logic for the memory addresses and values. Now, before we try to understand any of it deeply, we CTRL-F for `--__1m256` and we find the following:

```css
--__1m256: 86;
--__1m257: 87;
--__1m258: 85;
--__1m259: 137;
...
```

Now, that seems promising. This could very well be the program code being executed, as it looks very close to machine code!.

with a simple python script, we can reconstruct the binary.

```py
import sys
lines = open(sys.argv[1]).readlines()

numbers = []

for line in lines:
    # line example:  --__1m256: 86;
    parts = line.split(":")

    value = parts[1] # " 86;"
    value = value.strip()  # remove space
    value = value.replace(";", "")  # remove semicolon

    number = int(value)
    numbers.append(number)

data = bytes(numbers)
out = open("out.bin", "wb")
out.write(data)
out.close()

print("done")
```

Now, we have the program binary. We can decompile it as a function using ghidra. This is what we get:

```

undefined2 __cdecl16near FUN_0000_0005(void)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  code *pcVar8;
  int iVar9;
  char cVar10;
  undefined2 uVar11;
  undefined1 extraout_AH;
  int unaff_BP;
  uint uVar12;
  undefined2 unaff_SS;
  undefined2 unaff_DS;
  
  (*(code *)*(undefined2 *)0x33c)(0x2ea);
  (*(code *)*(undefined2 *)0x33c)(0x2f3);
  (*(code *)*(undefined2 *)0x33e)(0x2fc);
  uVar12 = 0;
  do {
    *(undefined2 *)*(undefined2 *)0x338 = 2;
    uVar11 = (*(code *)*(undefined2 *)0x33a)();
    cVar10 = (char)uVar11;
    if (cVar10 != '\0') {
      *(undefined2 *)*(undefined2 *)0x338 = 0;
      if (cVar10 == '\n') break;
      *(int *)(unaff_BP + -0xe) = uVar12 + 1;
      *(char *)(uVar12 + unaff_BP + -10) = cVar10;
      (*(code *)*(undefined2 *)0x340)(uVar11);
      uVar12 = *(uint *)(unaff_BP + -0xe);
    }
  } while ((int)uVar12 < 10);
  (*(code *)*(undefined2 *)0x340)(10);
  pcVar8 = (code *)*(undefined2 *)0x33c;
  if (((int)uVar12 < 9) && ((uVar12 & 1) == 0)) {
    bVar1 = *(byte *)(unaff_BP + -4);
    bVar2 = *(byte *)(unaff_BP + -8);
    if ((bVar1 ^ bVar2) == 0x6f) {
      bVar3 = *(byte *)(unaff_BP + -7);
      bVar4 = *(byte *)(unaff_BP + -3);
      if ((((bVar3 & bVar4) == 0) && ((bVar3 | bVar4) == 0x7f)) && ((bVar1 | bVar3) == 0x3f)) {
        bVar5 = *(byte *)(unaff_BP + -9);
        bVar6 = *(byte *)(unaff_BP + -5);
        if (((((((bVar5 & bVar6) == 0x40) && ((bVar2 ^ bVar6) == 0x11)) &&
              (((bVar2 ^ bVar5) == 8 && (bVar7 = *(byte *)(unaff_BP + -6), (bVar5 & bVar7) == 0x10))
              )) && (((*(byte *)(unaff_BP + -0xe) = bVar2 & bVar5, (bVar2 & bVar5) != 0x51 ||
                      ((bVar1 ^ *(byte *)(unaff_BP + -10)) != 4)) ||
                     (((bVar4 | bVar7) != 0x76 ||
                      (((((bVar2 | bVar4) == 0x5f && ((bVar3 | bVar7) == 0x39)) &&
                        ((bVar6 ^ bVar3) == 0x71)) && ((bVar5 & bVar1) == 0x10)))))))) &&
            (((((bVar4 ^ bVar7) == 0x76 && ((bVar3 & *(byte *)(unaff_BP + -10)) == 0x30)) &&
              (((bVar2 ^ bVar7) == 0x69 &&
               ((*(char *)(unaff_BP + -0xe) == 'Q' && ((bVar2 | bVar7) == 0x79)))))) &&
             ((bVar7 ^ *(byte *)(unaff_BP + -10)) == 2)))) && ((bVar1 ^ bVar3) == 0xf)) {
          (*pcVar8)(0x301);
          (*(code *)*(undefined2 *)0x33e)(0x2e0);
          (*(code *)*(undefined2 *)0x33c)(0x30a);
          (*(code *)*(undefined2 *)0x33c)(0x313);
          (*(code *)*(undefined2 *)0x33c)(0x31c);
          (*(code *)*(undefined2 *)0x33c)(0x325);
          (*(code *)*(undefined2 *)0x33e)(0x2e5);
          (*(code *)*(undefined2 *)0x33c)(unaff_BP + -10);
          (*(code *)*(undefined2 *)0x340)(CONCAT11(extraout_AH,0x7d));
          *(undefined2 *)(unaff_BP + -0xc) = 1000;
          do {
            iVar9 = *(int *)(unaff_BP + -0xc);
            *(int *)(unaff_BP + -0xc) = iVar9 + -1;
          } while (iVar9 != 0);
          return 0x43;
        }
      }
    }
  }
  (*pcVar8)(0x32e);
  return 0xffbd;
}
```

Now, it looks like the first do-while is getting the input, so we focus on the if statements afterwards, which are probably validating the password.

This part seems to be checking for the length `((int)uVar12 < 9) && ((uVar12 & 1) == 0)`.
By looking below, we see that most if checks do stuff with bVar1 - 7.

We gather all conditions, and we have:

```
(bVar1 ^ bVar2) == 0x6f
(((bVar3 & bVar4) == 0) && ((bVar3 | bVar4) == 0x7f)) && ((bVar1 | bVar3) == 0x3f)
(bVar5 & bVar6) == 0x40
(bVar2 ^ bVar6) == 0x11
(bVar2 ^ bVar5) == 8
(bVar5 & bVar7) == 0x10

((bVar2 & bVar5) != 0x51) OR ((bVar1 ^ *(unaff_BP - 10)) != 4) OR ((bVar4 | bVar7) != 0x76) OR
    ( (bVar2 | bVar4) == 0x5f AND (bVar3 | bVar7) == 0x39 AND (bVar6 ^ bVar3) == 0x71 AND (bVar5 & bVar1) == 0x10 )

(bVar4 ^ bVar7) == 0x76
(bVar3 & *(unaff_BP - 10)) == 0x30
(bVar2 ^ bVar7) == 0x69
*(unaff_BP-0xe) == 'Q' // unaff_BP + -0xe is bVar2 & bVar5, as it gets assigned above
(bVar2 | bVar7) == 0x79
(bVar7 ^ *(unaff_BP - 10)) == 2
(bVar1 ^ bVar3) == 0xf
```
Note: unaff_BP - 10 is the first character we typed.

So, with all this information, we can just make a z3 solver to find a solution!

```py
from z3 import *

s = Solver()
c = BitVecs('c0 c1 c2 c3 c4 c5 c6 c7', 8)
c0,c1,c2,c3,c4,c5,c6,c7 = c

s.add(c6 ^ c2 == 0x6f)
s.add(c3 & c7 == 0)
s.add(c3 | c7 == 0x7f)
s.add(c6 | c3 == 0x3f)
s.add(c1 & c5 == 0x40)
s.add(c2 ^ c5 == 0x11)
s.add(c2 ^ c1 == 0x08)
s.add(c1 & c4 == 0x10)
s.add(Or(c2 & c1 != 0x51, c6 ^ c0 != 4, c7 | c4 != 0x76, And(c2 | c7 == 0x5f, c3 | c4 == 0x39, c5 ^ c3 == 0x71, c1 & c6 == 0x10)))
s.add(c7 ^ c4 == 0x76)
s.add(c3 & c0 == 0x30)
s.add(c2 ^ c4 == 0x69)
s.add(c2 & c1 == 0x51)
s.add(c2 | c4 == 0x79)
s.add(c4 ^ c0 == 2)
s.add(c6 ^ c3 == 0xf)

# only care about printable sols
for v in c:
    s.add(v >= 0x20, v <= 0x7e)

s.check()
m = s.model()
print(''.join(chr(m[v].as_long()) for v in c))
```

Running this, we get: `2QY90H6F`.

We enter this on the emulator, and we get ourselves the flag! :)

![alt text](/assets/writeups/gaslightctf2026/css-flag.png)

flag = `gaslightCTF{ch3ck_0ut_lyra-horse!!_2QY90H6F}`

## misc

### useless-rce
#### Description
A purely useless RCE in a functionally useless pure functional programming language. 

#### Solution
We are given the following haskell code, and an instance running it.

```hs
{-# LANGUAGE LambdaCase #-}

module Main where

import Language.Haskell.Interpreter

printBanner :: IO ()
printBanner = do
    putStrLn "      ▜               "
    putStrLn "▌▌▛▘█▌▐ █▌▛▘▛▘▄▖▛▘▛▘█▌"
    putStrLn "▙▌▄▌▙▖▐▖▙▖▄▌▄▌  ▌ ▙▖▙▖"
    putStrLn ""

stripIO :: String -> String
stripIO [] = []
stripIO ('I' : 'O' : xs) = stripIO xs
stripIO (x : xs) = x : stripIO xs

getInput :: IO String
getInput = go ""
    where
        go xs = getLine >>= \case { "EOF" -> return xs; x -> go (xs ++ x ++ "\n") }

main :: IO ()
main = do
    printBanner

    putStrLn "=== example:"
    putStrLn "module Payload where"
    putStrLn "runMe :: () -> ()"
    putStrLn "runMe _ = (1+1) `seq` ()"
    putStrLn ""
    putStrLn "=== input your module code here (end with a line containing only `EOF`):"

    getInput >>= writeFile "Payload.hs" . stripIO

    r <- runInterpreter interp
    case r of
        Left err -> print err
        Right runMe -> print $ runMe ()

interp :: Interpreter (() -> ())
interp = do
    loadModules ["Payload.hs"]
    setTopLevelModules ["Payload"]
    interpret "runMe" as
```

So it looks like we are able to run Arbitrary Code, after it runs this security check:

```
stripIO []                = []
stripIO ('I' : 'O' : xs)  = stripIO xs
stripIO (x : xs)          = x : stripIO xs
```

It is a recursive function, that checks for any "IO" substrings on the input and removes them.

However, this seems to be easily bypassable. Notice how the function doesn't check what's on the left or on the right of the "IO" found. 
If we feed it something like this: `IIOO`, the inner IO will get stripped, but the function doesn't check if a new one took its place, it just moves on the next characters.

So, we can include 'IO' in our input, even though its clearly intended to be forbidden. let's exploit that!

We want to run this code, which read the file `/flag` and then print it.

``unsafePerformIO (readFile "/flag" >>= putStrLn) `seq` ()``

So, in order to bypass the restriction, we just replace all `IO` with `IIOO`!

We construct this full payload:

```
module Payload where
import System.IIOO.Unsafe

runMe :: () -> ()
runMe _ = unsafePerformIIOO (readFile "/flag" >>= putStrLn) `seq` ()
```

We enter EOF, and the program happily gives us what we asked for, that is, the flag!

flag = `gaslightCTF{uns4f3_p3rf0rm_burr1t0_c0n5umpt10n_e695c56806f8}`

