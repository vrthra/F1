# F1 Fuzzer

This is the F1 Fuzzer described in the paper [Building Fast Fuzzers](https://arxiv.org/abs/1911.07707).

If you use F1 in a production setting, if you found bugs with it (yay!), or if
you have any suggestions to share, please let us know – your experience is very
valuable for us.  Thanks!


### List of changes made to the sourcecode to make it run on Linux systems - ###
- Requires clang as compiler to work in Linux
- "stdint.h" header included in main.c
- fuzz\_src is written to fuzz.S instead of fuzz.s
- Compiled in Linux using "clang -g -Ofast -mcmodel=medium  -o fuzzer main.c fuzz.S"
  while MacOS compiles using "cc -g -Ofast -o fuzzer main.c fuzz.S"
- stackp's array size is INT\_MAX/100 in Linux (INT\_MAX in MacOS)
- out\_region\_initp's arraysize is UINT\_MAX/100 (UINT\_MAX in MacOS)
- all contents of ".section  __DATA,__data" is moved to ".text" section in vm\_ops.s


### llvm IR code from grammars - ###

To execute any of the handwritten IR files (`basic_handwritten_gram.ll` or `slightly_complex_handwritten_gram.ll`), just run `make` inside the F1 directory. This generates two executables - `basic` and `complex` respectively.


To generate an IR file corresponding to any grammar, please run `python3 main.py <grammarfile>`.
The next steps are printed on the terminal.