import F1
import sys
import json
import os
def main():
    if len(sys.argv) < 2:
        print('''
Usage: python -m F1 <grammar.json>
                ''')
        sys.exit(1)
    gfile = sys.argv[1]
    with open(gfile) as gf:
        fc = gf.read()
        my_grammar = json.loads(fc)
    c_grammar = F1.CTrans(my_grammar).translate()
    l = F1.LlvmIRFuzzer(c_grammar).fuzz_src()
    with open('fuzz.ll', 'w') as f:
        print(l, file=f)

    uname = os.uname()
    print('\nNext step:')
    if uname.sysname == "Darwin":
        print('$ clang -o fuzzer fuzz.ll')
    elif uname.sysname == "Linux":
        print('$ clang -o fuzzer fuzz.ll')
    print('''$ rm -f io.x
$ ./fuzzer > io.x
$ cat io.x
''')

main()
