import F1
import sys
import json
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
    vm_ops, main_src, fuzz_src = F1.CFWriteCTFuzzer(c_grammar).fuzz_src()

    with open('vm_ops.s', 'w+') as f:
        print(vm_ops, file=f)

    with open('fuzz.s', 'w+') as f:
        print(fuzz_src, file=f)

    with open('main.c', 'w+') as f:
        print(main_src, file=f)

    print('''\
Next step:
$ cc -g -Ofast -o fuzzer main.c fuzz.s
$ rm -f io.x
$ ./fuzzer 0 1000 1000
$ cat io.x
''')

main()
