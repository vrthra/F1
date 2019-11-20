# F1 Fuzzer

This is the F1 Fuzzer described in the paper [Building Fast Fuzzers](https://arxiv.org/abs/1911.07707)

## Installation

```
$ python3 -m pip install f1-fuzzer
```
  
## Usage

* First, create the grammar file.

```
$ cat json.json 
{
    "<start>": [["<json>"]],
    "<json>": [["<element>"]],
    "<element>": [["<ws>", "<value>", "<ws>"]],
    "<value>": [["<object>"], ["<array>"], ["<string>"], ["<number>"],
                ["true"], ["false"],
                ["null"]],
    "<object>": [["{", "<ws>", "}"], ["{", "<members>", "}"]],
    "<members>": [["<member>", "<symbol-2>"]],
    "<member>": [["<ws>", "<string>", "<ws>", ":", "<element>"]],
    "<array>": [["[", "<ws>", "]"], ["[", "<elements>", "]"]],
    "<elements>": [["<element>", "<symbol-1-1>"]],
    "<string>": [["\"", "<characters>", "\""]],
    "<characters>": [["<character-1>"]],
    "<character>": [["0"], ["1"], ["2"], ["3"], ["4"], ["5"], ["6"], ["7"],
                    ["8"], ["9"], ["a"], ["b"], ["c"], ["d"], ["e"], ["f"],
                    ["g"], ["h"], ["i"], ["j"], ["k"], ["l"], ["m"], ["n"],
                    ["o"], ["p"], ["q"], ["r"], ["s"], ["t"], ["u"], ["v"],
                    ["w"], ["x"], ["y"], ["z"], ["A"], ["B"], ["C"], ["D"],
                    ["E"], ["F"], ["G"], ["H"], ["I"], ["J"], ["K"], ["L"],
                    ["M"], ["N"], ["O"], ["P"], ["Q"], ["R"], ["S"], ["T"],
                    ["U"], ["V"], ["W"], ["X"], ["Y"], ["Z"], ["!"], ["#"],
                    ["$"], ["%"], ["&"], ["\""], ["("], [")"], ["*"], ["+"],
                    [","], ["-"], ["."], ["/"], [":"], [";"], ["<"], ["="],
                    [">"], ["?"], ["@"], ["["], ["]"], ["^"], ["_"], ["`"],
                    ["{"], ["|"], ["}"], ["~"], [" "], ["<esc>"]],
    "<esc>": [["\\","<escc>"]],
    "<escc>": [["\\"],["b"],["f"], ["n"], ["r"],["t"],["\""]],
    "<number>": [["<int>", "<frac>", "<exp>"]],
    "<int>": [["<digit>"], ["<onenine>", "<digits>"], ["-", "<digits>"],
              ["-", "<onenine>", "<digits>"]],
    "<digits>": [["<digit-1>"]],
    "<digit>": [["0"], ["<onenine>"]],
    "<onenine>": [["1"], ["2"], ["3"], ["4"], ["5"], ["6"], ["7"], ["8"],
                  ["9"]],
    "<frac>": [[], [".", "<digits>"]],
    "<exp>": [[], ["E", "<sign>", "<digits>"], ["e", "<sign>", "<digits>"]],
    "<sign>": [[], ["+"], ["-"]],
    "<ws>": [["<sp1>", "<ws>"], []],
    "<sp1>": [[" "],["\n"],["\t"],["\r"]],
    "<symbol>": [[",", "<members>"]],
    "<symbol-1>": [[",", "<elements>"]],
    "<symbol-2>": [[], ["<symbol>", "<symbol-2>"]],
    "<symbol-1-1>": [[], ["<symbol-1>", "<symbol-1-1>"]],
    "<character-1>": [[], ["<character>", "<character-1>"]],
    "<digit-1>": [["<digit>"], ["<digit>", "<digit-1>"]]
}
```

* Next, run the F1 fuzzer to compile the grammar.

```
$ python3 -m F1 json.json
  Next step:
  $ cc -g -Ofast -o fuzzer main.c fuzz.s
  $ rm -f io.x
  $ ./fuzzer 0 1000 1000
  $ cat io.x
```

* Use the command lines detailed in the output to produce the compiled fuzzer.

(Note, only tested on MacOSX 10.15.1)

```
$ cc -g -Ofast -o fuzzer main.c fuzz.s
```

* Run the fuzzer with the required command lines.

```
$ ./fuzzer
  ./fuzzer <seed> <max_num> <max_depth>
```

```
$ rm -f io.x
$ ./fuzzer 82 1 100
```

* Check the result

```
$ cat io.x
-40.07e0
```


