import itertools
import sys
import random
import os

class Sanitize:
    def __init__(self, g):
        self.g = g

    def to_key(self, k):
        s = k.replace('-', '_')
        s = s.replace('[', 'Osq').replace(']','Csq')
        s = s.replace('{','Obr').replace('}','Cbr')
        s = s.replace('import','XimportX')
        s = s.replace('class', 'XclassX')
        s = s.replace('def', 'XdefX')
        return s

    def to_token(self, t):
        return t

    def split_tokens(self, t, grammar):
        if t in grammar: return [t]
        my_tokens = []
        # these should not matter for performance comparisons,
        # and makes my life simpler
        esc = {'\r': '\r', '\n': '\n',
             '\\': '\\',
             '"':'"',
             "'":"'"}
        for i in t:
            if i in esc:
                my_tokens.append(esc[i])
            else:
                my_tokens.append(i)
        return my_tokens

        return list(t)

    def to_rule(self, rule, grammar):
        tokens = [k for t in rule for k in self.split_tokens(t, grammar)]
        return [self.to_token(t) if t not in grammar else self.to_key(t)
                for t in tokens]

    def translate(self):
        new_grammar = {}
        for k in self.g:
            rules = self.g[k]
            new_grammar[self.to_key(k)] = [self.to_rule(rule, self.g) for rule in rules]
        return new_grammar

class CTrans(Sanitize):
    def split_tokens(self, t, grammar):
        if t in grammar: return [t]
        my_tokens = []
        esc = {
           '\r': '\\r',
           '\n': '\\n',
           '\t': '\\t',
           '\\': '\\\\',
        }
        for i in t:
            #if i in esc:
            #    my_tokens.append(esc[i])
            #else:
                my_tokens.append(i)
        return my_tokens

class Fuzzer:
    def __init__(self, grammar):
        self.grammar = grammar
        self.system_name = os.uname().sysname # expect "Darwin" and "Linux"

    def fuzz(self, key='<start>', max_num=None, max_depth=None):
        raise NotImplemented()

class LimitFuzzer(Fuzzer):
    def symbol_cost(self, grammar, symbol, seen):
        if symbol in self.key_cost: return self.key_cost[symbol]
        if symbol in seen:
            self.key_cost[symbol] = float('inf')
            return float('inf')
        v = min((self.expansion_cost(grammar, rule, seen | {symbol})
                    for rule in grammar.get(symbol, [])), default=0)
        self.key_cost[symbol] = v
        return v

    def expansion_cost(self, grammar, tokens, seen):
        return max((self.symbol_cost(grammar, token, seen)
                    for token in tokens if token in grammar), default=0) + 1


class LimitFuzzer(LimitFuzzer):
    def gen_key(self, key, depth, max_depth):
        if key not in self.grammar: return key
        if depth > max_depth:
            clst = sorted([(self.cost[key][str(rule)], rule) for rule in self.grammar[key]])
            rules = [r for c,r in clst if c == clst[0][0]]
        else:
            rules = self.grammar[key]
        return self.gen_rule(random.choice(rules), depth+1, max_depth)

    def gen_rule(self, rule, depth, max_depth):
        return ''.join(self.gen_key(token, depth, max_depth) for token in rule)

    def fuzz(self, key='<start>', max_depth=10):
        return self.gen_key(key=key, depth=0, max_depth=max_depth)


class LimitFuzzer(LimitFuzzer):
    def __init__(self, grammar):
        super().__init__(grammar)
        self.key_cost = {}
        self.cost = self.compute_cost(grammar)

    def compute_cost(self, grammar):
        cost = {}
        for k in grammar:
            cost[k] = {}
            for rule in grammar[k]:
                cost[k][str(rule)] = self.expansion_cost(grammar, rule, set())
        return cost


# A non recursive version.
class LimitFuzzer_NR(LimitFuzzer):
    def is_nt(self, name):
        return (name[0], name[-1]) == ('<', '>')

    def tree_to_str(self, tree):
        name, children = tree
        if not self.is_nt(name): return name
        return ''.join([self.tree_to_str(c) for c in children])

    def nonterminals(self, rule):
        return [t for t in rule if self.is_nt(t)]

    def gen_key(self, key, max_depth):
        def get_def(t):
            if self.is_nt(t):
                return [t, None]
            else:
                return [t, []]

        cheap_grammar = {}
        for k in self.cost:
            # should we minimize it here? We simply avoid infinities
            rules = self.grammar[k]
            min_cost = min([self.cost[k][str(r)] for r in rules])
            #grammar[k] = [r for r in grammar[k] if self.cost[k][str(r)] == float('inf')]
            cheap_grammar[k] = [r for r in self.grammar[k] if self.cost[k][str(r)] == min_cost]

        root = [key, None]
        queue = [(0, root)]
        while queue:
            # get one item to expand from the queue
            (depth, item), *queue = queue
            key = item[0]
            if item[1] is not None: continue
            grammar = self.grammar if depth < max_depth else cheap_grammar
            chosen_rule = random.choice(grammar[key])
            expansion = [get_def(t) for t in chosen_rule]
            item[1] = expansion
            for t in expansion: queue.append((depth+1, t))
            #print("Fuzz: %s" % key, len(queue), file=sys.stderr)
        #print(file=sys.stderr)
        return root

    def fuzz(self, key='<start>', max_depth=10):
        return self.tree_to_str(self.gen_key(key=key, max_depth=max_depth))

class PooledFuzzer(LimitFuzzer):
    def compute_cost(self, grammar, cost={}):
        return {k:sorted([(self.expansion_cost(grammar, rule, set()), rule)
                          for rule in grammar[k]])
                for k in self.grammar}


class PooledFuzzer(PooledFuzzer):
    def cheap_grammar(self):
        new_grammar = {}
        for k in self.cost:
            crules = self.cost[k]
            min_cost = crules[0][0]
            new_grammar[k] = [r for c,r in crules if c == min_cost]
            assert len(new_grammar[k]) > 0
        return new_grammar


class PooledFuzzer(PooledFuzzer):
    def get_strings_for_key(self, grammar, key='<start>'):
        if key not in grammar: return [key]
        v = sum([self.get_strings_for_rule(grammar, rule)
                 for rule in grammar[key]], [])
        return random.sample(v, min(self.MAX_SAMPLE, len(v)))

    def get_strings_for_rule(self, grammar, rule):
        my_strings_list = [self.get_strings_for_key(grammar, key) for key in rule]
        v = [''.join(l) for l in itertools.product(*my_strings_list)]
        return random.sample(v, min(self.MAX_SAMPLE, len(v)))

    def completion_strings(self):
        # we are being choosy
        return {k:self.get_strings_for_key(self.c_grammar, k)
                for k in self.c_grammar}

class PooledFuzzer(PooledFuzzer):
    def __init__(self, grammar):
        super().__init__(grammar)
        self.c_grammar = self.cheap_grammar()
        self.MAX_SAMPLE = 255
        self.pool_of_strings = self.completion_strings()
        # reorder our grammar rules by cost.
        for k in self.grammar:
            self.grammar[k] = [r for (i,r) in self.cost[k]]
        self.ordered_grammar = True

    def gen_key(self, key, depth, max_depth):
        if key not in self.grammar: return key
        if depth > max_depth:
            return random.choice(self.pool_of_strings[key])
        return self.gen_rule(random.choice(self.grammar[key]), depth+1, max_depth)


# not clear what is the fastest: + or ''.join
# https://stackoverflow.com/questions/1316887/what-is-the-most-efficient-string-concatenation-method-in-python
class PyCompiledFuzzer(PooledFuzzer):
    def add_indent(self, string, indent):
        return '\n'.join([indent + i for i in string.split('\n')])

    # used for escaping inside strings
    def esc(self, t):
        t = t.replace('\\', '\\\\')
        t = t.replace('\n', '\\n')
        t = t.replace('\r', '\\r')
        t = t.replace('\t', '\\t')
        t = t.replace('\b', '\\b')
        t = t.replace('\v', '\\v')
        t = t.replace('"', '\\"')
        return t

    def esc_char(self, t):
        assert len(t) == 1
        t = t.replace('\\', '\\\\')
        t = t.replace('\n', '\\n')
        t = t.replace('\r', '\\r')
        t = t.replace('\t', '\\t')
        t = t.replace('\b', '\\b')
        t = t.replace('\v', '\\v')
        t = t.replace("'", "\\'")
        return t

    def k_to_s(self, k): return k[1:-1].replace('-', '_')

    def gen_rule_src(self, rule, key, i):
        res = []
        for token in rule:
            if token in self.grammar:
                res.append('''\
gen_%s(next_depth, max_depth)''' % self.k_to_s(token))
            else:
                res.append('''\
result.append("%s")''' % self.esc(token))
        return '\n'.join(res)

    def string_pool_defs(self):
        result =[]
        for k in self.pool_of_strings:
            result.append('''\
pool_of_%(key)s = %(values)s''' % {
                'key':self.k_to_s(k),
                'values': self.pool_of_strings[k]})
        result.append('''
result = []''')
        return '\n'.join(result)

    def gen_main_src(self):
        result = []
        result.append('''
import random
import sys
def main(args):
    global result
    max_num, max_depth = get_opts(args)
    for i in range(max_num):
        gen_start(0, max_depth)
        print(''.join(result))
        result = []

main(sys.argv)''')
        return '\n'.join(result)

    def gen_alt_src(self, key):
        rules = self.grammar[key]
        result = []
        result.append('''
def gen_%(name)s(depth, max_depth):
    next_depth = depth + 1
    if depth > max_depth:
        result.append(random.choice(pool_of_%(name)s))
        return
    val = random.randrange(%(nrules)s)''' % {
            'name':self.k_to_s(key),
            'nrules':len(rules)})
        for i, rule in enumerate(rules):
            result.append('''\
    if val == %d:
%s
        return''' % (i, self.add_indent(self.gen_rule_src(rule, key, i),'        ')))
        return '\n'.join(result)

    def gen_fuzz_src(self):
        result = []
        result.append(self.string_pool_defs())
        for key in self.grammar:
            result.append(self.gen_alt_src(key))
        return '\n'.join(result)

    def fuzz_src(self, key='<start>'):
        result = [self.gen_fuzz_src(),
                  self.gen_main_src()]
        return ''.join(result)
class PyRecCompiledFuzzer(PyCompiledFuzzer):
    def __init__(self, grammar):
        super().__init__(grammar)
        assert self.ordered_grammar
        self.rec_cost = {}
        self.compute_rule_recursion()

    def kr_to_s(self, key, i): return 'gen_%s_%d' % (self.k_to_s(key), i)
    # the grammar needs to be ordered by the cost.
    # else the ordering will change at the end.

    def is_rule_recursive(self, rname, rule, seen):
        if not rule: return False
        if rname in seen:
            return False # reached another recursive rule without seeing this one
        for token in rule:
            if token not in self.grammar: continue
            for i,trule in enumerate(self.grammar[token]):
                rn = self.kr_to_s(token, i)
                if rn  == rname: return True
                if rn in seen: return False
                v = self.is_rule_recursive(rname, trule, seen | {rn})
                if v: return True
        return False

    def is_key_recursive(self, check, key, seen):
        if not key in self.grammar: return False
        if key in seen: return False
        for rule in self.grammar[key]:
            for token in rule:
                if token not in self.grammar: continue
                if token == check: return True
                v = self.is_key_recursive(check, token, seen | {token})
                if v: return True
        return False

    def compute_rule_recursion(self):
        self.rule_recursion = {}
        for k in self.grammar:
            for i_rule,rule in enumerate(self.grammar[k]):
                n = self.kr_to_s(k, i_rule)
                self.rule_recursion[n] = self.is_rule_recursive(n, rule, set())
        self.key_recursion = {}
        for k in self.grammar:
            self.key_recursion[k] = self.is_key_recursive(k, k, set())

class LlvmIRFuzzer(PyRecCompiledFuzzer):
    header = '''; -> the semi-colon is the character to start a one-line comment
@.newline = private unnamed_addr constant [2 x i8] c"\\0A\\00", align 1 ; @.newline = '\\n'
declare i32 @printf(i8*, ...) ; declare cstdio's printf\n\n'''

    global_data_structures = '''@max_depth = global i32 50, align 4 ; (global) int max_depth = 50;
@depth = global i32 0, align 4 ; (global) int depth;
@rarr = internal global [4 x i64] [i64 13343, i64 9838742, i64 223185, i64 802124], align 16 ; static uint64_t rarr[4] = {13343, 9838742, 223185, 802124};
@rand_region_initp = common global [65536 x i8] zeroinitializer, align 16 ; uint8_t rand_region_initp[1ULL << 16];
@rand_regionp = global i8* getelementptr inbounds ([65536 x i8], [65536 x i8]* @rand_region_initp, i32 0, i32 0), align 8 ; uint8_t* rand_regionp = rand_region_initp;
@rand_region_sizep = global i8* null, align 8 ; uint8_t* rand_region_sizep = 0;\n\n'''

    map_fn = '''; This implements the random Integer Multiplication (Biased) method from  https://www.pcg-random.org/posts/bounded-rands.html
define zeroext i8 @map(i8 zeroext %range) alwaysinline {
    %rrp = load i8*, i8** @rand_regionp, align 8 ; uint8_t rrp = rand_regionp
    %from = load i8, i8* %rrp, align 8 ; uint8_t from = *rand_regionp
    %increment = getelementptr inbounds i8, i8* %rrp, i32 1 ; *increment = rrp+1
    store i8* %increment, i8** @rand_regionp, align 8 ; rand_regionp = increment
    %rrsp_ref = load i8*, i8** @rand_region_sizep, align 8 ;rrsp_ref is local reference of rand_region_sizep
    %comp = icmp uge i8* %increment, %rrsp_ref; is increment(=rand_regionp) >= rrsp_ref(=rand_region_sizep)
    br i1 %comp, label %reset_rand_regionp, label %return; branch jump to %reset_rand_regionp if true, to %return otherwise

  reset_rand_regionp:
    ;rand_regionp = rand_region_initp
    store i8* getelementptr inbounds ([65536 x i8], [65536 x i8]* @rand_region_initp, i64 0, i64 0), i8** @rand_regionp, align 8
    br label %return; branch jump to %label

  return:
    %ext_from = zext i8 %from to i16 ; ext_from = (uint16_t) from
    %ext_range = zext i8 %range to i16 ; ext_range = (uint16_t) range
    %product = mul nsw i16 %ext_from, %ext_range; product = ext_from * ext_range
    %product_ashr =  ashr i16 %product, 8; product_ashr = product >> 8
    %trunc_ashr = trunc i16 %product_ashr to i8; trunc_ashr = (uint8_t) %product_ashr
    ret i8 %trunc_ashr ; return trunc_ashr
}\n\n'''

    rotl_fn = '''define internal i64 @rotl(i64 %x, i64 %k) { ;static inline uint64_t rotl(const uint64_t x, uint64_t k)
  %lsx = shl i64 %x, %k; lsx = (x << k)
  %kdiff = sub nsw i64 64, %k; kdiff = 64 - k
  %rsx = lshr i64 %x, %kdiff; rsx = x >> kdiff
  %or_op = or i64 %lsx, %rsx; or_op = lsx | rsx
  ret i64 %or_op
}\n\n'''

    next_fn = '''define i64 @next() {
  %rarr0 = load i64, i64* getelementptr inbounds ([4 x i64], [4 x i64]* @rarr, i64 0, i64 0), align 8 ; rarr0 = rarr[0]
  %rarr1 = load i64, i64* getelementptr inbounds ([4 x i64], [4 x i64]* @rarr, i64 0, i64 1), align 8 ; rarr1 = rarr[1]
  %rarr2 = load i64, i64* getelementptr inbounds ([4 x i64], [4 x i64]* @rarr, i64 0, i64 2), align 8 ; rarr2 = rarr[2]
  %rarr3 = load i64, i64* getelementptr inbounds ([4 x i64], [4 x i64]* @rarr, i64 0, i64 3), align 8 ; rarr3 = rarr[3]

  %r1_5 = mul i64 %rarr1, 5 ; %r1_5 = rarr1*5
  %rotl_res = call i64 @rotl(i64 %r1_5, i64 7) ; rotl_res = rotl(r1_5, 7)
  %result_starstar = mul i64 %rotl_res, 9 ; result_starstar = rotl_res*9
  %t = shl i64 %rarr1, 17 ; t = rarr1 << 17

  %intermediate_rarr2 = xor i64 %rarr2, %rarr0 ; intermediate_rarr2 = rarr2^rarr0
  %intermediate_rarr3 = xor i64 %rarr3, %rarr1 ; intermediate_rarr3 = rarr3^rarr1

  %new_rarr1 = xor i64 %rarr1, %intermediate_rarr2 ; new_rarr1 = rarr1^rarr[2]
  %new_rarr0 = xor i64 %rarr0, %intermediate_rarr3 ; new_rarr0 = rarr0^rarr[3]
  %new_rarr2 = xor i64 %intermediate_rarr2, %t; new_rarr0 = intermediate_rarr2^t
  %new_rarr3 = call i64 @rotl(i64 %intermediate_rarr3, i64 45) ; rotl_res = rotl(r1_5, 7)

  store i64 %new_rarr0, i64* getelementptr inbounds ([4 x i64], [4 x i64]* @rarr, i64 0, i64 0), align 8; rarr[0] = new_rarr0
  store i64 %new_rarr1, i64* getelementptr inbounds ([4 x i64], [4 x i64]* @rarr, i64 0, i64 1), align 8; rarr[1] = new_rarr1
  store i64 %new_rarr2, i64* getelementptr inbounds ([4 x i64], [4 x i64]* @rarr, i64 0, i64 2), align 8; rarr[2] = new_rarr2
  store i64 %new_rarr3, i64* getelementptr inbounds ([4 x i64], [4 x i64]* @rarr, i64 0, i64 3), align 8; rarr[3] = new_rarr3

  ret i64 %result_starstar
}\n\n'''

    initialise_random_fn = '''; an alternate way will be replacing the call to next() in the "loop" label with its code
define void @initialise_random(i64 %max_size) {
    %arr_8 = load i8*, i8** @rand_regionp, align 8
    %arr = bitcast i8* %arr_8 to i64*
    %i_pointer = alloca i64, align 4 ; loop variable pointer on stack
    store i64 0, i64* %i_pointer, align 8; *i_pointer=0
    %upper_limit = udiv i64 %max_size, 8 ;upper_limit = max_size/8 (because we have 8 bytes)
    br label %loop_check

  loop_check:
    %i = load i64, i64* %i_pointer, align 8 ; load the value of i_pointer into variable i
    %comp_result = icmp ult i64 %i, %upper_limit ; check if i < max_size/8
    br i1 %comp_result, label %loop, label %breakout ; jump to label loop if yes, to breakout otherwise

  loop:
    %result_starstar = call i64 @next() ; result_starstar = next()
    %mem_addr = getelementptr inbounds i64, i64* %arr, i64 %i ; getting arr[i]
    store i64 %result_starstar, i64*%mem_addr, align 8
    br label %update_i

  update_i:
    %new_i = add i64 %i, 1
    store i64 %new_i, i64* %i_pointer, align 8
    br label %loop_check

  breakout:
    ; we already have the addresses of arr in %arr and i in %i (from loop_check)
    %new_addr = getelementptr inbounds i64, i64* %arr, i64 %i ; arr + i
    %new_addr_8 = bitcast i64* %new_addr to i8* ; new_addr_8 = (uint8_t*) (new_addr);
    store i8* %new_addr_8, i8** @rand_region_sizep, align 8
    ret void
}\n\n'''

    init_fn = '''define void @gen_init__(){ ; gen_init__ procedure
  store i32 0, i32* @depth, align 4 ; initialise (global) depth = 0
  call void @gen_start() ; calling gen_start()
  ; printf(@.newline)
  call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([2 x i8], [2 x i8]* @.newline, i64 0, i64 0))
  ret void ; return void
}\n\n'''

    main_fn = '''define i32 @main(){
    call void @initialise_random(i64 65536) ; initialise_random(rand_region_size);
    %i_pointer = alloca i32, align 4 ; loop variable pointer on stack
    store i32 0, i32* %i_pointer, align 4 ;write i = 0 to memory
    %seed_location = alloca i32, align 4 ; pointer to seed on stack
    store i32 0, i32* %seed_location, align 4 ; write seed = 0 to memory
    %seed = load i32, i32* %seed_location, align 4 ; load seed's value into a variable
    ; an alternative to previous 3 lines is to invoke the next getelementptr with 0, if seed is fixed
    %rrp = load i8*, i8** @rand_regionp, align 8 ; local reference to rand_regionp
    %new_rrp = getelementptr inbounds i8, i8* %rrp, i32 %seed ; new_rrp = rrp + seed
    store i8* %rrp, i8** @rand_regionp, align 8 ; rand_regionp = new_rrp
    %max_loop_p = alloca i32, align 4 ; maximum possible value of loop variable pointer on stack
    store i32 50, i32* %max_loop_p, align 4 ; write max_loop = 50 to memory
    br label %comparision_check; branch jump to comparision_check

  comparision_check:
    ; load the value of i_pointer into variable i
    %i = load i32, i32* %i_pointer, align 4
    ; load the value of max_loop_p into variable max_num (an alternative is compare directly to 10, if max_num is fixed)
    %max_num = load i32, i32* %max_loop_p, align 4
    %comp_result1 = icmp slt i32 %i, %max_num ; comp_result1 = true if i < max_num, false otherwise
    ;branch jump to call_gen_init__ if comp_result1 is true, jump to return_block otherwise
    br i1 %comp_result1, label %call_gen_init__, label %return_block

  call_gen_init__:
    call void @gen_init__() ; invoke gen_init__()
    %i_new = add nsw i32 %i, 1 ; update i(new) = i + 1
    store i32 %i_new, i32* %i_pointer, align 4; write updated i to memory
    br label %comparision_check

  return_block:
    ret i32 0
}'''

    randomising_fns = [map_fn, rotl_fn, next_fn, initialise_random_fn]

    def __init__(self, grammar):
        super().__init__(grammar)
        self.create_IR_grammar()

    # we need this because llvm IR defines all strings as globals
    # to keep track of which string turns up in which rule, in which
    # position in the expansion
    def create_IR_grammar(self):
        self.IR_gram_dict = dict()
        for k,v in self.grammar.items():
            self.IR_gram_dict[k] = {}
            counter = 0
            for i, expnsn in enumerate(v):
                vlist = []
                key = 'fe_' + self.k_to_s(k) +'.'+ str(i) + '.' + str(counter)
                s = ''
                for stri in expnsn:
                    if len(stri) == 1: # it is a character and not a non-terminal
                        s += stri
                    else: # it is a non-terminal of the structure "<[string.printable]+>"
                        if len(s) > 0:
                            counter +=1
                            vlist.append((key, s)) # key, value tuple. will use this key to name strings in IR
                        vlist.append(stri) # non-terminal
                        s = '' # new string again
                        key = 'fe_' + self.k_to_s(k) +'.'+ str(i) + '.' + str(counter) # new key
                if len(s) > 0:
                    vlist.append((key, s)) # when the expnsn ends and there's still string left.
                self.IR_gram_dict[k][i] = vlist

    def get_short_expnsns(self):
        res = ""
        pool_str = ""
        for k,v in self.pool_of_strings.items():
            name = self.k_to_s(k)
            pool_str += f"@pool_{name} = global [{len(v)} x i8*] ["
            for i in range(len(v)):
                res += f"@.{name}.{i} = private unnamed_addr constant [{len(v[i])+ 1} x i8] c\"{v[i]}\\00\", align 1\n"
                pool_str += f"i8* getelementptr inbounds ([{len(v[i]) +1} x i8], [{len(v[i]) +1} x i8]* @.{name}.{i}, i32 0, i32 0)"
                if i < len(v)-1:
                    pool_str += ", "
            pool_str += f"], align 16 ; pool of shortest expn strings from {k}\n"
        res += '\n'
        res += pool_str
        res += '\n'
        for v in self.IR_gram_dict.values():
            for rule in v.values():
                for expnsn in rule:
                    if type(expnsn) is tuple: #contains a identifier, string tuple
                        res += f"@.{expnsn[0]} = private unnamed_addr constant [{len(expnsn[1])+ 1} x i8] c\"{expnsn[1]}\\00\", align 1\n"
        return res

    def gen_rule_src(self, rule, key, i):
        res = []
        for token in rule:
            if type(token) is tuple: # token[0] = IR name of string, token[1] = string
                str_size = len(token[1]) + 1
                res.append(f'''call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([{str_size} x i8], [{str_size} x i8]* @.{token[0]}, i64 0, i64 0))''')
            else: # it is another non-terminal
                name = self.k_to_s(token)
                res.append(f'''call void @gen_{name}()''')
        return '\n'.join(res)

    def gen_alt_src(self, key):
        name = self.k_to_s(key)
        rules = self.grammar[key]
        nrules = len(rules)
        string_pool_len = len(self.pool_of_strings[key])
        result = []
        result.append(f'''define void @gen_{name}() {{;@gen_start procedure
  %md_local = load i32, i32* @max_depth, align 4; load global max_depth into md_local for local use
  %d_local = load i32, i32* @depth, align 4; load global depth into d_local for local use
  %comp_result1 = icmp sgt i32 %d_local, %md_local ; bool comp_result1 = depth > max_depth
  ; branch jump to s_expr if comp_result1 == true, else, jump to full_expansion
  br i1 %comp_result1, label %s_expr, label %full_expansion
  s_expr: ; when depth > max_depth, return choice(s_expr)
    %random_choice = call i8 @map(i8 {string_pool_len}) ; random_choice = map({string_pool_len})
    ; spointer = pointer to randomly selected element shortest expansion element
    %spointer = getelementptr inbounds [{string_pool_len} x i8*], [{string_pool_len} x i8*]* @pool_{name}, i64 0, i8 %random_choice
    %output = load i8*, i8** %spointer, align 16 ; load the element
    call i32 (i8*, ...) @printf(i8* %output) ; print it
    br label %return_block ; branch jump to return_block
  full_expansion: ; when depth <= max_depth, return any expansion after incrementing depth
    %new_d_local = add nsw i32 1, %d_local ; new_d_local = d_local + 1
    store i32 %new_d_local, i32* @depth, align 4 ; (global) depth = new_d_local
    %random_choice1 = call i8 @map(i8 {nrules}) ; random_choice1 = map({nrules})
    ; switch based on random_choice1's value, default is return_block
    switch i8 %random_choice1, label %return_block [
''')
        for i in range(nrules):
            result.append(f'''      i8 {i}, label %f_expnsn_case{i} ; jump to f_expnsn_case{i}, if random_choice1={i}
''')
        result.append(f'''    ]
    br label %return_block ; branch jump to return_block
''')
        IR_dict_rules_dict = self.IR_gram_dict[key]
        for i, rule in IR_dict_rules_dict.items():
            expnsn = self.gen_rule_src(rule, key, i)
            result.append(f'''  f_expnsn_case{i}:
{self.add_indent(expnsn,'    ')}
    br label %return_block
''')
        result.append('''return_block:
    ret void ; return void
}\n\n''')
        return ''.join(result)

    def gen_fuzz_src(self):
        result = []
        result.append(self.header)
        result.append(self.global_data_structures)
        result.append(self.get_short_expnsns())
        for fn in self.randomising_fns:
            result.append(fn)
        for key in self.grammar:
            result.append(self.gen_alt_src(key))
        return '\n'.join(result)

    def gen_main_src(self):
        return self.init_fn + self.main_fn

    def fuzz_src(self, key='<start>'):
        return self.gen_fuzz_src() + self.gen_main_src()

class CFuzzer(PyRecCompiledFuzzer):
    def cheap_chars(self, string):
        # to be embedded within single quotes
        escaped = {'t':'\t', 'n': '\n', "'": "\\'", "\\":"\\\\", 'r': '\r'}
        slst = []
        while string:
            c, *string = string
            if c in {'\\'}:
                c1, *string = string
                slst.append(escaped[c1])
            elif c in {"'"}:
                slst.append("\'")
            else:
                slst.append(c)
        return slst

    def gen_rule_src(self, rule, key, i):
        res = []
        for token in rule:
            if token in self.grammar:
                res.append('gen_%s(depth +1);' % self.k_to_s(token))
            else:
                res.append("out('%s');" % self.esc_char(token))
        return '\n        '.join(res)

    def gen_alt_src(self, k):
        rules = self.grammar[k]
        cheap_strings = self.pool_of_strings[k]
        result = ['''
void gen_%(name)s(int depth) {
    if (depth > max_depth) {
        int val = map(%(num_cheap_strings)d);
        const char* str = pool_%(name)s[val];
        const int str_l = pool_l_%(name)s[val];
        for (int i = 0; i < str_l; i++) {
            out(str[i]);
        }
        return;
    }

    int val = map(%(nrules)d);
    switch(val) {''' % {'name':self.k_to_s(k), 'nrules':len(rules),
                        'num_cheap_strings': len(cheap_strings),
                       }]
        for i, rule in enumerate(rules):
            result.append('''
    case %d:
        %s
        break;''' % (i, self.gen_rule_src(rule, k, i)))
        result.append('''
    }
}
    ''')
        return '\n'.join(result)

    def string_pool_defs(self):
        result = []
        for k in self.grammar:
            cheap_strings = self.pool_of_strings[k]
            result.append('''
const char* pool_%(k)s[] =  {%(cheap_strings)s};
const int pool_l_%(k)s[] =  {%(cheap_strings_len)s};
        ''' % {'k':self.k_to_s(k),
               'cheap_strings': ', '.join(['"%s"' % self.esc(s) for s in cheap_strings]),
               'cheap_strings_len': ', '.join([str(len(s)) for s in cheap_strings])})
        return '\n'.join(result)


    def fn_fuzz_decs(self):
        result = []
        for k in self.grammar:
            result.append('''void gen_%s(int depth);''' % self.k_to_s(k))
        return '\n'.join(result)

    def fn_map_def(self):
        return '''
int map(int v) {
    return random() % v;
}
 '''
    def fn_out_def(self):
        return '''
void out(const char s) {
    fputc(s, stdout);
}
 '''

    def fuzz_hdefs(self):
        return '''
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
'''

    def fuzz_out_var_defs(self):
        return '''
void out(const char s);'''

    def fuzz_rand_var_defs(self):
        return '''
int map(int v);'''
    def fuzz_stack_var_defs(self):
        return '''
extern int max_depth;'''

    def fuzz_var_defs(self):
        return '\n'.join([self.fuzz_out_var_defs(), self.fuzz_rand_var_defs(), self.fuzz_stack_var_defs()])

    def fn_main_input_frag(self):
        return '''
    if (argc < 3) {
        printf("%s <seed> <max_num> <max_depth>\\n", argv[0]);
        return 0;
    }
    seed = atoi(argv[1]);
    max_num = atoi(argv[2]);
    max_depth = atoi(argv[3]);'''

    def fn_main_loop_frag(self):
        return '''
    for(int i=0; i < max_num; i++) {
        gen_init__();
    }'''

    def fn_main_def(self):
        result = '''
int main(int argc, char** argv) {
    int seed, max_num;
%(input_frag)s
    //srandom(time(0));
    srandom(seed);
%(loop_frag)s
    return 0;
}''' % {'input_frag':self.fn_main_input_frag(),
        'loop_frag': self.fn_main_loop_frag()}
        return result

    def main_stack_var_defs(self):
        return '''
int max_depth = 0;'''

    def main_init_var_defs(self):
        return '''
void gen_init__();'''

    def main_var_defs(self):
        return '\n'.join([self.main_stack_var_defs(), self.main_init_var_defs()])

    def fuzz_fn_defs(self):
        result = []
        for key in self.grammar:
            result.append(self.gen_alt_src(key))
        return '\n'.join(result)

    def fuzz_entry(self):
        return '''
void gen_init__() {
    gen_start(0);
    out('\\n');
    return;
}'''

    def main_hdefs(self):
        return '''
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
'''

    def gen_main_src(self):
        return '\n'.join([self.main_hdefs(),
                          self.main_var_defs(),
                          self.fn_map_def(),
                          self.fn_out_def(),
                          self.fn_main_def()])

    def gen_fuzz_src(self):
        return '\n'.join([self.fuzz_hdefs(),
                          self.fuzz_var_defs(),
                          self.fn_fuzz_decs(),
                          self.string_pool_defs(),
                          self.fuzz_fn_defs(),
                          self.fuzz_entry()])

    def fuzz_src(self, key='<start>'):
        return self.gen_main_src(), self.gen_fuzz_src()
# II
# https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
class CFuzzerExtRand(CFuzzer):
    def main_hdefs(self):
        s = super().main_hdefs()
        return s + '''
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <math.h>
'''

    def fn_map_def(self):
        return '''
uint8_t
__attribute__((always_inline))
map(uint8_t to) {
    uint8_t from = rand_regionp[rand_cursor++];
    if (rand_cursor >= rand_region_size)
        rand_cursor = 0;
    return ((uint16_t) from * (uint16_t) to) >> 8;
}

static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}
static uint64_t r__s[4] = {13343, 9838742, 223185, 802124}; /*TODO: initialize with seed.*/
uint64_t
next(void) {
    const uint64_t result_starstar = rotl(r__s[1] * 5, 7) * 9;

    const uint64_t t = r__s[1] << 17;

    r__s[2] ^= r__s[0];
    r__s[3] ^= r__s[1];
    r__s[1] ^= r__s[2];
    r__s[0] ^= r__s[3];

    r__s[2] ^= t;

    r__s[3] = rotl(r__s[3], 45);

    return result_starstar;
}

uint8_t* rand_region_sizep = 0;

void
__attribute__((flatten))
initialize_random(uint64_t max_chars) {
    uint64_t* arr = (uint64_t*) rand_regionp;
    uint64_t i;
    for (i=0; i < max_chars/8; i++) { /*max_space/8 because we have 8 bytes*/
        arr[i] = next();
    }
    rand_region_sizep = (uint8_t*) (arr+i);
}
'''
    def main_rand_var_defs(self):
        return '''
const uint64_t rand_region_size = 1ULL << 16;
uint8_t rand_regionp[rand_region_size];
uint64_t rand_cursor = 0;
'''

    def main_var_defs(self):
        s = super().main_var_defs()
        return s + self.main_rand_var_defs()

    def fuzz_hdefs(self):
        s = super().fuzz_hdefs()
        return s + '''
#include <unistd.h>
#include <stdint.h>'''

    def fuzz_rand_var_defs(self):
        return '''
extern uint8_t* rand_regionp;
extern uint64_t rand_cursor;
extern uint64_t rand_region_size;
uint8_t map(uint8_t to);'''

    def fn_main_rand_frag(self):
        return '''\
    initialize_random(rand_region_size);
    rand_cursor = seed;
    '''

    def fn_main_def(self):
        return '''
int main(int argc, char** argv) {
    struct stat st;
    int max_num, seed, rand_fd, out_fd;
    long out_size;
%(input_frag)s
%(rand_frag)s
%(loop_frag)s
    return 0;
}''' % { 'input_frag': self.fn_main_input_frag(),
         'loop_frag': self.fn_main_loop_frag(),
         'rand_frag': self.fn_main_rand_frag()}
# II
class CFuzzerExtRandP(CFuzzerExtRand):
    def fn_map_def(self):
        return '''
uint8_t
__attribute__((always_inline))
map(uint8_t to) {
    uint8_t from = *rand_regionp++;
    if (rand_regionp >= rand_region_sizep)
        rand_regionp = rand_region_initp;
    return ((uint16_t) from * (uint16_t) to) >> 8;
}


static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}
static uint64_t r__s[4] = {13343, 9838742, 223185, 802124}; /*TODO: initialize with seed.*/
uint64_t
next(void) {
    const uint64_t result_starstar = rotl(r__s[1] * 5, 7) * 9;

    const uint64_t t = r__s[1] << 17;

    r__s[2] ^= r__s[0];
    r__s[3] ^= r__s[1];
    r__s[1] ^= r__s[2];
    r__s[0] ^= r__s[3];

    r__s[2] ^= t;

    r__s[3] = rotl(r__s[3], 45);

    return result_starstar;
}

void
__attribute__((flatten))
initialize_random(uint64_t max_chars) {
    uint64_t* arr = (uint64_t*) rand_regionp;
    uint64_t i;
    for (i=0; i < max_chars/8; i++) { /*max_space/8 because we have 8 bytes*/
        arr[i] = next();
    }
    rand_region_sizep = (uint8_t*) (arr+i);
}
'''
    def main_rand_var_defs(self):
        return '''
uint8_t* rand_region_sizep = 0;
const uint64_t rand_region_size = 1ULL << 16;
uint8_t rand_region_initp[rand_region_size];

uint8_t* rand_regionp = rand_region_initp;
'''
    def fuzz_rand_var_defs(self):
        return '''
uint8_t map(uint8_t to);
'''

    def fn_main_loop_frag(self):
        return '''
    for (int i = 0; i < max_num; i++) {
        gen_init__();
    }
'''
    def fn_main_rand_frag(self):
        return '''\
    initialize_random(rand_region_size);
    rand_regionp += seed;
    '''
    def fn_main_def(self):
        return '''
int main(int argc, char** argv) {
    struct stat st;
    long out_size;
    char* out_region_sizep = 0;
    char* out_region_initp;
    int out_fd;
    int seed, max_num;
%(input_frag)s
%(rand_frag)s
%(loop_frag)s
    return 0;
}''' % {'input_frag': self.fn_main_input_frag(),
        'rand_frag': self.fn_main_rand_frag(),
        'loop_frag': self.fn_main_loop_frag()
       }

class CFWriteFuzzer(CFuzzerExtRandP):
    def main_out_var_defs(self):
        if self.system_name == "Darwin":
            ret_str = 'const uint64_t size = UINT_MAX; /*max size of a single input -- 4G*/'
        elif self.system_name == "Linux":
            ret_str = 'const uint64_t size = UINT_MAX/100; /*max size of a single input -- 40M*/'
        return ret_str + '''
char out_region_initp[size];
char *out_regionp = out_region_initp;
uint64_t out_cursor = 0;
FILE* fs;
'''
    def main_var_defs(self):
        s = super().main_var_defs()
        return s + self.main_out_var_defs()

    def fn_out_def(self):
        return '''
void
__attribute__((always_inline))
out(char c) {
    out_regionp[out_cursor++] = c;
}'''

    def fuzz_out_var_defs(self):
        return '''
void out(char c);
extern char* out_regionp;
extern uint64_t out_cursor;
'''

    def fn_main_input_frag(self):
        return '''
    if (argc < 3) {
        printf("%s <seed> <max_num> <max_depth>\\n", argv[0]);
        return 0;
    }
    seed = atoi(argv[1]);
    max_num = atoi(argv[2]);
    max_depth = atoi(argv[3]);'''

    def fn_main_out_frag(self):
        return '''
    if (argc > 4) {
        out_fd = open(argv[4], O_RDWR | O_CREAT, 0600);
    } else {
        out_fd = open("io.x", O_RDWR | O_CREAT, 0600);
    }
    fs = fdopen(out_fd, "w");
'''

    def fn_main_sync_frag(self):
        return '''
    fclose(fs);
    close(out_fd);
'''

    def fn_truncateio(self):
        return '''
'''
    def fn_main_loop_frag(self):
        return '''
    for(int i=0; i < max_num; i++) {
        gen_init__();
        fwrite(out_regionp, sizeof(char), out_cursor, fs);
        out_cursor = 0;
    }
'''

    def fn_main_def(self):
        return self.fn_truncateio() + '''
int main(int argc, char** argv) {
    struct stat st;
    int rand_fd, out_fd;
    int seed, max_num;
%(input_frag)s
%(rand_frag)s
%(out_frag)s
%(loop_frag)s
%(sync_frag)s
    return 0;
}''' % {'input_frag': self.fn_main_input_frag(),
        'out_frag': self.fn_main_out_frag(),
        'sync_frag': self.fn_main_sync_frag(),
        'rand_frag': self.fn_main_rand_frag(),
        'loop_frag': self.fn_main_loop_frag(),
       }

# II
class CFWriteDTFuzzer(CFWriteFuzzer):
    def fn_out_def(self): return ''
    def gen_rule_src(self, rule, k, j):
        res = []
        leaf = True
        for i, token in enumerate(rule):
            if token in self.grammar:
                leaf = False
                trules = self.grammar[token] # ordered by cost
                len_min_choices = len(self.c_grammar[token])
                assert len(trules) < 256
                cheap_strings = self.pool_of_strings[token]
                if len(cheap_strings) < 256: # we only have 255 random choices
                    check_pool = '''
        val = map(%(len_cheap_strings)s);
        const char* str = pool_%(k)s[val];
        const int str_l = pool_l_%(k)s[val];
        for (int i = 0; i < str_l; i++) {
            *out_regionp++ = str[i];
        }
        --returnp;
        goto **returnp;
            ''' % { 'len_cheap_strings': len(cheap_strings), 'k': self.k_to_s(token)}
                else:
                    check_pool = '''
        val = map(%(len_min_choices)s);
                ''' % {'len_min_choices':len_min_choices}
                res.append('''\
    *returnp = &&return__%(i)d__%(j)d__%(k)s;
    if (returnp > max_depthp) {
        %(check_pool)s;
    } else {
        val = map(%(len_rules)s);
    }
    goto *gen_%(t)s[val];
return__%(i)d__%(j)d__%(k)s:;
            ''' % {'i':i, 'j':j, 'k':self.k_to_s(k),
                   't':self.k_to_s(token), 'rnum':0, 'len_rules':len(trules), 'len_min_choices':len_min_choices, 'check_pool':check_pool})
            else:
                t = self.esc_char(token)
                res.append('''\
    *out_regionp++ = '%s';''' % t)
        return res, leaf

    def gen_alt_src_1rule(self, k):
        rule = self.grammar[k][0]
        ri = 0
        src, leaf = self.gen_rule_src(rule, k, ri)
        body = '\n'.join(src)
        result = []
        if leaf:
            return '''
gen_%(name)s_0: {
%(body)s
    goto **returnp;
}''' % {'name':self.k_to_s(k), 'body':body}
        else:
             return '''
gen_%(name)s_0: {
    ++returnp;
    // single -- no switch
%(body)s
    --returnp;
    goto **returnp;
}''' % {'name':self.k_to_s(k), 'body':body}

    def gen_alt_src(self, k):
        rules = self.grammar[k]
        ret = self.k_to_s(k)
        result = []
        if len(rules) == 1: return self.gen_alt_src_1rule(k)
        for ri, rule in enumerate(rules):
            src, leaf = self.gen_rule_src(rule, k, ri)
            body = '\n'.join(src)
            if leaf:
                result.append('''
gen_%(name)s_%(rnum)d: {
%(body)s
    goto **returnp;
}
    ''' % {'name': self.k_to_s(k), 'rnum': ri, 'body':body})
            else:
                 result.append('''
gen_%(name)s_%(rnum)d: {
    ++returnp;
%(body)s
    --returnp;
    goto **returnp;
}
    ''' % {'name': self.k_to_s(k), 'rnum': ri, 'body':body})
        return '\n'.join(result)

    def fuzz_out_var_defs(self):
        return '''\
extern char* out_regionp;'''

    def fuzz_rand_var_defs(self):
        return '''
uint8_t map(uint8_t to);'''

    def fuzz_stack_var_defs(self):
        return '''
extern void* stackp[];
'''

    def fuzz_entry(self):
        result = ['''
void gen_init__(void** max_depthp) {
    uint8_t val;
    void** returnp = stackp;
    *returnp =  &&return__init;
''']
        for k in self.grammar:
            l = []
            for ri,rule in enumerate(self.grammar[k]):
                l.append('&&gen_%(k)s_%(ri)d' % {'k':self.k_to_s(k), 'ri':ri})
            s = '''
    void** gen_%(k)s[] = {
%(body)s
    };''' % {'k': self.k_to_s(k), 'body': ',\n'.join(l)}
            result.append(s)
        result.append('''
    goto gen_start_0;''')
        result.append(self.fuzz_fn_defs())
        result.append("""
return__init:
    *out_regionp++ = '\\n';
    return;
return_abort:
    exit(10);
}""")
        return '\n'.join(result)


    def main_stack_var_defs(self):
        if self.system_name == "Darwin":
            ret_str = 'void* stackp[INT_MAX];\n'
        elif self.system_name == "Linux":
            ret_str = 'void* stackp[INT_MAX/100];\n'
        return'''
int max_depth;
void** max_depthp;
''' + ret_str

    def main_init_var_defs(self):
        return'''
void gen_init__(void** max_depthp);
'''

    def fn_main_loop_frag(self):
        return '''
    fs = fdopen(out_fd, "w");
    for(int i=0; i < max_num; i++) {
        out_regionp = out_region_initp;
        gen_init__(max_depthp);
        out_cursor = out_regionp - out_region_initp;
        fwrite(out_region_initp, sizeof(char), out_cursor, fs);
    }
    '''

    def fn_main_def(self):
        return self.fn_truncateio() + '''
int main(int argc, char** argv) {
    struct stat st;
    long out_size;
    char* out_region_sizep = 0;
    int out_fd;
    int seed, max_num;
%(input_frag)s
    max_depthp = stackp + max_depth;
%(rand_frag)s
%(out_frag)s
%(loop_frag)s
%(sync_frag)s
    return 0;
}''' % {'input_frag': self.fn_main_input_frag(),
        'rand_frag': self.fn_main_rand_frag(),
        'out_frag': self.fn_main_out_frag(),
        'loop_frag': self.fn_main_loop_frag(),
        'sync_frag': self.fn_main_sync_frag()
       }


    def gen_fuzz_src(self):
        return '\n'.join([self.fuzz_hdefs(),
                          self.fuzz_var_defs(),
                          self.fn_fuzz_decs(),
                          self.string_pool_defs(),
                          # self.fuzz_fn_defs(),
                          self.fuzz_entry()])

class CFWriteCTFuzzer(CFWriteDTFuzzer):

    def fn_choice(self, val):
        return '''
    # [ random
    # extract one byte from the random stream %%r14,
    movq (%%r14), %%rdi
    # advance the random cursor
    inc %%r14                                     # rand_region++
    movzbl %%dil, %%edi                           # X  --- (rdi:(edi:(di:(dil))))
    # then multiply with the choices we have

    xor %%rsi, %%rsi                              # avoid data dependencies
    movb $%(val)s, %%sil                          # = %(val)s
    movzbl %%sil, %%edx
    imull %%edi, %%edx                            # m = (short) x * (short) N)
    sarl $8, %%edx                                # return (char)(m >> 8) ;
    # random ]
    # %%edx now contains the selected random value from %(val)d options''' % {'val':val}

    def cheap_strings(self, k):
        cheap_strings = self.pool_of_strings[k]
        results = ['''
    # --- cheap -- [''']
        results.append('''
%(choices)s
''' % {'choices':self.fn_choice(len(cheap_strings)), 'len_choices': len(cheap_strings)})
        # get the choices from vm, then call it, and return.

        results.append('''
    # now we have the right print quad in %%edx. Load the right address and call it.
    leaq _%(key)s_prints(%%rip), %%rcx
    leaq (%%rcx, %%rdx, 8), %%rax
    callq *(%%rax)
    ret
    ''' % {'key': self.k_to_s(k)})
        results.append('''
    # --- cheap -- ]''')
        return '\n'.join(results)

    def output_char(self, c):
        if len(c) != 1:
            assert c[0] == '\\'
            c = c[-1]
        return '''
   movb $%(ichar)d, (%%r13)                     # '%(char)s'
   inc %%r13                                    # out_region++   : increment a byte (r13++)
   ''' % {'char':self.esc(c), 'ichar':ord(c)}

    def gen_rule_src(self, rule, k, j):
        # in each rule, there are a number of tokens.
        # iter each token in turn, choose the right rule and call.
        result = []
        for token in rule:
            if token not in self.grammar:
                result.append(self.output_char(token))
                continue
            else:
                # how many choices do we have?
                rules = self.grammar[token]
                result.append('''
    # start the choice machine.
    # length of rules = %(len_rules)d
%(choices)s
    # --- switch ---
    ''' % {'choices': self.fn_choice(len(rules)), 'len_rules':len(rules)})
                result.append('''
    # now we have the right choice in %%edx. Load the right address and call it.
    leaq _%(key)s_choices(%%rip), %%rcx
    leaq (%%rcx, %%rdx, 8), %%rax
    callq *(%%rax)
    ''' % {'key': self.k_to_s(token)})
        return '\n'.join(result)

    def gen_alt_src(self, k):
        result = []
        for ruleid, rule in enumerate(self.grammar[k]):
            # produce a skeletal subroutine structure.
            result.append('''
gen_%(key)s_%(ruleid)s:
    # check if the max depth is breached.
    cmpq %%rsp, %%r8                             # returnp(rbp) <> max_depth(r8) ?
    jle _%(key)s_%(ruleid)s_fi                       # returnp <= max_depth

%(return_cheap_string)s
_%(key)s_%(ruleid)s_fi:
''' % {'return_cheap_string': self.cheap_strings(k),
       'key':self.k_to_s(k),
       'ruleid':ruleid,
       'last_label':self.last_label})
            self.last_label += 1
            result.append(self.gen_rule_src(rule, k, ruleid))
            # we were called. So simply return.
            result.append('''
    ret
            ''')
        return '\n'.join(result)

    def fn_fuzz_decs(self):
        if self.system_name == "Darwin":
            result = ['''
.section  __DATA,__data
''']

        elif self.system_name == "Linux":
            result = ['''
.text
''']
        result.append('''\
# Virtual Machine OPS.
''')
        for k in self.grammar:
            result.append('''
    .globl  _%(key)s_choices
    .p2align 4
_%(key)s_choices:''' % {'key':self.k_to_s(k)})
            for i, rule in enumerate(self.grammar[k]):
                result.append('''\
    .quad gen_%s_%d''' % (self.k_to_s(k), i))

        for k in self.pool_of_strings:
            result.append('''
    .globl  _%(key)s_prints
    .p2align 4
_%(key)s_prints:''' % {'key':self.k_to_s(k)})
            for string in self.pool_of_strings[k]:
                result.append('''\
    .quad %s''' % (self.all_prints[string]))


        result.append('''
# End Virtual Machine OPS.''')
        return '\n'.join(result)

    def gen_cheap(self, grammar):
        all_strings = set()
        for k in grammar:
            all_strings |= set(self.pool_of_strings[k])
        all_strings = list(all_strings)
        all_strings.sort(key=lambda item: (-len(item), item))
        all_prints_hash = {}
        if self.system_name == "Darwin":
            result = ['''
.text
            ''']
        elif self.system_name == "Linux":
            result = ['''
            ''']
        for i, s_ in enumerate(all_strings):
            s = s_
            result.append('''\
print_%(name)d: # "%(value)s"''' % {'name': i, 'value': self.esc(s)})
            for j in s:
                result.append('''\
    movb $%(ichar)s, (%%r13)            # '%(char)s'
    inc %%r13''' % {'ichar':ord(j), 'char':self.esc(j)})
            result.append('''\
    ret''')
            all_prints_hash[s_] = 'print_%d' % i
        return ('\n'.join(result), all_prints_hash)

    def fuzz_entry(self):
        result = ["""
#include "vm_ops.s"
.macro pushaq
    push %%rsp
    push %%rbp
    push %%r8
    push %%r9
    push %%r10
    push %%r11
    push %%r12
    push %%r13
    push %%r14
    push %%r15
.endm


.macro popaq
    pop %%r15
    pop %%r14
    pop %%r13
    pop %%r12
    pop %%r11
    pop %%r10
    pop %%r9
    pop %%r8
    pop %%rbp
    pop %%rsp
.endm

.global %(os)sgen_init__
.global return__init
.text
%(os)sgen_init__:
    # 1 rdi = max_depth
    # 2 rsi = returnp
    # 3 rdx = &out_region
    # 4 rcx = &rand_region
    pushaq

    leal 0(,%%rdi,8), %%eax
    movq %%rsp, %%r8
    subq %%rax, %%r8

    movq %%rdx, %%r11                              # &out_region
    movq %%rcx, %%r12                              # &rand_region
    movq (%%r11),%%r13                             # out_region
    movq (%%r12),%%r14                             # rand_region

    # general regs
    # rax, rcx, rdx, rbx, rsi,rdi
    # rbp, r8-r15

    call gen_start_0
    movq %%r13, (%%r11)                            # *(&out_region) <-
    movq %%r14, (%%r12)                            # *(&rand_region) <-
    popaq
    movq  $0, %%rax
    ret
""" % {'os': '_' if sys.platform == 'darwin' else ''}]
        result.append(self.fuzz_fn_defs())
        return ''.join(result)

    def main_init_var_defs(self):
        return'''
void gen_init__(uint32_t max_depth, void** returnp, char** out_region, uint8_t** rand_region);
'''

    def fn_main_loop_frag(self):
        return '''
    fs = fdopen(out_fd, "w");
    for(int i=0; i < max_num; i++) {
        out_regionp = out_region_initp;
        gen_init__(max_depth32, stackp, &out_regionp, &rand_regionp);
        *out_regionp++ = '\\n';
        out_cursor = out_regionp - out_region_initp;
        fwrite(out_region_initp, sizeof(char), out_cursor, fs);
    }
    '''

    def fn_main_def(self):
        return self.fn_truncateio() + '''
int main(int argc, char** argv) {
    struct stat st;
    long out_size;
    int out_fd;
    uint32_t max_depth32;
    int seed, max_num;
%(input_frag)s
    max_depth32 = max_depth;
%(rand_frag)s
%(out_frag)s
%(loop_frag)s
%(sync_frag)s
    return 0;
}''' % {'input_frag': self.fn_main_input_frag(),
        'rand_frag': self.fn_main_rand_frag(),
        'out_frag': self.fn_main_out_frag(),
        'loop_frag': self.fn_main_loop_frag(),
        'sync_frag': self.fn_main_sync_frag()
       }

    def fuzz_src(self, key='<start>'):
        self.last_label = 0
        self.cheap, self.all_prints = self.gen_cheap(self.grammar)
        ext_strings = '\n'.join([self.fn_fuzz_decs(), self.cheap])
        return ext_strings, self.gen_main_src(), self.gen_fuzz_src()

    def gen_fuzz_src(self):
        return '\n'.join([self.fuzz_entry()])

