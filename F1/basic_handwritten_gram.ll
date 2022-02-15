; -> the semi-colon is the character to start a one-line comment
; This is the implementation of the F1 fuzzer for the grammar '"<start>" : [["a"]]'.
; -> @max_depth and @depth are defined as a global 32-bit integers, aligned to 4 bytes
@max_depth = global i32 10, align 4 ; (global) int max_depth = 10;
@depth = global i32 0, align 4 ; (global) int depth;
@.start.0 = private unnamed_addr constant [2 x i8] c"a\00", align 1 ; @.start.0 is the "a" in '"<start>" : [["a"]]'
@.newline = private unnamed_addr constant [2 x i8] c"\0A\00", align 1 ; @.newline is the '\n' printed out at the end of gen_init.
@rarr = internal global [4 x i64] [i64 13343, i64 9838742, i64 223185, i64 802124], align 16 ; static uint64_t rarr[4] = {13343, 9838742, 223185, 802124};
@rand_region_initp = common global [65536 x i8] zeroinitializer, align 16 ; uint8_t rand_region_initp[1ULL << 16];
@rand_regionp = global i8* getelementptr inbounds ([65536 x i8], [65536 x i8]* @rand_region_initp, i32 0, i32 0), align 8 ; uint8_t* rand_regionp = rand_region_initp;
@rand_region_sizep = global i8* null, align 8 ; uint8_t* rand_region_sizep = 0;

; This implements the random Integer Multiplication (Biased) method from  https://www.pcg-random.org/posts/bounded-rands.html
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
}

; I have changed the signature of rotl from 'static inline uint64_t rotl(const uint64_t x, int k)'
; to 'static inline uint64_t rotl(const uint64_t x, uint64_t k)'
define internal i64 @rotl(i64 %x, i64 %k) {
  %lsx = shl i64 %x, %k; lsx = (x << k)
  %kdiff = sub nsw i64 64, %k; kdiff = 64 - k
  %rsx = lshr i64 %x, %kdiff; rsx = x >> kdiff
  %or_op = or i64 %lsx, %rsx; or_op = lsx | rsx
  ret i64 %or_op
}

define i64 @next() {
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
}

; can't find llvm IR's equivalent to the flatten attribute
; an alternate way will be replacing the call to next() in the "loop" label with its code
define void @initialize_random(i64 %max_size) {
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
}

define void @gen_start() {;@gen_start procedure
    %md_local = load i32, i32* @max_depth, align 4; load global max_depth into md_local for local use
    %d_local = load i32, i32* @depth, align 4; load global depth into d_local for local use
    %comp_result1 = icmp sgt i32 %d_local, %md_local ; bool comp_result1 = depth > max_depth
    ; branch jump to s_expr if comp_result1 == true, else, jump to full_expansion
    br i1 %comp_result1, label %s_expr, label %full_expansion
  s_expr: ; when depth > max_depth, return choice(s_expr)
    %random_choice = call i8 @map(i8 1) ; random_choice = map(1)
    switch i8 %random_choice, label %return_block [; switch on random_choice's value, default to return_block,
      i8 0, label %case0 ; jump to case0, if random_choice = 0
    ]
    br label %return_block ; branch jump to return_block
  case0:
    ; printf(@.start.0)
    %printf_call1 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([2 x i8], [2 x i8]* @.start.0, i64 0, i64 0))
    br label %return_block
  full_expansion: ; when depth <= max_depth, return any expansion after incrementing depth
    %new_d_local = add nsw i32 1, %d_local ; new_d_local = d_local + 1
    store i32 %new_d_local, i32* @depth, align 4 ; (global) depth = new_d_local
    ; the next currently commented two lines are for debugging purposes.
    ; %newd1 = load i32, i32* @depth, align 4;load global depth into newd1 for local use
    ; call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str.4, i64 0, i64 0), i32 %newd1)
    %random_choice1 = call i8 @map(i8 1) ; random_choice1 = map(1)
    ; switch based on random_choice1's value, default is return_block
    switch i8 %random_choice1, label %return_block [
      i8 0, label %case0 ; jump to case0, when random_choice1 is 0
    ]
  return_block:
    ret void ; return void
}
declare i32 @printf(i8*, ...) ; declare cstdio's printf

; gen_init__ procedure
define void @gen_init__(){
  store i32 0, i32* @depth, align 4 ; initialise (global) depth = 0
  call void @gen_start() ; calling gen_start()
  ; printf(@.newline)
  call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([2 x i8], [2 x i8]* @.newline, i64 0, i64 0))
  ret void ; return void
}

define i32 @main(){
    call void @initialize_random(i64 65536) ; initialize_random(rand_region_size);
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
    store i32 10, i32* %max_loop_p, align 4 ; write max_loop = 10 to memory
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
}
declare void @srand(i32)