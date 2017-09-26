cd ~/buzz && git pull origin test && cd ~/buzz/KLEE/buzz && rm klee-* -r && rm multistage.adu
clang -I ~/klee_src/include -emit-llvm -c driver.c -o driver.bc
klee --libc=uclibc --posix-runtime driver.bc
ktest-tool --write-ints klee-last/test000001.ktest > multistage.adu

