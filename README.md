```
$ gcc -o examples/example1 examples/example1.c

$ zig build run
info: Initializing
info: Starting fuzzing loop
info: Cases: 5353	Cases per second: 1070	Coverage: 5	Crashes: 0	Time: 5.00 seconds
info: Cases: 10594	Cases per second: 1059	Coverage: 7	Crashes: 0	Time: 10.00 seconds
info: Cases: 15641	Cases per second: 1042	Coverage: 9	Crashes: 3	Time: 15.00 seconds
info: Cases: 20646	Cases per second: 1032	Coverage: 9	Crashes: 7	Time: 20.00 seconds
^C

$ ./examples/example1 ./crashes/crash_c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2 
Segmentation fault (core dumped)
```