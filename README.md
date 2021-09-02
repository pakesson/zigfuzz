```
$ gcc -o examples/example1 examples/example1.c

$ mkdir corpus
$ echo -n "aaaaaa" > corpus/aaaaaa

$ zig build run
info: Initializing
info: Corpus size: 1
info: Starting fuzzing loop
info: Cases: 6206	Cases per second: 1241	Coverage: 6	Crashes: 0	Time: 5.00 seconds
info: Cases: 12356	Cases per second: 1235	Coverage: 7	Crashes: 0	Time: 10.00 seconds
info: Cases: 18395	Cases per second: 1226	Coverage: 8	Crashes: 0	Time: 15.00 seconds
info: Cases: 24422	Cases per second: 1220	Coverage: 8	Crashes: 0	Time: 20.00 seconds
info: Cases: 30423	Cases per second: 1216	Coverage: 9	Crashes: 1	Time: 25.00 seconds
info: Cases: 36336	Cases per second: 1211	Coverage: 9	Crashes: 1	Time: 30.00 seconds
^C

$ ./examples/example1 ./crashes/crash_c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2 
Segmentation fault (core dumped)
```