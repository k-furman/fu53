# Fu53

**fu53** (fuse | fuzzing safe environment/execution) - library that redefine dangerous system functions to make fuzzing safer. As an example, use of `open()`, `unlink()`, `write()` functions on system files can broke system by modifying, removing etc. some system stuff.

## Building

For build this library you should run `make` - library will built on both states - static and shared. `make install` will link this library into `/usr/lib` directory.

## Linking

Library links by using `AFL_PRELOAD`, because by default it blocks functions, which fuzzer use to work - `fork()`, `fopen()`, `open()` as an example.

You can use this library with `LD_PRELOAD`, but you can understand which functions should be unlocked.

Also, you can link library on linking stage with your binary.

## Using

By default library replaces all functions from library header. Some functions can be enabled by using environment variables, so you shouldn't recompile your project and library. For example, if you set `WITH_FORK=0`, fu53 won't block `fork()` calls, if you set `WITH_FORK=N`, fu53 let call only `N` `fork()` calls during this instance.

Also, this library can capture inputs that causes calling some functions. For example, use of `NO_OPEN=1` variable, will throw `assert(0)` when some of open- functions will called, and fuzzer can save this input as a crash.
