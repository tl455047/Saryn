# Saryn

- Saryn is a [~~warframe~~](https://warframe.fandom.com/zh-tw/wiki/Saryn) , a coverage-guided fuzzer implemented ```taint inference```, and several tainte mutation strategies, including ```taint havoc```, ```input-to-state+```, and ```linear search```.

- This project is based on AFL++ 3.15a, to see the original README please refer to [README.md](docs/orig_README.md).

- <details><summary>Saryn Prime </summary><p>
    <img src="https://i.imgur.com/qgBkR00.jpg"/>
</p></details>

## Features
#### Taint Inference
- Collect ```critical bytes``` for cmp, switch instructions based on cmplog instrumentation, refer to [PATA](https://www.computer.org/csdl/proceedings-article/sp/2022/131600a154/1wKCe9rJFfi) for more details.
#### Taint Havoc
- Apply ```havoc``` to ```critical bytes``` only.
#### Input-to-State+
- Replace ```colorization``` with ```taint inference``` for instr. type ```input-to-state```.
#### Linear Search
- Refer to [PATA](https://www.computer.org/csdl/proceedings-article/sp/2022/131600a154/1wKCe9rJFfi) for more details.
    
## How to build
``` 
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
# try to install llvm 11 and install the distro default if that fails
sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

git clone https://github.com/tl455047/Saryn.git
cd Saryn

# build project
make clean
make soure only
```
- LLVM version should be 11.
- Refer to [INSTALL.md](docs/INSTALL.md) for more details.
- It is recommended to use gcc/g++ to compile, since sometimes error occurred when using clang/clang++.


## Compile target using afl-cc
- AF++ 3.15a supports several instrumentation mode, including ```lto mode```, ```pcguard mode```, ```llvm mode```, ```gcc plugin mode```, ```gcc/clang mode```.
- Our implementation is based AFL++ ```cmplog mode```, to support ```cmplog mode```, we need to use ```llvm mode ``` , ```pcguard mode```, or ```lto mode```.
- If you install ```llvm-11``` correctly, and choose ```afl-cc``` as compiler-wrapper, the default instrumentation mode will be ```pcguard mode```. 
```=c
# set compiler-wrapper
export CC=/path/to/Saryn/afl-cc
export CXX=/path/to/Saryn/afl-c++
# AFL instrumentation
...
# build commands
# remember to disable shared ex. ./configure --disable-shared
...
make
...
# if is pcguard mode, you should see following messages
afl-cc++3.15a by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: LLVM-PCGUARD                                                                                    warning: unknown warning option '-Wshadow=local' [-Wunknown-warning-option]                                                                                           
SanitizerCoveragePCGUARD++3.15a
[+] Instrumented xx locations with no collisions (non-hardened mode) of which are 0 handled and 0 unhandled selects.
...

# cmplog instrumentation
# build with a new target instance
export AFL_LLVM_CMPLOG=1
...
# build commands
# remember to disable shared ex. ./configure --disable-shared
...
make
...
# if is cmplog mode, you should see following messages
CmpLog mode by <andreafioraldi@gmail.com>
Running cmplog-switches-pass by andreafioraldi@gmail.com
Hooking xx switch instructions
Running split-switches-pass by laf.intel@gmail.com
...
Running cmplog-instructions-pass by andreafioraldi@gmail.com
Running cmplog-routines-pass by andreafioraldi@gmail.com

```
- Refer to [README.md](docs/orig_README.md) for more details.
## Usage

- Same with ```cmplog mode```, add command line option ```-c``` with cmplog instrumentation binary path.
- Our cmplog instrumentation is slightly different from AFL++ cmplog instrumentation, to enable our features, please use our ```afl-cc``` to compile target with cmplog instrumentation.
```
# if input is from stdin
./afl-fuzz -i input-dir -o output-dir -m none -M fuzz-node-name -c /path/to/target-binary-cmplog -- /path/to/target-afl 
# if input is from command line with file
./afl-fuzz -i input-dir -o output-dir -m none -M fuzz-node-name -c /path/to/target-binary-cmplog -- /path/to/target-afl @@
```
- Refer to [README.md](docs/orig_README.md) for more details.
## Example
- Build ```binutils 2.37``` with afl-cc.
```
# get binutils
https://mirror.ossplanet.net/gnu/binutils/binutils-2.37.tar.gz
tar -xvf binutils-2.37.tar.gz
# set compiler wrapper
export CC=/path/to/Saryn/afl-cc
export CXX=/path/to/Saryn/afl-c++
cd binutils-2.37
mkdir afl
cd afl
# AFL instrumentation
../configure --disable-shared
make clean
make
cd ..
mkdir cmplog
cd cmplog
# cmplog instrumentation
export AFL_LLVM_CMPLOG=1
../configure --disable-shared
make clean
make
```
- Fuzz ```objdump``` with option ```-x```.
```
./afl-fuzz -i input-dir -o output-dir -m none -M fuzz-node-name -c /path/to/binutils-2.37/cmplog/binutils/objdump -- /path/to/binutils-2.37/afl/binutils/objdump -x @@
```
### UI
![](https://i.imgur.com/lLWFo9f.png)
#### th/tls/its+
- ```taint havoc```/```taint linear search```/```input-to-state+```
    - ```new coverage```/```executions``` 
#### taint inference
- c-bytes
    - ```critical bytes```/```input length```
## Reference
[PATA](https://www.computer.org/csdl/proceedings-article/sp/2022/131600a154/1wKCe9rJFfi)
