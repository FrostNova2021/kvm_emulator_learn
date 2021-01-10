
## KVM Emulator Learn Code

#### Code Map

```
    emulator_code.asm  =>  execute code in KVM
    main.c  =>  KVM emulator
```


#### Make Code

First Step: make KVM emulator code .

```shell
    make
```

Then ,compiler emulator_code.asm with make_emulator_code.sh

```shell
    ./make_emulator_code.sh
```

#### Try it!

Output:

```shell
    $ ./main 
    code_buffer = BA0000B8
    Current KVM VERSION:12 
    KVM IO_IN ==> IO size = 2 ;IO port = 18 
    KVM IO_OUT ==> IO size = 2 ;IO port = 17 ;IO data = 12 
    KVM MMIO Read = 0x8000 (2) 
    KVM MMIO Output => BC 
    KVM IO_OUT ==> IO size = 2 ;IO port = 17 ;IO data = 1 
    KVM IO_OUT ==> IO size = 2 ;IO port = 17 ;IO data = 0 
    KVM IO_OUT ==> IO size = 2 ;IO port = 17 ;IO data = FC18 
    KVM VM Shutdown!
```

