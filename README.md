# runc-fuzzers

This repository contains fuzzers written for the runc project during march and april 2021. 

Besides the fuzzers itself is a build script that can be called from runc's own OSS-fuzz build script. Just add the following:

```bash
cd $SRC
git clone --depth 1 https://github.com/AdaLogics/runc-fuzzers
./runc-fuzzers/build.sh
```
