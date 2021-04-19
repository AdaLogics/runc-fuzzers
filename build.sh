#!/bin/bash -eu

go clean --modcache
go mod tidy
go mod vendor
rm -r $SRC/runc/vendor
go get github.com/AdaLogics/go-fuzz-headers

export RUNC_PATH=github.com/opencontainers/runc
mv $SRC/runc-fuzzers/fs2_fuzzer.go $SRC/runc/libcontainer/cgroups/fs2/
compile_go_fuzzer $RUNC_PATH/libcontainer/cgroups/fs2 FuzzGetStats get_stats_fuzzer
compile_go_fuzzer $RUNC_PATH/libcontainer/cgroups/fs2 FuzzCgroupReader cgroup_reader_fuzzer

mv $SRC/runc-fuzzers/specconv_fuzzer.go $SRC/runc/libcontainer/specconv/
compile_go_fuzzer $RUNC_PATH/libcontainer/specconv Fuzz specconv_fuzzer

mv $SRC/runc-fuzzers/devices_fuzzer.go $SRC/runc/libcontainer/cgroups/devices
compile_go_fuzzer $RUNC_PATH/libcontainer/cgroups/devices Fuzz devices_fuzzer

mv $SRC/runc-fuzzers/fscommon_fuzzer.go $SRC/runc/libcontainer/cgroups/fscommon/
compile_go_fuzzer $RUNC_PATH/libcontainer/cgroups/fscommon FuzzSecurejoin securejoin_fuzzer

mv $SRC/runc-fuzzers/intelrdt_fuzzer.go $SRC/runc/libcontainer/intelrdt/
compile_go_fuzzer $RUNC_PATH/libcontainer/intelrdt FuzzFindMpDir find_mountpoint_dir_fuzzer
compile_go_fuzzer $RUNC_PATH/libcontainer/intelrdt FuzzSetCacheScema set_cache_schema_fuzzer
compile_go_fuzzer $RUNC_PATH/libcontainer/intelrdt FuzzParseMonFeatures parse_mon_features_fuzzer

mv $SRC/runc-fuzzers/libcontainer_fuzzer.go $SRC/runc/libcontainer/
compile_go_fuzzer $RUNC_PATH/libcontainer FuzzStateApi state_api_fuzzer
