// +build gofuzz

package fs2

import (
	"bytes"
    "errors"
    "os"
    "github.com/opencontainers/runc/libcontainer/cgroups"
    gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzCgroupReader(data []byte) int {
	r := bytes.NewReader(data)
	_, _ = parseCgroupFromReader(r)
	return 1
}


func createFiles(files []string, cf *gofuzzheaders.ConsumeFuzzer) error {
    for i:=0;i<len(files);i++ {
        f, err := os.OpenFile(files[i], os.O_RDWR|os.O_CREATE, 0755)
        if err != nil {
            return errors.New("Could not create file")
        }
        defer f.Close()
        //defer os.RemoveAll(files[i])
        b, err := cf.GetBytes()
        if err != nil {
            return errors.New("Could not get bytes")
        }
        _, err = f.Write(b)
        if err != nil {
            return errors.New("Could not write to file")
        } 
    }
    return nil
}

func FuzzGetStats(data []byte) int {
    stats := cgroups.Stats{}
    f := gofuzzheaders.NewConsumer(data)
    err := f.GenerateStruct(&stats)
    if err != nil {
        return -1
    }

    // statPids:
    sPidsFiles := []string{"/tmp/pids.current",
                           "/tmp/pids.max"}
    err = createFiles(sPidsFiles, f)
    if err != nil {
        return -1
    }
    defer os.RemoveAll("/tmp/pids.current")
    defer os.RemoveAll("/tmp/pids.max")
    _ = statPids("/tmp", &stats)

    // statPidsWithoutController:
    stats2 := cgroups.Stats{}
    err = f.GenerateStruct(&stats2)
    if err != nil {
        return -1
    }
    sPidsWoCFiles := []string{"/tmp/cgroup.procs",
                              "/tmp/cgroup.threads"}
    err = createFiles(sPidsWoCFiles, f)
    if err != nil {
        return -1
    }
    defer os.RemoveAll("/tmp/cgroup.procs")
    defer os.RemoveAll("/tmp/cgroup.threads")
    _ = statPidsWithoutController("/tmp", &stats2)


    // statMemory:
    stats3 := cgroups.Stats{}
    err = f.GenerateStruct(&stats3)
    if err != nil {
        return -1
    }
    sMemFiles := []string{"/tmp/memory.stat",
                          "/tmp/memory.swap",
                          "/tmp/memory.current",
                          "/tmp/memory.max"}
    err = createFiles(sMemFiles, f)
    if err != nil {
        return -1
    }
    defer os.RemoveAll("/tmp/memory.stat")
    defer os.RemoveAll("/tmp/memory.swap")
    defer os.RemoveAll("/tmp/memory.current")
    defer os.RemoveAll("/tmp/memory.max")
    _ = statMemory("/tmp", &stats3)

    // StatIo:
    stats4 := cgroups.Stats{}
    err = f.GenerateStruct(&stats4)
    if err != nil {
        return -1
    }
    sIoFiles := []string{"/tmp/io.stat"}
    err = createFiles(sIoFiles, f)
    if err != nil {
        return -1
    }
    defer os.RemoveAll("/tmp/io.stat")
    _ = statIo("/tmp", &stats4)

    // statCpu:
    stats5 := cgroups.Stats{}
    err = f.GenerateStruct(&stats5)
    if err != nil {
        return -1
    }
    sCpuFiles := []string{"/tmp/cpu.stat"}
    err = createFiles(sCpuFiles, f)
    if err != nil {
        return -1
    }
    defer os.RemoveAll("/tmp/cpu.stat")
    _ = statCpu("/tmp", &stats5)
    return 1
}
