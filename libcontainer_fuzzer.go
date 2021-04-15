// +build gofuzz

package libcontainer

import (
	"os"
	"golang.org/x/sys/unix"
	"encoding/json"
	"errors"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/sirupsen/logrus"
	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/opencontainers/runc/libcontainer/configs/validate"
)

func FuzzInit(data []byte) int {
	if len(data) < 5 {
		return -1
	}

	pipe, err := os.OpenFile("pipe.txt", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return -1
	}
	defer pipe.Close()
	defer os.RemoveAll("pipe.txt")

	consoleSocket, err := os.OpenFile("consoleSocket.txt", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return -1
	}
	defer consoleSocket.Close()
	defer os.RemoveAll("consoleSocket.txt")

	// Create fuzzed initConfig
	config := new(initConfig)
	c := gofuzzheaders.NewConsumer(data)
	c.GenerateStruct(config)

	fifoFd := int(data[0])
	l := &linuxStandardInit{
		pipe:          pipe,
		consoleSocket: consoleSocket,
		parentPid:     unix.Getppid(),
		config:        config,
		fifoFd:        fifoFd,
	}
	_ = l.Init()
	return 1
}

func FuzzStateApi(data []byte) int {
	// We do not want any log output:
	logrus.SetLevel(logrus.PanicLevel)

	if len(data) < 4 {
		return -1
	}

	// Create the root dir:
	root, err := newTestRoot()
	if err != nil {
		return -1
	}
	defer os.RemoveAll(root)

	// Create a fuzzconsumer for later user
	c := gofuzzheaders.NewConsumer(data)

	// Create a config
	config := new(configs.Config)
	c.GenerateStruct(config)
	config.Rootfs = root

	// Add Namespaces:
	ns, err := c.GetInt()
	if err != nil {
		return -1
	}
	if (ns % 3) == 0 {
		config.Namespaces = configs.Namespaces(
			[]configs.Namespace{
				{Type: configs.NEWUTS},
			},
		)
	} else if (ns % 4) == 0 {
		config.Namespaces = configs.Namespaces(
			[]configs.Namespace{
				{Type: configs.NEWNS},
			},
		)
	} else {
		config.Namespaces = []configs.Namespace{}
	}

	// Create container:
	containerName, err := c.GetString()
	if err != nil {
		return 0
	}
	container, err := newContainerWithName(containerName, root, config)
	if err != nil {
		return 0
	}
	defer container.Destroy()

	// Fuzz container APIs:
	_, _ = container.State()
	_, _ = container.Stats()
	_, _ = container.OCIState()
	_, _ = container.Processes()
	return 1
}

type FuzzState struct {
	OciVersion  string   `json:"ociVersion"`
	Id          string   `json:"id"`
	Status      string   `json:"status"`
	Pid         int      `json:"pid"`
	Bundle      string   `json:"bundle"`
	Annotations []string `json:"annotations"`
}

func FuzzFactory(data []byte) int {
	if len(data) < 20 {
		return -1
	}
	root := "/tmp/fuzz-root"
	err := os.MkdirAll(root, 0777)
	if err != nil {
		return -1
	}
	err = os.MkdirAll("/tmp/fuzz-root/fuzz", 0777)
	if err != nil {
		return -1
	}
	factory := &LinuxFactory{
		Root:      root,
		InitPath:  "/proc/self/exe",
		InitArgs:  []string{os.Args[0], "init"},
		Validator: validate.New(),
		CriuPath:  "criu",
	}
	c := gofuzzheaders.NewConsumer(data)
	fs := FuzzState{}
	ociVersion, err := c.GetString()
	if err != nil {
		return 0
	}
	id, err := c.GetString()
	if err != nil {
		return 0
	}
	status, err := c.GetString()
	if err != nil {
		return 0
	}
	pid, err := c.GetInt()
	if err != nil {
		return 0
	}
	bundle, err := c.GetString()
	if err != nil {
		return 0
	}
	if len(ociVersion) < 5 || len(id) < 5 || len(bundle) < 5 {
		return 0
	}

	fs.OciVersion = ociVersion
	fs.Id = id
	fs.Status = status
	fs.Pid = pid
	fs.Bundle = bundle
	fs.Annotations = []string{"fuzz"}
	b, err := json.Marshal(&fs)
	if err != nil {
		return 0
	}

	stateFilename := "state.json"
	state_json_path := "/tmp/fuzz-root/fuzz/state.json"
	state_json := []string{state_json_path}
	err = createFiles(state_json, b)
	if err != nil {
		return 0
	}
	defer os.RemoveAll(state_json_path)

	stateFilePath, err := securejoin.SecureJoin("/tmp/fuzz-root/fuzz", stateFilename)
	if err != nil {
		return -1
	}
	f, err := os.Open(stateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return -1
		}
	}
	defer f.Close()
	_, _ = factory.Load("fuzz")
	return 1
}

func newContainerWithName(name, root string, config *configs.Config) (Container, error) {
	f, err := New(root, Cgroupfs)
	if err != nil {
		return nil, err
	}
	if config.Cgroups != nil && config.Cgroups.Parent == "system.slice" {
		f, err = New(root, SystemdCgroups)
		if err != nil {
			return nil, err
		}
	}
	return f.Create(name, config)
}

func newTestRoot() (string, error) {
	dir := "/tmp/fuzzing"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func createFiles(files []string, b []byte) error {
	for i := 0; i < len(files); i++ {
		f, err := os.OpenFile(files[i], os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			return errors.New("Could not create file")
		}
		defer f.Close()
		_, err = f.Write(b)
		if err != nil {
			return errors.New("Could not write to file")
		}
	}
	return nil
}