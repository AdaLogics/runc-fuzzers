package devices

import (
	"strings"
    gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
)

func Fuzz(data []byte) int {
	c := gofuzzheaders.NewConsumer(data)
	str1, err := c.GetString()
	if err != nil {
		return -1
	}
	reader1 := strings.NewReader(str1)
	emu1, err := EmulatorFromList(reader1)
	if err != nil {
		return -1
	}

	str2, err := c.GetString()
	if err != nil {
		return -1
	}
	reader2 := strings.NewReader(str2)
	emu2, err := EmulatorFromList(reader2)
	if err != nil {
		return -1
	}
	emu1.Transition(emu2)
	return 1
}
