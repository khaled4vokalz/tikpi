package ip

import "github.com/khaled4vokalz/tikpi/utils"

func IPChecksum(data []byte) uint16 {
	return utils.ChecksumData(data)
}
