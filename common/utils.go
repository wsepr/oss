// utils
package common

import (
	"time"
)

func HttpGMTDate() string{
	return time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}
