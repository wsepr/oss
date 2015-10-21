// auth
package auth

import (
	"io"
	"net/http"
	"aliyun/oss/common"
	"strings"
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"crypto/sha1"
	"sort"
	"hash"
)

//build Signature
func Sign(accessKeySecret string, verb string, header http.Header, resource string) string{
	
	hs := make([]string, 0, len(header))
	for k, _ := range header{
		if strings.HasPrefix(k, common.HeaderOssPrefix){ //canonical format
			hs = append(hs, strings.ToLower(k))
		}
	}
	sort.Strings(hs)
	
	var signBuf bytes.Buffer
	
	signBuf.WriteString(verb)
	signBuf.WriteByte('\n')
	signBuf.WriteString(header.Get(common.HeaderContentMd5))
	signBuf.WriteByte('\n')
	signBuf.WriteString(header.Get(common.HeaderContentType))
	signBuf.WriteByte('\n')
	signBuf.WriteString(header.Get(common.HeaderDate))
	signBuf.WriteByte('\n')
	
	//CanonicalizedOSSHeaders
	for _, h := range hs {
		signBuf.WriteString(h)
		signBuf.WriteByte(':')
		signBuf.WriteString(strings.TrimSpace(header.Get(h)))
		signBuf.WriteByte('\n')
	}
	signBuf.WriteString(resource)

	hm := hmac.New(func() hash.Hash { return sha1.New() }, []byte(accessKeySecret))
	io.WriteString(hm, signBuf.String())

	return base64.StdEncoding.EncodeToString(hm.Sum(nil))
}
