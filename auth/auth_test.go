// auth_test
package auth

import (
	"log"
	"testing"
	"net/http"
)

func TestSign(t *testing.T){
	result := "26NBxoKdsyly4EDv6inkoDft/yA="
	
	accessKeySecret := "OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV"
	verb := "PUT"
	resource := "/oss-example/nelson"
	
	var header http.Header
	header = make(map[string][]string)
	header.Add("User-Agent", `wsepr`)
	header.Add("Content-Type","text/html")
	header.Add("Content-Md5","ODBGOERFMDMzQTczRUY3NUE3NzA5QzdFNUYzMDQxNEM=")
	header.Add("Date","Thu, 17 Nov 2005 18:49:58 GMT")
	header.Add("X-OSS-Meta-Author", "foo@bar.com")
	header.Add("X-OSS-Magic", "abracadabra")
	
	signature := Sign(accessKeySecret, verb, header, resource)
	log.Println("TestSign:",signature)
	if signature != result{
		t.Fatalf("excepted %s, but %s", result, signature)
	}
}
