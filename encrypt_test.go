package beego_yar

import "testing"

func Test_Encrypt(t *testing.T) {

	key := "weixinhost"

	data := "abcdefsfdgskldjfglkwejiojlksdnfgoe23482374204203shldnfls"

	body := &EncryptBody{
		Key : []byte(key),
	}
	body.Encrypt([]byte(data));
	decrypt,err:= body.Decrypt()

	t.Error(err,string(decrypt[:body.RealLen]))
}

