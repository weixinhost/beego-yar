package beego_yar

import (
	"crypto/md5"
	"crypto/aes"
)

const (
	BLOCK_SIZE = 16
)


// aes 128 ecb

type EncryptBody struct {

	Key 		[]byte
	BodyLen 	uint32
	RealLen 	uint32
	Body 		[]byte
}

func (this *EncryptBody)Encrypt(body []byte) error {
	key := encodeKey(this.Key)
	this.Body = make([]byte,0)
	block,err := aes.NewCipher(key)

	if err != nil {
		return err
	}

	var used int = 0
	var len  int = len(body)
	this.RealLen = uint32(len)

	ecb := NewECBEncrypter(block)

	for {

		var text [BLOCK_SIZE]byte
		if used > len {
			break
		}

		copyed := BLOCK_SIZE

		if len - used < BLOCK_SIZE {
			copyed = len - used
		}

		for i:= 0;i<copyed;i++ {
			text[i] = body[used +i]
		}

		var crypted [BLOCK_SIZE]byte

		ecb.CryptBlocks(crypted[:], text[:])
		this.Body = append(this.Body,crypted[:]...)
		used += BLOCK_SIZE
	}

	this.BodyLen = uint32(used)
	return nil

}


func (this *EncryptBody)Decrypt() ([]byte,error) {

	key := encodeKey(this.Key)
	block,err := aes.NewCipher(key)

	if err != nil {
		return nil,err
	}

	var used int = 0
	var len  int =  int(this.BodyLen)
	var body []byte

	ecb := NewECBDecrypter(block)

	for {

		var text [BLOCK_SIZE]byte
		if used > len {
			break
		}

		copyed := BLOCK_SIZE

		if len - used < BLOCK_SIZE {
			copyed = len -used
		}

		for i:= 0;i<copyed;i++ {
			text[i] = this.Body[used +i]
		}

		var crypted [BLOCK_SIZE]byte

		ecb.CryptBlocks(crypted[:], text[:])
		body = append(body,crypted[:]...)
		used += BLOCK_SIZE
	}

	return body,nil

}

func encodeKey(key []byte) []byte{

	md5 := md5.New()
	md5.Write(key)
	return md5.Sum(nil)
}

