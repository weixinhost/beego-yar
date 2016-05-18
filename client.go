package beego_yar

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/weixinhost/beego-yar/packager"
	"github.com/weixinhost/beego-yar/transports"
)

type ClientOpt int

const (
	CLIENT_CONNECTION_TIMEOUT  ClientOpt = 1 //连接超时
	CLIENT_TIMEOUT             ClientOpt = 2 //整体超时
	CLIENT_PACKAGER            ClientOpt = 4 //打包协议.目前支持 "json"
	CLIENT_MAGIC_NUM           ClientOpt = 8
	CLIENT_ENCRYPT             ClientOpt = 10
	CLIENT_ENCRYPT_PRIVATE_KEY ClientOpt = 12
)

const (
	CLIENT_DEFAULT_PACKAGER                  = "JSON" // 默认打包协议
	CLIENT_DEFAULT_TIMEOUT_SECOND            = 5000   // 默认超时.包含连接超时.因此,rpc函数的执行超时为 TIMEOUT - CONNECTION_TIMEOUT
	CLIENT_DEFAULT_CONNECTION_TIMEOUT_SECOND = 1000   // 默认链接超时
)

//用于yar请求的客户端
type Client struct {
	net       string   //网络传输协议.支持 "tcp","udp","http","unix"等值
	hostname  string   //用于初始化网络链接的信息,入 ip:port domain:port 等
	request   *Request //请求体
	transport transports.Transport
	opt       map[ClientOpt]interface{} //配置项
}

//初始化一个客户端
func NewClient(net string, hostname string) (client *Client) {

	client = new(Client)
	client.hostname = hostname
	client.net = strings.ToLower(net)
	client.opt = make(map[ClientOpt]interface{}, 6)
	client.request = NewRequest()
	client.request.Protocol = NewHeader()
	client.initOpt()
	client.init()

	return client
}

func (client *Client) init() {

	switch client.net {

	case "tcp", "udp", "unix":
		{
			client.transport, _ = transports.NewSock(client.net, client.hostname)
			break
		}
	}

}

func (self *Client) initOpt() {

	self.opt[CLIENT_CONNECTION_TIMEOUT] = CLIENT_DEFAULT_CONNECTION_TIMEOUT_SECOND
	self.opt[CLIENT_TIMEOUT] = CLIENT_DEFAULT_TIMEOUT_SECOND
	self.opt[CLIENT_PACKAGER] = CLIENT_DEFAULT_PACKAGER
	self.opt[CLIENT_MAGIC_NUM] = uint32(MAGIC_NUMBER)

}

//配置项操作
func (self *Client) SetOpt(opt ClientOpt, v interface{}) bool {
	self.opt[opt] = v
	return true
}

func (self *Client) sockCall(method string, ret interface{}, params ...interface{}) (err error) {

	if params != nil {
		self.request.Params = params
	} else {
		self.request.Params = []string{}
	}
	self.request.Id = rand.Uint32()
	self.request.Method = method
	self.request.Protocol.Id = self.request.Id
	self.request.Protocol.MagicNumber = uint32(self.opt[CLIENT_MAGIC_NUM].(uint32))

	var pack []byte

	if len(self.opt[CLIENT_PACKAGER].(string)) < 8 {
		for i := 0; i < len(self.opt[CLIENT_PACKAGER].(string)); i++ {
			self.request.Protocol.Packager[i] = self.opt[CLIENT_PACKAGER].(string)[i]
		}
	}

	pack, err = packager.Pack([]byte(self.opt[CLIENT_PACKAGER].(string)), self.request)

	if err != nil {
		return err
	}

	self.request.Protocol.BodyLength = uint32(len(pack) + PACKAGER_LENGTH)
	conn, conn_err := self.transport.Connection()

	if conn_err != nil {
		return conn_err
	}

	conn.Write(self.request.Protocol.Bytes().Bytes())
	conn.Write(pack)
	protocol_buffer := make([]byte, PROTOCOL_LENGTH+PACKAGER_LENGTH)
	conn.Read(protocol_buffer)
	self.request.Protocol.Init(bytes.NewBuffer(protocol_buffer))
	body_buffer := make([]byte, self.request.Protocol.BodyLength-PACKAGER_LENGTH)
	conn.Read(body_buffer)
	response := new(Response)
	err = packager.Unpack([]byte(self.opt[CLIENT_PACKAGER].(string)), body_buffer, &response)

	if response.Status != ERR_OKEY {
		return errors.New(response.Error)
	}
	//这里需要优化,需要干掉这次pack/unpack
	pack_data, err := packager.Pack(self.request.Protocol.Packager[:], response.Retval)
	err = packager.Unpack(self.request.Protocol.Packager[:], pack_data, ret)

	return err
}

func (self *Client) httpCall(method string, ret interface{}, params ...interface{}) (err error) {

	if params != nil {
		self.request.Params = params
	} else {
		self.request.Params = []string{}
	}

	self.request.Id = rand.Uint32()
	self.request.Method = method
	self.request.Protocol.Id = self.request.Id
	self.request.Protocol.MagicNumber = uint32(self.opt[CLIENT_MAGIC_NUM].(uint32))

	var pack []byte

	if len(self.opt[CLIENT_PACKAGER].(string)) < 8 {

		for i := 0; i < len(self.opt[CLIENT_PACKAGER].(string)); i++ {
			self.request.Protocol.Packager[i] = self.opt[CLIENT_PACKAGER].(string)[i]
		}
	}

	pack, err = packager.Pack([]byte(self.opt[CLIENT_PACKAGER].(string)), self.request)

	if err != nil {
		return errors.New("[YarClient httpCall] Pack Params Error: " + err.Error())
	}

	e, ok := self.opt[CLIENT_ENCRYPT]

	encrypt := false
	encrypt_key := ""

	if ok == true {
		encrypt = e.(bool)
	}

	if encrypt {

		e, ok := self.opt[CLIENT_ENCRYPT_PRIVATE_KEY]

		if ok == false {
			return errors.New("encrypt_private_key empty.")
		}
		encrypt_key = e.(string)
	}

	if encrypt {

		self.request.Protocol.Encrypt = 1
		encryptBody := &EncryptBody{
			Key: []byte(encrypt_key),
		}

		err := encryptBody.Encrypt(pack)

		if err != nil {
			return errors.New("[Encrypt] error:" + err.Error())
		}

		encryptPack := bytes.NewBufferString("")

		binary.Write(encryptPack, binary.BigEndian, encryptBody.BodyLen)
		binary.Write(encryptPack, binary.BigEndian, encryptBody.RealLen)
		encryptPack.Write(encryptBody.Body)
		pack = encryptPack.Bytes()
	}

	self.request.Protocol.BodyLength = uint32(len(pack) + PACKAGER_LENGTH)

	post_buffer := bytes.NewBuffer(self.request.Protocol.Bytes().Bytes())
	post_buffer.Write(pack)

	//todo 停止验证HTTPS请求
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(self.opt[CLIENT_TIMEOUT].(int)) * time.Millisecond,
	}

	resp, err := httpClient.Post(self.hostname, "application/json", post_buffer)

	if err != nil {
		return errors.New("[YarClient httpCall] Http Post Error: " + err.Error())
	}

	allBody, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return errors.New("[YarClient httpCall] Http Response Error: " + err.Error())
	}

	protocol_buffer := allBody[0 : PROTOCOL_LENGTH+PACKAGER_LENGTH]

	self.request.Protocol.Init(bytes.NewBuffer(protocol_buffer))

	bodyTotal := self.request.Protocol.BodyLength - PACKAGER_LENGTH

	if uint32(len(allBody)-PROTOCOL_LENGTH+PACKAGER_LENGTH) < bodyTotal {
		return errors.New("[YarClient httpCall] Http Response Content Error:" + string(allBody))
	}

	body_buffer := allBody[PROTOCOL_LENGTH+PACKAGER_LENGTH:]

	if self.request.Protocol.Encrypt == 1 {

		encryptBody := &EncryptBody{
			Key:  []byte(encrypt_key),
			Body: body_buffer[8:],
		}

		decryptBuffer := bytes.NewReader(body_buffer[:8])

		binary.Read(decryptBuffer, binary.BigEndian, &encryptBody.BodyLen)
		binary.Read(decryptBuffer, binary.BigEndian, &encryptBody.RealLen)

		data, err := encryptBody.Decrypt()

		if err != nil {
			return errors.New("[Decrypt] error:" + err.Error())
		}

		body_buffer = data[:encryptBody.RealLen]
	}

	response := new(Response)
	err = packager.Unpack([]byte(self.opt[CLIENT_PACKAGER].(string)), body_buffer, &response)

	if response.Status != ERR_OKEY {
		return errors.New(fmt.Sprintf("[YarClient httpCall] Yar Response Error: %s %d", response.Error, response.Status))
	}

	//这里需要优化,需要干掉这次pack/unpack
	pack_data, err := packager.Pack(self.request.Protocol.Packager[:], response.Retval)
	if err != nil {
		return errors.New("[YarClient httpCall] Pack Data Error: " + err.Error())
	}

	err = packager.Unpack(self.request.Protocol.Packager[:], pack_data, ret)

	if err != nil {
		return errors.New("[YarClient httpCall] Unpack Data Error: " + err.Error())
	}

	return nil
}

//执行一次rpc请求.
//method为请求的方法名.ret参数必须是一个指针类型,用于接收rpc结果.params为rpc函数的形参列表
func (self *Client) Call(method string, ret interface{}, params ...interface{}) (err error) {

	switch self.net {

	case "tcp", "unix":
		{
			return self.sockCall(method, ret, params...)
		}

	case "http":
		{
			return self.httpCall(method, ret, params...)
		}
	}

	return errors.New("unsupported client netmode")
}

func (self *Client) parseRetVal(retval interface{}, parse interface{}) (err error) {

	buf := bytes.NewBufferString("")

	enc := gob.NewEncoder(buf)
	dec := gob.NewDecoder(buf)

	err = enc.Encode(retval)

	if err != nil {

		return err
	}

	err = dec.Decode(parse)

	if err != nil {

		return err
	}

	return nil

}
