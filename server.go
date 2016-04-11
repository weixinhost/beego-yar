package beego_yar

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/weixinhost/beego-yar/packager"
)

type ServerOpt int

const (
	SERVER_MAGIC_NUMBER           = 1
	SERVER_ENCRYPT                = 2
	SERVER_ENCRYPT_PRIVATE_KEY    = 3
	SERVER_SUPPORT_DYANIMIC_PARAM = 4
)

type Server struct {
	ctx       *context.Context
	class     interface{}
	methodMap map[string]string
	body      []byte
	opt       map[ServerOpt]interface{}
}

func NewServer(ctx *context.Context, class interface{}) *Server {
	server := new(Server)
	server.class = class
	server.ctx = ctx
	server.methodMap = make(map[string]string, 32)
	server.opt = make(map[ServerOpt]interface{}, 2)
	return server
}

func (self *Server) SetOpt(opt ServerOpt, v interface{}) bool {
	self.opt[opt] = v
	return true
}

func (self *Server) Register(rpcName string, methodName string) {
	self.methodMap[strings.ToLower(rpcName)] = methodName
}

func (self *Server) getHeader() (*Header, error) {

	header_buffer := bytes.NewBuffer(self.body[0 : PROTOCOL_LENGTH+PROTOCOL_LENGTH])

	header := NewHeaderWithBytes(header_buffer)

	var magicNumber uint32 = MAGIC_NUMBER

	e, ok := self.opt[SERVER_MAGIC_NUMBER]

	if ok {
		magicNumber = e.(uint32)
	}

	if header.MagicNumber != magicNumber {

		return nil, errors.New("magic number check failed.")

	}

	encrypt := false
	encryptKey := ""

	e, ok = self.opt[SERVER_ENCRYPT]

	if ok == true {
		encrypt = e.(bool)
	}

	if header.Encrypt == 1 {
		if encrypt == false {
			return nil, errors.New("this is a encrypt request,but server not support encrypt mode.")
		}

		e, ok := self.opt[SERVER_ENCRYPT_PRIVATE_KEY]

		if ok == true {
			encryptKey = e.(string)
		}

		if len(encryptKey) < 1 {
			return nil, errors.New("this is a encrypt request,but server not set a encrypt private key..")
		}
	}

	if header.Encrypt == 0 && encrypt == true {
		return nil, errors.New("this server is encrypt,but request is not encrypt mode")
	}

	return header, nil

}

func (self *Server) getRequest(header *Header) (*Request, error) {

	body_len := header.BodyLength

	body_buffer := self.body[90 : 90+body_len-8]

	request := NewRequest()

	encrypt := false
	encryptKey := ""

	e, ok := self.opt[SERVER_ENCRYPT]

	if ok == true {
		encrypt = e.(bool)
	}

	if encrypt {
		e, ok := self.opt[SERVER_ENCRYPT_PRIVATE_KEY]
		if ok == true {
			encryptKey = e.(string)
		}

		if len(encryptKey) < 1 {
			return nil, errors.New("encrypt_private_key is empty.")
		}

		encryptBody := &EncryptBody{
			Key:  []byte(encryptKey),
			Body: body_buffer[8:],
		}

		decryptBuffer := bytes.NewReader(body_buffer[:8])

		binary.Read(decryptBuffer, binary.BigEndian, &encryptBody.BodyLen)
		binary.Read(decryptBuffer, binary.BigEndian, &encryptBody.RealLen)

		data, err := encryptBody.Decrypt()

		if err != nil {
			return nil, errors.New("[Decrypt] error:" + err.Error())
		}
		body_buffer = data[0:encryptBody.RealLen]
	}

	err := packager.Unpack(header.Packager[:], body_buffer, request)

	if err != nil {

		return nil, err

	}

	return request, nil
}

func (self *Server) sendResponse(response *Response) error {

	sendPackData, err := packager.Pack(response.Protocol.Packager[:], response)
	if err != nil {
		return err
	}

	encrypt := false
	encryptKey := ""

	e, ok := self.opt[SERVER_ENCRYPT]

	if ok == true {
		encrypt = e.(bool)
	}

	if encrypt {

		e, ok := self.opt[SERVER_ENCRYPT_PRIVATE_KEY]
		if ok == true {
			encryptKey = e.(string)
		}

		if len(encryptKey) < 1 {
			return errors.New("encrypt_private_key is empty.")
		}

		encryptBody := &EncryptBody{
			Key: []byte(encryptKey),
		}

		encryptBody.Encrypt(sendPackData)

		temp := bytes.NewBufferString("")

		binary.Write(temp, binary.BigEndian, encryptBody.BodyLen)
		binary.Write(temp, binary.BigEndian, encryptBody.RealLen)
		temp.Write(encryptBody.Body[:encryptBody.BodyLen])
		sendPackData = temp.Bytes()
	}

	response.Protocol.BodyLength = uint32(len(sendPackData) + 8)
	self.ctx.ResponseWriter.Write(response.Protocol.Bytes().Bytes())
	self.ctx.ResponseWriter.Write(sendPackData)
	return nil

}

func (self *Server) call(request *Request, response *Response) {

	defer func() {
		if r := recover(); r != nil {
			response.Status = ERR_EMPTY_RESPONSE
			response.Error = "call handler internal panic:" + fmt.Sprint(r)
			debug.PrintStack()
		}
	}()

	call_params := request.Params.([]interface{})

	class_fv := reflect.ValueOf(self.class)

	methodMap, ok := self.methodMap[strings.ToLower(request.Method)]

	var err bool

	if ok == false {
		_, err = class_fv.Type().MethodByName(request.Method)
		methodMap = request.Method
	} else {
		_, err = class_fv.Type().MethodByName(methodMap)
	}

	if err == false {
		response.Status = ERR_EMPTY_RESPONSE
		response.Error = "call undefined api:" + request.Method
		return
	}

	fv := class_fv.MethodByName(methodMap)

	supportedDynamic := false

	e, ok := self.opt[SERVER_SUPPORT_DYANIMIC_PARAM]

	if ok {
		supportedDynamic = e.(bool)
	}

	var real_params []reflect.Value

	if supportedDynamic {
		real_params = make([]reflect.Value, fv.Type().NumIn())
	} else {

		if len(call_params) != fv.Type().NumIn() {
			response.Status = ERR_EMPTY_RESPONSE
			response.Error = "mismatch handler param size"
			return
		}

		real_params = make([]reflect.Value, len(call_params))
	}

	func() {

		for i := 0; i < len(real_params); i++ {
			if i >= len(call_params) {
				real_params[i] = reflect.Zero(fv.Type().In(i))
				continue
			}

			v := call_params[i]

			raw_val := reflect.ValueOf(v)

			//hack number
			if raw_val.Type().Name() == "Number" {

				fi := fv.Type().In(i)
				var coverErr error = nil
				verify := true
				nv := v.(json.Number)

				switch fi.Kind() {

				case reflect.Uint8:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(uint8(utv))
						break
					}

				case reflect.Uint16:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(uint16(utv))
						break
					}

				case reflect.Uint32:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(uint32(utv))
						break
					}

				case reflect.Uint64:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(uint64(utv))
						break
					}

				case reflect.Uint:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(uint(utv))
						break
					}

				case reflect.Int8:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(int8(utv))
						break
					}
				case reflect.Int16:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(int16(utv))
						break
					}
				case reflect.Int32:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(int32(utv))
						break
					}
				case reflect.Int64:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(int64(utv))
						break
					}
				case reflect.Int:
					{
						utv, err := nv.Int64()
						coverErr = err
						real_params[i] = reflect.ValueOf(int(utv))
						break
					}
				case reflect.Float32:
					{
						utv, err := nv.Float64()
						coverErr = err
						real_params[i] = reflect.ValueOf(float32(utv))
						break
					}
				case reflect.Float64:
					{
						utv, err := nv.Float64()
						coverErr = err
						real_params[i] = reflect.ValueOf(float64(utv))
						break
					}

				default:
					{
						verify = false
					}
				}

				if coverErr != nil {
					response.Status = ERR_EMPTY_RESPONSE
					response.Error = "cover number type error:" + coverErr.Error()
					return
				}

				if verify == true {
					continue
				}

			}

			if raw_val.Type().Name() == "string" {

				var coverErr error = nil
				verify := true

				switch fv.Type().In(i).Kind() {

				case reflect.Uint8:
					{

						n, e := strconv.ParseUint(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(uint8(n))
						break
					}
				case reflect.Uint16:
					{

						n, e := strconv.ParseUint(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(uint16(n))
						break

					}
				case reflect.Uint32:
					{
						n, e := strconv.ParseUint(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(uint32(n))
						break

					}
				case reflect.Uint64:
					{

						n, e := strconv.ParseUint(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(uint64(n))
						break

					}
				case reflect.Uint:
					{

						n, e := strconv.ParseUint(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(uint(n))
						break

					}

				case reflect.Int8:
					{

						n, e := strconv.ParseInt(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(int8(n))
						break

					}
				case reflect.Int16:
					{

						n, e := strconv.ParseInt(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(int16(n))
						break

					}
				case reflect.Int32:
					{

						n, e := strconv.ParseInt(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(int32(n))
						break

					}
				case reflect.Int64:
					{

						n, e := strconv.ParseInt(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(int64(n))
						break

					}

				case reflect.Int:
					{

						n, e := strconv.ParseInt(raw_val.String(), 10, 64)
						coverErr = e
						real_params[i] = reflect.ValueOf(int(n))
						break

					}

				case reflect.Float32:
					{
						n, e := strconv.ParseFloat(raw_val.String(), fv.Type().In(i).Bits())
						coverErr = e
						real_params[i] = reflect.ValueOf(float32(n))
						break
					}

				case reflect.Float64:
					{
						n, e := strconv.ParseFloat(raw_val.String(), fv.Type().In(i).Bits())
						coverErr = e
						real_params[i] = reflect.ValueOf(float64(n))
						break
					}

				default:
					{
						verify = false
					}

				}

				if coverErr != nil {
					response.Status = ERR_EMPTY_RESPONSE
					response.Error = "cover string to number error:" + coverErr.Error()
					return
				}

				if verify == true {
					continue
				}

			}

			real_params[i] = raw_val.Convert(fv.Type().In(i))
		}

		rs := fv.Call(real_params)
		if len(rs) < 1 {
			response.Return(nil)
			return
		}

		if len(rs) > 1 {
			response.Status = ERR_EMPTY_RESPONSE
			response.Error = "unsupprted multi value return on rpc call"
			return
		}

		response.Return(rs[0].Interface())
	}()

}

func (self *Server) Handle() (bool, error) {

	self.body = self.ctx.Input.RequestBody

	var err error

	if len(self.body) < (PROTOCOL_LENGTH + PACKAGER_LENGTH) {

		return false, errors.New("read request body error.")
	}

	header, err := self.getHeader()

	if err != nil {
		beego.Error(err)
		return false, err
	}

	request, err := self.getRequest(header)

	if err != nil {
		beego.Error(err)
		return false, err
	}

	response := NewResponse()
	response.Status = ERR_OKEY
	response.Protocol = header
	self.call(request, response)
	self.sendResponse(response)

	if response.Status != ERR_OKEY {

		beego.Warn(request.Id, request.Method, response.Error)

	} else {

		beego.Notice(request.Id, request.Method, "OKEY")

	}

	return true, nil
}

func init() {

	beego.BConfig.CopyRequestBody = true

}
