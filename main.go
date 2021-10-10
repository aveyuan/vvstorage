package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

type SSO struct {
	Appkey   string `form:"appkey" binding:"required"`    //随机Key
	Date     int64  `form:"date" binding:"required"`      //过期时间
	FilePath string `form:"file_path" binding:"required"` //文件路径
	Sign     string `form:"sign" binding:"required"`      //签名
}

var token string
var debug bool = false
var host string
var port int

func main() {
	gin.SetMode(func() string {
		if debug {
			return gin.DebugMode
		}
		return gin.ReleaseMode
	}())
	r := gin.Default()
	base := new(Base)
	r.POST("/api_upload", base.upload)
	r.DELETE("/api_remove", base.Remove)
	r.Static("/", "./upload")
	log.Printf("启动成功,主机:%v端口:%v", host, port)
	r.Run(fmt.Sprintf("%v:%v", host, port))
}

func init() {
	flag.StringVar(&host, "h", "0.0.0.0", "input your host")
	flag.IntVar(&port, "p", 8001, "input your port")
	flag.StringVar(&token, "t", "", "input your token")
	flag.BoolVar(&debug, "d", false, "input your debug default is false")
	flag.Parse()
	if token == "" {
		log.Fatal("token is null")
		os.Exit(0)
	}
}

type Base struct{}

func (t *Base) upload(c *gin.Context) {
	var form SSO
	c.ShouldBindQuery(&form)
	log.Print(form)

	file, err := c.FormFile("file")
	if err != nil {
		t.RJson(402, "文件获取失败", c)
		return
	}
	log.Print(file.Filename, file.Size)

	// 验证签名
	if form.GetSignature(token) != form.Sign {
		t.RJson(402, "签名验证失败", c)
		return
	}
	dir := "./" + form.FilePath

	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		t.RJson(402, "文件夹创建失败", c)
		return
	}

	f, err := os.OpenFile(dir, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		log.Print(err)
		t.RJson(402, "文件创建失败", c)
		return
	}

	defer f.Close()

	sf, err := file.Open()
	if err != nil {
		t.RJson(402, "文件信息有误", c)
		return
	}

	if _, err := io.Copy(f, sf); err != nil {
		log.Print(err)
		t.RJson(402, "文件上传失败", c)
		return
	}

	t.RJson(200, "文件上传成功", c)
}

func (t *Base) Remove(c *gin.Context) {

	var form SSO
	c.ShouldBind(&form)

	// 验证签名
	if form.GetSignature(token) != form.Sign {
		t.RJson(402, "签名验证失败", c)
		return
	}

	if err := os.Remove("./" + form.FilePath); err != nil {
		t.RJson(402, "文件删除失败", c)
		return
	}

	t.RJson(200, "文件上传成功", c)
}

// GetSignature 签名生成
func (c *SSO) GetSignature(key string) string {
	toSing := fmt.Sprintf("%v%v%v", c.Appkey, c.FilePath, c.Date)
	byteSing := []byte(toSing)
	bas := base64.StdEncoding.EncodeToString(byteSing)
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(bas))
	ssoEncode := fmt.Sprintf("%x", mac.Sum(nil))
	return string(ssoEncode)
}

func (t *Base) RJson(code int, msg interface{}, c *gin.Context) {
	c.JSON(code, gin.H{
		"code": code,
		"msg":  msg,
	})
	c.Abort()
}

// GetRandomString 水机字符串生成
func GetRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
