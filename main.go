package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type SSO struct {
	Appkey   string `form:"appkey" binding:"required"`    //随机Key
	Date     int64  `form:"date" binding:"required"`      //过期时间
	Domain   string `form:"domain" binding:"required"`    //目录
	FileName string `form:"file_name" binding:"required"` //文件名称
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
	r.POST("/upload", new(Base).upload)
	r.Static("/", "/upload")
	log.Printf("启动成功,主机:%v端口:%v", host, port)
	r.Run(":8080")
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
	c.ShouldBind(&form)

	file, err := c.FormFile("file")
	if err != nil {
		t.RJson(402, "文件获取失败", c)
		return
	}

	if file.Filename != form.FileName {
		t.RJson(402, "文件比对失败", c)
		return
	}

	// 验证签名
	if form.GetSignature(token) != form.Sign {
		t.RJson(402, "签名验证失败", c)
		return
	}

	// 开始处理文件
	pwd, _ := os.Getwd()
	fTime := time.Now().Format("2006/01/02")

	// 压缩文件

	// 添加水印
	uuidStr := uuid.New().String()
	uuid := strings.Replace(uuidStr, "-", "", -1)

	ext := filepath.Ext(file.Filename)
	newFileName := uuid + ext

	savePath := "/uploads/" + form.Domain + "/" + fTime
	upPath := savePath + "/" + newFileName
	fileTime := pwd + savePath
	// name改为uuid
	// 计算
	saveImg := fileTime + "/" + newFileName

	if err := os.MkdirAll(fileTime, 0755); err != nil {
		t.RJson(402, "文件创建失败", c)
		return
	}
	if err := c.SaveUploadedFile(file, saveImg); err != nil {
		t.RJson(402, "文件上传失败", c)
		return
	}

	t.RJson(200, upPath, c)
}

// GetSignature 签名生成
func (c *SSO) GetSignature(key string) string {
	toSing := fmt.Sprintf("%v%v%v%v", c.Appkey, c.Domain, c.FileName, c.Date)
	byteSing := []byte(toSing)
	bas := base64.StdEncoding.EncodeToString(byteSing)
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(bas))
	ssoEncode := fmt.Sprintf("%x", mac.Sum(nil))
	return string(ssoEncode)
}

func (t *Base) RJson(code int, msg interface{}, c *gin.Context) {
	c.JSON(200, gin.H{
		"code": 402,
		"msg":  "文件获取失败",
	})
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
