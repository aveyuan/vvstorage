package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/ini.v1"
)

type SSO struct {
	URL      string
	Appkey   string //Appkey
	Date     int64  //过期时间
	Domain   string //用户名
	FileName string //用户ID
}

func main() {

	ini, err := ini.Load("app.ini")
	if err != nil {
		log.Fatal("配置文件读取出错,请检查", err.Error())
	}

	sso := SSO{
		Appkey: GetRandomString(10),
		Date:   time.Now().Add(30 * time.Second).Unix(),
	}
	//得到签名
	makesigkey := sso.GetSignature(ini.Section("").Key("token").String())
	//生成登录的地址
	url := fmt.Sprintf("%v?app_key=%v&domain=%v&date=%v&filename=%v&sign=%v", sso.URL, sso.Appkey, sso.Domain, sso.Date, sso.FileName, makesigkey)
	fmt.Println(url)

	r := gin.Default()

	r.MaxMultipartMemory = 8 << 20 // 8 MiB
	r.POST("/upload", func(c *gin.Context) {

		file, err := c.FormFile("file")
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
			return
		}

		basePath := "./upload/"
		filename := basePath + filepath.Base(file.Filename)
		if err := c.SaveUploadedFile(file, filename); err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
			return
		}

		c.String(http.StatusOK, fmt.Sprintf("文件 %s 上传成功 ", file.Filename))
	})

	r.Static("/", "/upload")
	r.Run(":8080")
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
