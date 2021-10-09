package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

type SSO struct {
	URL      string
	Appkey   string //Appkey
	UserName string //用户名
	Date     int64  //过期时间
	UserID   string //用户ID
}

func main() {

	r := gin.Default()

	r.MaxMultipartMemory = 8 << 20 // 8 MiB
	r.POST("/upload", func(c *gin.Context) {
		sso := SSO{
			Appkey:   GetRandomString(10),
			UserName: os.Args[3],
			Date:     time.Now().Add(30 * time.Second).Unix(),
			UserID:   os.Args[4],
			URL:      os.Args[1],
		}
		//得到签名
		makesigkey := sso.GetSignature(os.Args[2])
		//生成登录的地址
		url := fmt.Sprintf("%v?app_key=%v&user_name=%v&date=%v&user_id=%v&sign=%v", sso.URL, sso.Appkey, sso.UserName, sso.Date, sso.UserID, makesigkey)
		fmt.Println(url)

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
	toSing := fmt.Sprintf("%v%v%v%v", c.Appkey, c.UserName, c.UserID, c.Date)
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
