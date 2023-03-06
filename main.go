package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

const zipSuffix string = ".zip"
const aesSuffix string = ".aes"

func main() {
	if len(os.Args) != 2 {
		fmt.Println("数据加密软件\n\t用法: crypt 文件或文件夹")
		os.Exit(0)
	}
	absPath, e := filepath.Abs(".")
	catch(e, "获取程序当前执行目录", absPath)

	name := getFileInfoName(os.Args[1])
	password := getPassword()

	if strings.HasSuffix(name, aesSuffix) {
		name = strings.TrimSuffix(name, aesSuffix)
		e := deCryptZip(name, password)
		catch(e, "解密文件", name)
		e = deZip(name)
		catch(e, "解压")
		e = os.RemoveAll(name + aesSuffix)
		catch(e, "清理加密文件")
		e = os.RemoveAll(name + zipSuffix)
		catch(e, "清理解压前的压缩文件")
	} else {
		e := enZip(name)
		catch(e, "压缩")
		e = enCryptZip(name, password)
		catch(e, "压缩文件加密")
		e = os.RemoveAll(name + zipSuffix)
		catch(e, "清理加密前的压缩文件")
		e = os.RemoveAll(name)
		catch(e, "清理加密前的文件或文件夹")
	}
}

func getFileInfoName(name string) string {
	file, e := os.Open(name)
	catch(e, "打开", name)
	defer file.Close()
	fileInfo, e := file.Stat()
	catch(e, "读取", name)
	return fileInfo.Name()
}

func getPassword() string {
	fmt.Print("请输入密码: ")
	password1, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n请确认密码: ")
	password2, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if bytes.Equal(password1, password2) {
		return string(password1)
	} else {
		log.Println("密码不一致!")
		return getPassword()
	}
}

func catch(err error, message ...string) {
	if len(message) == 0 {
		if err != nil {
			// panic(err.Error())
			log.Fatalln("未知错误", "[失败]")
		}
	} else {
		if err == nil {
			log.Println(strings.Join(message, " "), "[成功]")
		} else {
			// panic(err.Error())
			log.Fatalln(strings.Join(message, " "), "[失败]")
		}
	}
}

func enZip(name string) error {
	// 创建一个压缩文件
	targetZip, e := os.Create(name + zipSuffix)
	catch(e)
	defer targetZip.Close()
	// 创建一个压缩文件写入器
	targetZipWriter := zip.NewWriter(targetZip)
	defer targetZipWriter.Close()

	// 遍历文件夹或者单个文件
	return filepath.Walk(name, func(filePath string, fileInfo os.FileInfo, e error) error {
		catch(e)
		// 创建文件头
		fileInfoHeader, e := zip.FileInfoHeader(fileInfo)
		catch(e)
		// 设置相对路径
		fileInfoHeader.Name, e = filepath.Rel(filepath.Dir(name), filePath)
		catch(e)
		// 设置时间
		fileInfoHeader.Modified = time.Unix(fileInfo.ModTime().Unix(), 0)

		if fileInfo.IsDir() {
			fileInfoHeader.Name += "/"
		} else {
			// 设置压缩方法
			fileInfoHeader.Method = zip.Deflate
		}
		// 压缩对象写入文件信息
		zipWriter, e := targetZipWriter.CreateHeader(fileInfoHeader)
		catch(e, "写入信息", filePath)

		if fileInfo.IsDir() {
			return nil
		} else {
			zipReader, e := os.Open(filePath)
			catch(e)
			defer zipReader.Close()
			_, e = io.Copy(zipWriter, zipReader)
			catch(e, "压缩文件", filePath)
			return e
		}
	})
}

func deZip(name string) error {
	zipReader, e := zip.OpenReader(name + zipSuffix)
	catch(e)
	defer zipReader.Close()
	// 遍历压缩包内文件
	for _, file := range zipReader.File {
		filePath := file.Name
		mtime := file.FileInfo().ModTime()
		if file.FileInfo().IsDir() {
			// 创建文件夹目录
			e := os.MkdirAll(filePath, os.ModePerm)
			catch(e, "解压目录", filePath)
		} else {
			// 创建文件父目录
			e := os.MkdirAll(filepath.Dir(filePath), os.ModePerm)
			catch(e)
			targetFile, e := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
			catch(e)
			defer targetFile.Close()

			zippedFile, e := file.Open()
			catch(e)
			defer zippedFile.Close()

			_, e = io.Copy(targetFile, zippedFile)
			catch(e)
			// 设置时间
			e = os.Chtimes(filePath, mtime, mtime)
			catch(e, "解压文件", filePath)
		}
	}
	return nil
}

func toMd5(password string) string {
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

func enCrypt(data []byte, password string) []byte {
	block, e := aes.NewCipher([]byte(toMd5(password)))
	catch(e)
	gcm, e := cipher.NewGCM(block)
	catch(e)
	nonce := make([]byte, gcm.NonceSize())
	_, e = io.ReadFull(rand.Reader, nonce)
	catch(e)
	return gcm.Seal(nonce, nonce, data, nil)
}

func deCrypt(data []byte, password string) []byte {
	block, e := aes.NewCipher([]byte(toMd5(password)))
	catch(e)
	gcm, e := cipher.NewGCM(block)
	catch(e)
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		catch(errors.New(""), "解密数据")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	fileByte, e := gcm.Open(nil, nonce, ciphertext, nil)
	catch(e, "校验密码")
	return fileByte
}

func enCryptZip(name string, password string) error {
	fileData, e := os.ReadFile(name + zipSuffix)
	catch(e)

	// 先尝试加密文件
	fileData = enCrypt(fileData, password)

	target, e := os.Create(name + aesSuffix)
	catch(e)
	defer target.Close()

	_, e = target.Write(fileData)
	return e
}

func deCryptZip(name string, password string) error {
	fileData, e := os.ReadFile(name + aesSuffix)
	catch(e)

	// 先尝试解密文件
	fileData = deCrypt(fileData, password)

	target, e := os.Create(name + zipSuffix)
	catch(e)
	defer target.Close()

	_, e = target.Write(fileData)
	return e
}
