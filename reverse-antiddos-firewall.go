/*
Gelistirici: github.com/ertugrulturan
T13R ANTI-DDOS/ANTI-FLOOD Reverse proxy kernel
*/
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var (
	// Duzenlencek kisim
	waf_port                 = "127.0.0.1:80"     //waf cikisi
	real_port                = "127.0.0.1:1881" //servis (apache/plesk gibi ayarlardan desitirin 80 e kernel gelcek) ip port
	pps_per_ip_limit         = 10               //Ip ye izin verilen per pps kisitlamasi
	connection_limit         = 10               //IP Den baglanti kisitlamasi
	banned_time      float64 = 60               //IP Ban suresi

	connection_per_ip sync.Map 
	rps_per_ip        sync.Map 
	banned_list       sync.Map

	connMap sync.Map 
	errMsg  = "HTTP/1.1 503 service unavailable\r\n\r\n"

	access_log_chan = make(chan string)
	banned_log_chan = make(chan string)
)

func main() {

	listener, err := net.Listen("tcp", waf_port)
	if err != nil {
		panic("baglanti hatasi:" + err.Error())
	}
	go access_log()
	go banned_log()
	go unban()
	go monitor()
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Hatayi Kabul Et:", err)
			continue
		}
		remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0] 
		if isBanned(remoteIP) {
			conn.Close()
			continue
		}
		connections, ok := connection_per_ip.Load(remoteIP)
		if ok {
			if connections.(int) >= connection_limit {
				banned_list.Store(remoteIP, time.Now())
				banned_log_chan <- remoteIP + " [" + time.Now().Format("2020-12-02 15:04:05") + "] Baglantı siniri nedeniyle yasaklandi!"
				conn.Close()
				continue
			}
			connection_per_ip.Store(remoteIP, connections.(int)+1)
		} else {
			connection_per_ip.Store(remoteIP, 1)
		}
		connMap.Store(conn.RemoteAddr().String(), conn)
		access_log_chan <- remoteIP + " [" + time.Now().Format("2020-12-02 15:04:05") + "] Baglandi!"
		go handle(conn, remoteIP)
	}
}

func access_log() {
	file, err := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Hata mesaji: %s\n", err)
		os.Exit(1)
	}
	for v := range access_log_chan { //Kanalı kapattıktan sonra duracak
		file.Write(str2bytes(v + "\n"))
	}
}

func banned_log() {
	file, err := os.OpenFile("banned.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Hata mesaji: %s\n", err)
		os.Exit(1)
	}
	for v := range banned_log_chan { //Kanalı kapattıktan sonra duracak
		file.Write(str2bytes(v + "\n"))
	}
}

func unban() {
	for {
		banned_list.Range(func(ip, time_banned interface{}) bool {
			tmp := time_banned.(time.Time)
			if used := time.Since(tmp); used.Seconds() >= banned_time {
				banned_list.Delete(ip.(string))
			}
			return true
		})
		time.Sleep(time.Second * 1) //1 Saniyede bir kontrol et
	}
}

func monitor() {
	for {
		rps := 0
		currentConn := 0
		bannedIP := 0
		rps_per_ip.Range(func(ip, times interface{}) bool {
			rps++
			if times.(int) >= pps_per_ip_limit { //limitle pps
				banned_list.Store(ip.(string), time.Now())
				banned_log_chan <- ip.(string) + " [" + time.Now().Format("2020-12-02 15:04:05") + "] Pps siniri nedeniyle yasaklandi!"
			}
			rps_per_ip.Delete(ip.(string))
			return true
		})
		connMap.Range(func(addr, conn interface{}) bool {
			currentConn++
			return true
		})
		banned_list.Range(func(ip, time_banned interface{}) bool {
			bannedIP++
			return true
		})
		fmt.Printf("Baglantilar: %d \nYasaklanan IP: %d \nRps: %d \n", currentConn, bannedIP, rps)
		time.Sleep(time.Second)
		clearScreen()
	}
}

func isBanned(remoteIP string) bool {
	banned := false
	banned_list.Range(func(ip, _ interface{}) bool {
		if ip == remoteIP {
			banned = true
			return false
		}
		return true
	})
	return banned
}

/*
func readhttp(src net.Conn) (string, bool) { 
	buf := make([]byte, 8192) // 65535 bitin üzerinde bir paket göndermeyeceğinizi düşünüyorum :D
	payload := ""
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				return "", false
			}
			break
		}

			TODO:
			Need to check post header
			because the post data is after the \r\n\r\n

		if n > 0 {
			payload += bytes2str(buf[:n])
			if len(payload) > 4 {
				if payload[len(payload)-4:] == "\r\n\r\n" { //2 crlf, http talebinin sonu
					break
				}
			}
		}
	}
	return payload, true
}*/

func handle(src net.Conn, remoteIP string) {
	defer src.Close()
	defer func() {
		connections, ok := connection_per_ip.Load(remoteIP)
		if ok && connections.(int) > 0 {
			connection_per_ip.Store(remoteIP, connections.(int)-1)
		} else {
			connection_per_ip.Delete(remoteIP)
		}

		connMap.Delete(src.RemoteAddr().String())
	}()
	if src, ok := src.(*net.TCPConn); ok {
		src.SetNoDelay(false)
	}
	var dst net.Conn
	requestsPerConnection := 0
	for {
		src.SetDeadline(time.Now().Add(10 * time.Second)) //10 saniye timeout

		if isBanned(remoteIP) {
			return
		}
		if requestsPerConnection >= 50 {
			return
		}
		buf := make([]byte, 8192) 
		n, err := src.Read(buf)
		if err != nil {
			if dst != nil {
				dst.Close()
			}
			return
		}
		request := buf[:n]
		/*
			request, ok := readhttp(src)
			if !ok {
				if dst != nil {
					dst.Close()
				}
				return
			}*/
		if dst == nil {
			//fmt.Println("Gercek sunucuya baglanti baslattildi")
			dst, err = net.DialTimeout("tcp", real_port, time.Second*10)
			if err != nil {
				src.Write(str2bytes(errMsg))
				return
			}
			if dst, ok := dst.(*net.TCPConn); ok {
				dst.SetNoDelay(false)
			}
			go func() {
				defer dst.Close()
				io.Copy(src, dst)
			}()
		} else {
			//fmt.Println("Bağlantıyı yeniden kullan")
		}
		dst.SetDeadline(time.Now().Add(10 * time.Second)) //10 saniye sonra timeout
		dst.Write(request)
		//dst.Write(str2bytes(request))
		//fmt.Println(request)//Bazi enjeksiyon veya istismar gibi istekleri daha sonra filtreleyebiliriz ...
		requestsPerConnection++
		rps, ok := rps_per_ip.Load(remoteIP)
		if ok {
			rps_per_ip.Store(remoteIP, rps.(int)+1)
		} else {
			rps_per_ip.Store(remoteIP, 1)
		}
	}
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func str2bytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}
func bytes2str(s []byte) string {
	return *(*string)(unsafe.Pointer(&s))
}
