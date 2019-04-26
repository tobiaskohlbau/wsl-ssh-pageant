package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

var (
	unixSocket   = flag.String("wsl", "", "Path to Unix socket for passthrough to WSL")
	namedPipe    = flag.String("winssh", "", "Named pipe for use with Win32 OpenSSH")
	dockerSocket = flag.String("docker", "", "Path to Unix socket for passthrough to WSL")
	gpgSocket    = flag.String("gpg", "", "Path to Unix socket folder for passthrough to WSL")
	verbose      = flag.Bool("verbose", false, "Enable verbose logging")
	force        = flag.Bool("force", false, "Forces the usage of the socket (unlink existing socket)")
)

const (
	// Windows constats
	invalidHandleValue = ^windows.Handle(0)
	pageReadWrite      = 0x4
	fileMapWrite       = 0x2

	// Windows errors
	errorSocketAlreadyInUse = 10048

	// ssh-agent/Pageant constants
	agentMaxMessageLength = 8192
	agentCopyDataID       = 0x804e50ba
)

// copyDataStruct is used to pass data in the WM_COPYDATA message.
// We directly pass a pointer to our copyDataStruct type, we need to be
// careful that it matches the Windows type exactly
type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

var queryPageantMutex sync.Mutex

func queryPageant(buf []byte) (result []byte, err error) {
	if len(buf) > agentMaxMessageLength {
		err = errors.New("Message too long")
		return
	}

	hwnd := win.FindWindow(syscall.StringToUTF16Ptr("Pageant"), syscall.StringToUTF16Ptr("Pageant"))

	if hwnd == 0 {
		err = errors.New("Could not find Pageant window")
		return
	}

	// Typically you'd add thread ID here but thread ID isn't useful in Go
	// We would need goroutine ID but Go hides this and provides no good way of
	// accessing it, instead we serialise calls to queryPageant and treat it
	// as not being goroutine safe
	mapName := fmt.Sprintf("WSLPageantRequest")
	queryPageantMutex.Lock()

	fileMap, err := windows.CreateFileMapping(invalidHandleValue, nil, pageReadWrite, 0, agentMaxMessageLength, syscall.StringToUTF16Ptr(mapName))
	if err != nil {
		queryPageantMutex.Unlock()
		return
	}
	defer func() {
		windows.CloseHandle(fileMap)
		queryPageantMutex.Unlock()
	}()

	sharedMemory, err := windows.MapViewOfFile(fileMap, fileMapWrite, 0, 0, 0)
	if err != nil {
		return
	}
	defer windows.UnmapViewOfFile(sharedMemory)

	sharedMemoryArray := (*[agentMaxMessageLength]byte)(unsafe.Pointer(sharedMemory))
	copy(sharedMemoryArray[:], buf)

	mapNameWithNul := mapName + "\000"

	// We use our knowledge of Go strings to get the length and pointer to the
	// data and the length directly
	cds := copyDataStruct{
		dwData: agentCopyDataID,
		cbData: uint32(((*reflect.StringHeader)(unsafe.Pointer(&mapNameWithNul))).Len),
		lpData: ((*reflect.StringHeader)(unsafe.Pointer(&mapNameWithNul))).Data,
	}

	ret := win.SendMessage(hwnd, win.WM_COPYDATA, 0, uintptr(unsafe.Pointer(&cds)))
	if ret == 0 {
		err = errors.New("WM_COPYDATA failed")
		return
	}

	len := binary.BigEndian.Uint32(sharedMemoryArray[:4])
	len += 4

	if len > agentMaxMessageLength {
		err = errors.New("Return message too long")
		return
	}

	result = make([]byte, len)
	copy(result, sharedMemoryArray[:len])

	return
}

var failureMessage = [...]byte{0, 0, 0, 1, 5}

func handleSSHConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		lenBuf := make([]byte, 4)
		_, err := io.ReadFull(reader, lenBuf)
		if err != nil {
			if *verbose {
				log.Printf("io.ReadFull error '%s'", err)
			}
			return
		}

		len := binary.BigEndian.Uint32(lenBuf)
		buf := make([]byte, len)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			if *verbose {
				log.Printf("io.ReadFull error '%s'", err)
			}
			return
		}

		result, err := queryPageant(append(lenBuf, buf...))
		if err != nil {
			// If for some reason talking to Pageant fails we fall back to
			// sending an agent error to the client
			if *verbose {
				log.Printf("Pageant query error '%s'", err)
			}
			result = failureMessage[:]
		}

		_, err = conn.Write(result)
		if err != nil {
			if *verbose {
				log.Printf("net.Conn.Write error '%s'", err)
			}
			return
		}
	}
}

func handleDockerConnection(conn net.Conn) {
	defer conn.Close()

	namedPipeFullName := "\\\\.\\pipe\\docker_engine"
	timeout := 3 * time.Second
	dockerConn, err := winio.DialPipe(namedPipeFullName, &timeout)
	if err != nil {
		log.Fatalf("Could not connect named pipe %s, error %q\n", namedPipeFullName, err)
	}

	go func() {
		_, err := io.Copy(dockerConn, conn)
		if err != nil && err != io.EOF {
			log.Printf("Could not copy docker data from named pipe to socket: %q", err)
		}
	}()

	_, err = io.Copy(conn, dockerConn)
	if err != nil && err != io.EOF {
		log.Printf("Could not copy docker data from socket to named pipe: %s", err)
	}
}

func handleGPGConnection(conn net.Conn, path string) {
	defer conn.Close()

	var port int
	var nonce [16]byte

	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(file)

	tmp, _, err := reader.ReadLine()
	port, err = strconv.Atoi(string(tmp))
	if err != nil {
		log.Fatalf("Could not read port from gpg socket: %q", err)
	}

	n, err := reader.Read(nonce[:])
	if err != nil {
		log.Fatalf("Could not read port from gpg nonce: %q", err)
	}

	if n != 16 {
		log.Fatal("Could not connet gpg: incorrect number of bytes for nonceRead incorrect number of bytes for nonce")
	}

	gpgConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("Could not connet gpg: %s", err)
	}

	_, err = gpgConn.Write(nonce[:])
	if err != nil {
		log.Fatalf("Could not authenticate gpg: %q\n", err)
	}

	go func() {
		_, err := io.Copy(gpgConn, conn)
		if err != nil && err != io.EOF {
			log.Printf("Could not copy gpg data from assuan socket to socket: %q\n", err)
		}
	}()

	_, err = io.Copy(conn, gpgConn)
	if err != nil && err != io.EOF {
		log.Printf("Could not copy gpg data from socket to assuan socket: %q\n", err)
	}
}

func listenLoop(ln net.Listener, handler func(conn net.Conn)) {
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("net.Listener.Accept error '%s'", err)
			return
		}

		if *verbose {
			log.Printf("New connection: %v\n", conn)
		}

		go handler(conn)
	}
}

func gpg(assuan, socket string) {
	unix, err := net.Listen("unix", socket)
	if *force && err != nil {
		log.Printf("Could not open socket %s, error '%s'\nTrying to unlink %s\n", socket, err, socket)
		operr, ok := err.(*net.OpError)
		if !ok {
			log.Fatalf("Could not unlink socket %s, error is not *net.OpError\n", socket)
		}
		syscallerr, ok := operr.Err.(*os.SyscallError)
		if !ok {
			log.Fatalf("Could not unlink socket %s, error is not *os.SyscallError\n", socket)
		}
		errno, ok := syscallerr.Err.(syscall.Errno)
		if !ok {
			log.Fatalf("Could not unlink socket %s, error is not syscall.Errno\n", socket)
		}
		if errno == errorSocketAlreadyInUse {
			if err := syscall.Unlink(socket); err != nil {
				log.Fatalf("Could not unlink socket %s, error %q\n", socket, err)
			}
		}
		unix, err = net.Listen("unix", socket)
	}
	if err != nil {
		log.Fatalf("Could not open socket %s, error '%s'\n", socket, err)
	}

	// defer unix.Close()
	log.Printf("Listening on Unix socket: %s\n", socket)
	go func() {
		listenLoop(unix, func(conn net.Conn) { handleGPGConnection(conn, assuan) })
	}()
}

func main() {
	flag.Parse()

	var unix, pipe net.Listener
	var err error

	done := make(chan bool, 1)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		switch sig {
		case os.Interrupt:
			log.Printf("Caught signal")
			done <- true
		}
	}()

	if *unixSocket != "" {
		unix, err = net.Listen("unix", *unixSocket)
		if *force && err != nil {
			log.Printf("Could not open socket %s, error '%s'\nTrying to unlink %s\n", *unixSocket, err, *unixSocket)
			operr, ok := err.(*net.OpError)
			if !ok {
				log.Fatalf("Could not unlink socket %s, error is not *net.OpError\n", *unixSocket)
			}
			syscallerr, ok := operr.Err.(*os.SyscallError)
			if !ok {
				log.Fatalf("Could not unlink socket %s, error is not *os.SyscallError\n", *unixSocket)
			}
			errno, ok := syscallerr.Err.(syscall.Errno)
			if !ok {
				log.Fatalf("Could not unlink socket %s, error is not syscall.Errno\n", *unixSocket)
			}
			if errno == errorSocketAlreadyInUse {
				if err := syscall.Unlink(*unixSocket); err != nil {
					log.Fatalf("Could not unlink socket %s, error %q\n", *unixSocket, err)
				}
			}
			unix, err = net.Listen("unix", *unixSocket)
		}
		if err != nil {
			log.Fatalf("Could not open socket %s, error '%s'\n", *unixSocket, err)
		}

		defer unix.Close()
		log.Printf("Listening on Unix socket: %s\n", *unixSocket)
		go func() {
			listenLoop(unix, handleSSHConnection)
			// If for some reason our listener breaks, kill the program
			done <- true
		}()
	}

	if *namedPipe != "" {
		namedPipeFullName := "\\\\.\\pipe\\" + *namedPipe
		var cfg = &winio.PipeConfig{}
		pipe, err = winio.ListenPipe(namedPipeFullName, cfg)

		if err != nil {
			log.Fatalf("Could not open named pipe %s, error '%s'\n", namedPipeFullName, err)
		}

		defer pipe.Close()
		log.Printf("Listening on named pipe: %s\n", namedPipeFullName)
		go func() {
			listenLoop(pipe, handleSSHConnection)
			// If for some reason our listener breaks, kill the program
			done <- true
		}()
	}

	if *dockerSocket != "" {
		unix, err = net.Listen("unix", *dockerSocket)
		if *force && err != nil {
			log.Printf("Could not open socket %s, error '%s'\nTrying to unlink %s\n", *unixSocket, err, *dockerSocket)
			operr, ok := err.(*net.OpError)
			if !ok {
				log.Fatalf("Could not unlink socket %s, error is not *net.OpError\n", *dockerSocket)
			}
			syscallerr, ok := operr.Err.(*os.SyscallError)
			if !ok {
				log.Fatalf("Could not unlink socket %s, error is not *os.SyscallError\n", *dockerSocket)
			}
			errno, ok := syscallerr.Err.(syscall.Errno)
			if !ok {
				log.Fatalf("Could not unlink socket %s, error is not syscall.Errno\n", *dockerSocket)
			}
			if errno == errorSocketAlreadyInUse {
				if err := syscall.Unlink(*dockerSocket); err != nil {
					log.Fatalf("Could not unlink socket %s, error %q\n", *dockerSocket, err)
				}
			}
			unix, err = net.Listen("unix", *dockerSocket)
		}
		if err != nil {
			log.Fatalf("Could not open socket %s, error '%s'\n", *dockerSocket, err)
		}

		defer unix.Close()
		log.Printf("Listening on Unix socket: %s\n", *dockerSocket)
		go func() {
			listenLoop(unix, handleDockerConnection)
			// If for some reason our listener breaks, kill the program
			done <- true
		}()
	}

	if *gpgSocket != "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("failed to find user home dir")
		}
		basePath := filepath.Join(homeDir, "AppData", "Roaming", "gnupg")
		gpg(filepath.Join(basePath, "S.gpg-agent"), filepath.Join(*gpgSocket, "S.gpg-agent"))
		gpg(filepath.Join(basePath, "S.gpg-agent.browser"), filepath.Join(*gpgSocket, "S.gpg-agent.browser"))
		gpg(filepath.Join(basePath, "S.gpg-agent.extra"), filepath.Join(*gpgSocket, "S.gpg-agent.extra"))
	}

	if *namedPipe == "" && *unixSocket == "" && *dockerSocket == "" && *gpgSocket == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Wait until we are signalled as finished
	<-done

	log.Printf("Exiting...")
}
