package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/viper"
)

var (
	server http.Server
	done   chan os.Signal
)

func StartServer() error {
	http.HandleFunc("/report", report)

	port := viper.GetUint("port")
	server = http.Server{
		Addr: fmt.Sprintf(":%d", port),
	}

	done = make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen: %s\n", err)
		}

		log.Println("Server stopped listening")
	}()
	log.Printf("Server listening on port %d", port)

	<-done
	return shutdown()
}

func StopServer() {
	close(done)
}

func shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer func() {
		cancel()
	}()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %+v", err)

		return err
	}

	log.Print("Server exited nicely")
	return nil
}
