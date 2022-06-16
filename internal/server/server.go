package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	server http.Server
	done   chan os.Signal
)

func StartServer() {
	sugar := zap.L().Sugar()

	http.HandleFunc("/report", report)

	port := ":" + viper.GetString("port")
	var addr string
	if viper.GetBool("dev-mode") {
		addr = "localhost" + port
	} else {
		addr = port
	}
	server = http.Server{
		Addr: addr,
	}

	done = make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Fatalf("Listen: %s\n", err)
		}

		sugar.Info("Server stopped listening")
	}()
	sugar.Info("Server listening on " + addr)

	<-done

	shutdown()
}

func StopServer() {
	close(done)
}

func shutdown() {
	sugar := zap.L().Sugar()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer func() {
		cancel()
	}()

	if err := server.Shutdown(ctx); err != nil {
		sugar.Fatalf("Server shutdown failed: %+v", err)
	}

	sugar.Info("Server exited nicely")
}
