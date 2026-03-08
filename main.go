package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/civiledcode/grxm-iam/api"
	"github.com/civiledcode/grxm-iam/auth"
	"github.com/civiledcode/grxm-iam/config"
	"github.com/civiledcode/grxm-iam/db"
	"github.com/civiledcode/grxm-iam/token"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func main() {
	configPath := os.Getenv("IAM_CONFIG_LOCATION")
	if configPath == "" {
		configPath = "./config.json"
	}

	conf, err := config.LoadConfig(configPath)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err, "path", configPath)
		os.Exit(1)
	}

	// Setup MongoDB connection
	mongoClient, err := mongo.Connect(options.Client().ApplyURI(conf.Database.URI))
	if err != nil {
		slog.Error("Failed to connect to MongoDB", "error", err)
		os.Exit(1)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		mongoClient.Disconnect(ctx)
	}()

	database := mongoClient.Database(conf.Database.Database)
	userRepo := db.NewMongoUserRepository(database)

	tokenSource := token.GetTokenSource(conf)
	if tokenSource == nil {
		slog.Error("Failed to initialize token source")
		os.Exit(1)
	}

	server := api.NewServer(conf, tokenSource, userRepo)

	for _, method := range auth.DefaultRegistrationMethods {
		server.RegisterRegisterMethod(method)
		slog.Info("Registered registration method", "id", method.ID())
	}

	for _, method := range auth.DefaultLoginMethods {
		server.RegisterLoginMethod(method)
		slog.Info("Registered login method", "id", method.ID())
	}

	if err := server.Start(); err != nil {
		slog.Error("Server encountered an error", "error", err)
		os.Exit(1)
	}
}
