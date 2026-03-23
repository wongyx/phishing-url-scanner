package db

import (
	"fmt"
	"time"

	"github.com/wongyx/phishing-url-scanner/internal/config"
	"github.com/wongyx/phishing-url-scanner/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Connect(cfg *config.DB) (*gorm.DB, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable", cfg.User, cfg.Password, cfg.Host, cfg.Name)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	err = db.AutoMigrate(&models.Scan{})
	if err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, nil
}
