package main

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateAccessToken(userID string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":  userID,
		"exp":  time.Now().Add(time.Minute * 15).Unix(),
		"type": "access",
		"iat":  time.Now().Unix(),
	}).SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func generateRefreshToken(userID string, exp int64) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  userID,
		"exp":  exp,
		"type": "refresh",
		"iat":  time.Now().Unix(),
	}).SignedString([]byte(os.Getenv("SECRET_KEY")))
}
