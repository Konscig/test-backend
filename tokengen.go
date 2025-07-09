package main

import (
	"fmt"
	"os"
	"time"

	"github.com/gofrs/uuid/v5"
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
	return jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":  userID,
		"exp":  exp,
		"type": "refresh",
		"iat":  time.Now().Unix(),
	}).SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func checkToken(tokenString string, tokenType string) (*jwt.Token, error) {
	fmt.Println("income token:", tokenString)
	fmt.Println("income type:", tokenType)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	fmt.Println("parsed token:", token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token")
	}
	if token.Valid && tokenType != "" && token != nil {
		claims, _ := token.Claims.(jwt.MapClaims)
		exactType := claims["type"].(string)
		if exactType != tokenType {
			return nil, fmt.Errorf("invalid token type")
		}
		exp, err := claims.GetExpirationTime()
		if err != nil {
			return nil, fmt.Errorf("no exp time")
		}
		if time.Now().After(exp.Time) {
			return nil, fmt.Errorf("token expired")
		}
	}
	return token, err
}

func extractSub(token *jwt.Token) (uuid.UUID, error) {
	if token == nil {
		return uuid.Nil, fmt.Errorf("token is nil")
	}
	sub, exists := token.Claims.(jwt.MapClaims)["sub"].(string)
	if !exists {
		return uuid.Nil, fmt.Errorf("sub claim not found")
	}
	subUUID, err := uuid.FromString(sub)
	if err != nil {
		return uuid.Nil, fmt.Errorf("uuid parse error")
	}
	return subUUID, nil
}

func getIat(token *jwt.Token) (time.Time, error) {
	iat, exists := token.Claims.(jwt.MapClaims)["iat"].(float64)
	if !exists {
		return time.Time{}, fmt.Errorf("iat claim not found")
	}
	return time.Unix(int64(iat), 0), nil
}
