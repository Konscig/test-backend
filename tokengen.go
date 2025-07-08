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
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  userID,
		"exp":  exp,
		"type": "refresh",
		"iat":  time.Now().Unix(),
	}).SignedString([]byte(os.Getenv("SECRET_KEY")))
}

func checkToken(tokenString string, tokenType string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		// 	return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		// }
		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	if err == nil && token.Valid && tokenType != "" && token != nil {
		claims, _ := token.Claims.(jwt.MapClaims)
		exactType := claims["type"].(string)
		if exactType != tokenType {
			return token, fmt.Errorf("invalid token type")
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
		return uuid.Nil, fmt.Errorf(err.Error())
	}
	return subUUID, nil
}

func extractTypeAccess(tokenString string) (string, error) {
	var tokenType string
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	if err == nil {
		tokenType = token.Claims.(jwt.MapClaims)["type"].(string)
	}
	return tokenType, nil
}
