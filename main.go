package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func DatabaseMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("db", db)
		c.Next()
	}
}

func extractBearerToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is missing")
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", fmt.Errorf("invalid authorization header format")
	}

	token := strings.TrimPrefix(authHeader, prefix)
	if token == "" {
		return "", fmt.Errorf("token is missing")
	}

	return token, nil
}

func CheckTokenMiddleware(tokenType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		db, ok := c.Value("db").(*gorm.DB)
		if !ok {
			c.JSON(500, gin.H{"error": "DB connection not found"})
			return
		}

		bearerToken, err := extractBearerToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		var token *jwt.Token
		_, err = base64.StdEncoding.DecodeString(bearerToken)
		if err != nil {
			tokenType = "access"
		} else {
			tokenType = "refresh"
		}

		fmt.Println("1", tokenType)

		if tokenType == "refresh" {
			clearToken, err := base64.StdEncoding.DecodeString(bearerToken)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "token decoding error"})
				c.Abort()
				return
			}

			token, err = checkToken(string(clearToken), tokenType)
			fmt.Println("2", token)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				c.Abort()
				return
			}

			sub, err := extractSub(token)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				c.Abort()
				return
			}

			var refreshTokens []RefreshToken
			err = db.Where("user_id = ? AND expired = false", sub).Find(&refreshTokens).Error
			if err != nil {
				fmt.Println("refresh token not found")
				c.JSON(401, gin.H{"error": err.Error()})
				c.Abort()
				return
			}

			shaToken := sha256.Sum256([]byte(bearerToken))
			var spottedToken *RefreshToken
			for i := range refreshTokens {
				err = bcrypt.CompareHashAndPassword([]byte(refreshTokens[i].TokenHash), shaToken[:])
				if err == nil {
					spottedToken = &refreshTokens[i]
					break
				}
			}
			if spottedToken == nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				c.Abort()
				return
			}
			c.Set("spottedToken", spottedToken)

		} else if tokenType == "access" {
			fmt.Println("5", token)
			token, err = checkToken(bearerToken, tokenType)
		} else {
			fmt.Println("6", bearerToken)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		sub, err := extractSub(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		c.Set("userid", sub)
		c.Set("tokenType", tokenType)
		c.Next()
	}
}

func generateTokens(userID uuid.UUID) (string, string, []byte, error) {

	accessToken, err := generateAccessToken(userID.String())
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create access token: %v", err)
	}
	refreshToken, err := generateRefreshToken(userID.String(), time.Now().Add(time.Hour*24*30).Unix())
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create refresh token: %v", err)
	}
	fmt.Println("CREATED REF token: ", refreshToken)

	b64Token := base64.StdEncoding.EncodeToString([]byte(refreshToken))
	shaToken := sha256.Sum256([]byte(b64Token))
	refreshHash, err := bcrypt.GenerateFromPassword([]byte(shaToken[:]), bcrypt.DefaultCost)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to hash refresh token: %v", err)
	}

	return accessToken, b64Token, refreshHash, nil
}

func main() {
	godotenv.Load(".env")

	pg_user := os.Getenv("PG_USER")
	pg_password := os.Getenv("PG_PASSWORD")
	pg_db := os.Getenv("PG_DB")
	pg_port := os.Getenv("PG_PORT")
	pg_host := os.Getenv("PG_HOST")

	dsn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable", pg_host, pg_port, pg_user, pg_db, pg_password)
	db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	db.AutoMigrate(&User{}, &RefreshToken{})

	router := gin.Default()
	router.Use(DatabaseMiddleware(db))

	noTokenGroup := router.Group("/login")
	{
		noTokenGroup.POST("/", postLogin)
	}

	accessTokenGroup := router.Group("/user")
	accessTokenGroup.Use(CheckTokenMiddleware("access"))
	{
		accessTokenGroup.GET("/uuid/", getUserId)
		accessTokenGroup.POST("/logout/", postLogout)
	}

	refreshTokenGroup := router.Group("/refresh")
	refreshTokenGroup.Use(CheckTokenMiddleware("refresh"))
	{
		refreshTokenGroup.POST("/", postRefresh)
	}

	router.Run("localhost:8080")
}

func postLogin(c *gin.Context) {
	db, ok := c.Value("db").(*gorm.DB)
	if !ok {
		c.JSON(500, gin.H{"error": "DB connection not found"})
		return
	}
	userAgent := c.GetHeader("User-Agent")
	ipAddr := c.ClientIP()

	var userData LoginRequest
	err := c.ShouldBindJSON(&userData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	password := []byte(userData.Password)

	var user User
	err = db.Where("username = ?", userData.Username).First(&user).Error
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password!"})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password!!"})
		return
	}
	accessToken, refreshTokenB64, refreshHash, err := generateTokens(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	newRefreshToken := RefreshToken{
		UserID:    user.ID,
		TokenHash: string(refreshHash),
		UserAgent: userAgent,
		IPAddress: ipAddr,
	}

	result := db.Create(&newRefreshToken)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save refresh token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"refresh_token": refreshTokenB64, "access_token": accessToken})
}

func postRefresh(c *gin.Context) {
	db, ok := c.Value("db").(*gorm.DB)
	if !ok {
		c.JSON(500, gin.H{"error": "DB connection not found"})
		return
	}

	tokenValue, ok := c.Get("spottedToken")
	if !ok {
		fmt.Println("token not found in context")
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	oldRefreshToken, ok := tokenValue.(*RefreshToken)
	if !ok {
		fmt.Println("token not found in context")
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	incomeUserAgent := c.GetHeader("User-Agent")
	incomeIPAddress := c.ClientIP()
	webhookUrl := os.Getenv("WEBHOOK")

	if incomeUserAgent != oldRefreshToken.UserAgent {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Your User-Agent has been changed"})
		oldRefreshToken.Expired = true
		err := db.Save(oldRefreshToken).Error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token"})
			return
		}
		return
	}

	if incomeIPAddress != oldRefreshToken.IPAddress {
		payload := map[string]string{
			"user_id": oldRefreshToken.UserID.String(),
			"new_ip":  oldRefreshToken.IPAddress,
			"old_ip":  incomeIPAddress,
			"msg":     "IP has been changed",
		}
		jsonPayload, _ := json.Marshal(payload)
		_, err := http.Post(webhookUrl, "application/json", bytes.NewBuffer(jsonPayload))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send webhook"})
			return
		}
	}

	oldRefreshToken.Expired = true
	err := db.Save(oldRefreshToken).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token"})
		return
	}

	accessToken, b64Token, refreshHash, err := generateTokens(oldRefreshToken.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	newRefreshToken := RefreshToken{
		UserID:    oldRefreshToken.UserID,
		TokenHash: string(refreshHash),
		UserAgent: incomeUserAgent,
		IPAddress: incomeIPAddress,
	}

	err = db.Create(&newRefreshToken).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"refresh_token": b64Token, "access_token": accessToken})

}

func getUserId(c *gin.Context) {
	sub, ok := c.Get("userid")
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user id"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"userid": sub})
}

func postLogout(c *gin.Context) {

}
