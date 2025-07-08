package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

	// Проверяем формат "Bearer <token>"
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", fmt.Errorf("invalid authorization header format")
	}

	// Извлекаем токен (обрезаем префикс)
	token := strings.TrimPrefix(authHeader, prefix)
	if token == "" {
		return "", fmt.Errorf("token is missing")
	}

	return token, nil
}

func CheckTokenMiddleware(tokenType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		bearerToken, err := extractBearerToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token format"})
			c.Abort()
			return
		}
		clearToken, err := base64.StdEncoding.DecodeString(bearerToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token decoding error"})
		}
		token, err := checkToken(string(clearToken), tokenType)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		sub, _ := extractSub(token)
		c.Set("userid", sub)
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

	b64Token := base64.StdEncoding.EncodeToString([]byte(refreshToken))
	fmt.Printf("CREATED REF token: %s\n", b64Token)
	shaToken := sha256.Sum256([]byte(b64Token))
	fmt.Printf("SHA256 of CREATED REF token: %x\n", shaToken)
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

	router := gin.Default()
	router.Use(DatabaseMiddleware(db))

	noTokenGroup := router.Group("/login")
	{
		noTokenGroup.POST("/", postLogin)
	}

	accessTokenGroup := router.Group("/user")
	accessTokenGroup.Use(CheckTokenMiddleware("access"))
	{
		accessTokenGroup.GET("/:guid/", getUserId)
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

	sub, ok := c.Get("userid")

	if !ok {
		fmt.Println("sub not found in context")
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	var oldRefreshToken RefreshToken
	err := db.Where("user_id = ?", sub).First(&oldRefreshToken).Error
	if err != nil {
		fmt.Println("refresh token not found")
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	bearerToken, err := extractBearerToken(c)
	fmt.Println("Bearer token:", bearerToken)

	if bearerToken == "" {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	shaToken := sha256.Sum256([]byte(bearerToken))
	fmt.Printf("SHA256 of BEARER token: %x\n", shaToken)
	fmt.Printf("Hash from DB: %s\n", oldRefreshToken.TokenHash)

	err = bcrypt.CompareHashAndPassword([]byte(oldRefreshToken.TokenHash), shaToken[:])

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
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
	}

	err = db.Model(&oldRefreshToken).Updates(&newRefreshToken).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"refresh_token": b64Token, "access_token": accessToken})

}

func getUserId(c *gin.Context) {

}

func postLogout(c *gin.Context) {

}
