package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
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

	router.POST("/login/", postLogin)
	router.POST("/refresh/", getRefresh)
	router.GET("/user/:guid", getUserId)
	router.POST("/logout/", postLogout)

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

	accessToken, err := generateAccessToken(user.ID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access token"})
		return
	}
	refreshToken, err := generateRefreshToken(user.ID.String(), time.Now().Add(time.Hour*24*30).Unix())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create refresh token: %v", err)})
		return
	}

	shaHash := sha256.Sum256([]byte(refreshToken))
	tokenHash, err := bcrypt.GenerateFromPassword(shaHash[:], bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to hash refresh token: %v", err)})
		return
	}
	newRefreshToken := RefreshToken{
		UserID:    user.ID,
		TokenHash: string(tokenHash),
	}
	result := db.Create(&newRefreshToken)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save refresh token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"refresh_token": refreshToken, "access_token": accessToken})
}

func getRefresh(c *gin.Context) {

}

func getUserId(c *gin.Context) {

}

func postLogout(c *gin.Context) {

}
