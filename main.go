package main

import (
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	router.POST("/create-tokens/", postTokens)
	router.GET("/refresh/", getRefresh)
	router.GET("/index/:guid", index)
	router.GET("unauthorize", getUnauthorize)

	router.Run("localhost:8080")
}

func postTokens(c *gin.Context) {

}

func getRefresh(c *gin.Context) {

}

func index(c *gin.Context) {

}

func getUnauthorize(c *gin.Context) {

}
