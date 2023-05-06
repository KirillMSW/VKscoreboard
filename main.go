package main

import (
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

var store = sessions.NewCookieStore([]byte("SECRET"))
var db *sql.DB

func main() {
	onStartup()
	fmt.Println("Begining app")
	router := gin.Default()
	router.POST("/api/login", login)
	router.POST("/api/register", register)
	router.GET("/api/secret", secret)
	router.Run("localhost:8080")
}

func onStartup() {
	viper.SetConfigFile("secrets.json")
	err := viper.ReadInConfig()
	if err != nil {
		//errors.New("Failed to read config")
	}
	cfg := mysql.Config{
		User:   fmt.Sprintf("%v", viper.Get("db_user")),
		Passwd: fmt.Sprintf("%v", viper.Get("db_password")),
		Net:    "tcp",
		Addr:   fmt.Sprintf("%v", viper.Get("db_ip")),
		DBName: "vk_schema",
	}
	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(err)
	}
}

func login(c *gin.Context) {
	login := c.PostForm("login")
	password := c.PostForm("password")
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	fmt.Println(string(hash))
	if err != nil {
		// TODO: Properly handle error
		log.Fatal(err)
	}

	//TODO: check if there such user
	result := db.QueryRow("SELECT password FROM  users WHERE login=?", login)

	var dbPass []byte
	err = result.Scan(&dbPass)
	if err != nil {
		c.String(418, "Invalid username or password")
		return
	}
	res := bcrypt.CompareHashAndPassword(dbPass, []byte(password))

	if res == nil {
		session, _ := store.Get(c.Request, "cookie-name")
		// TODO: set secure to "true"
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
		session.Values["authenticated"] = true
		session.Save(c.Request, c.Writer)
		c.String(200, "Logged in")
	} else {
		c.String(418, "Invalid username or password")
	}
}

func register(c *gin.Context) {
	login := c.PostForm("login")
	password := c.PostForm("password")
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO users VALUES (?,?)", login, hash)
	if err != nil {

	}

}
func secret(c *gin.Context) {
	session, _ := store.Get(c.Request, "cookie-name")

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		fmt.Printf("not okay")
		c.String(401, "no flag")
		return
	}

	fmt.Printf("okay")
	c.String(200, "flag{qwert}")
}
