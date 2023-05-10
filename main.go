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
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"
)

type userInfo struct {
	Login          string
	RelativeWeb    int
	RelativeStego  int
	RelativeCrypto int
	Web            int
	Stego          int
	Crypto         int
}

var store *sessions.CookieStore
var db *sql.DB

func main() {
	onStartup()
	fmt.Println("Begining app")
	router := gin.Default()
	router.POST("/api/login", login)
	router.POST("/api/logout", logout)
	router.POST("/api/register", register)
	router.GET("/api/secret", secret)
	router.GET("/api/isloged", isLoged)
	router.GET("/api/scoreboard", getScoreboard)
	router.Run("localhost:8050")
}

func onStartup() {
	rand.Seed(time.Now().UnixNano())
	viper.SetConfigFile("secrets.json")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Failed to read config")
	}
	store = sessions.NewCookieStore([]byte(fmt.Sprintf("%v", viper.Get("cookie_secret"))))
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

	result := db.QueryRow("SELECT password FROM  users WHERE login=?", login)

	var dbPass []byte
	err := result.Scan(&dbPass)
	if err != nil {
		c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.String(400, "Invalid username or password")
		return
	}
	res := bcrypt.CompareHashAndPassword(dbPass, []byte(password))

	if res == nil {
		session, _ := store.Get(c.Request, "session")
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   60,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		}
		session.Values["authenticated"] = true
		session.Save(c.Request, c.Writer)
		c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.String(200, "Logged in")
	} else {
		c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.String(400, "Invalid username or password")
	}
}

func register(c *gin.Context) {
	login := c.PostForm("login")
	password := c.PostForm("password")
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	result, err := db.Query("SELECT * FROM  tasks")

	categoriesAmount := make(map[string]int)
	for result.Next() {
		var task string
		var amount int
		err = result.Scan(&task, &amount)
		if err != nil {
			log.Fatal(err)
		}
		categoriesAmount[task] = amount
	}

	_, err = db.Exec("INSERT INTO users VALUES (?,?,?,?,?)", login, hash, rand.Intn(categoriesAmount["Web"]),
		rand.Intn(categoriesAmount["Stego"]), rand.Intn(categoriesAmount["Crypto"]))
	if err != nil {
		c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
		c.Header("Access-Control-Allow-Credentials", "true")
		if strings.Contains(err.Error(), "Duplicate entry") {
			c.String(400, "User exists")
		}
		c.Writer.WriteHeader(400)
	}
	session, _ := store.Get(c.Request, "session")
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	session.Values["authenticated"] = true
	session.Save(c.Request, c.Writer)
	c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
	c.Header("Access-Control-Allow-Credentials", "true")

}
func secret(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.String(401, "no flag")
		return
	}

	c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
	c.Header("Access-Control-Allow-Credentials", "true")
	c.String(200, "flag{qwert}")
}

func getScoreboard(c *gin.Context) {

	result, err := db.Query("SELECT * FROM  tasks")

	categoriesAmount := make(map[string]int)
	for result.Next() {
		var task string
		var amount int
		err = result.Scan(&task, &amount)
		if err != nil {
			log.Fatal(err)
		}
		categoriesAmount[task] = amount
	}
	result, err = db.Query("SELECT login, web_solved, stego_solved, crypto_solved FROM users")
	var users []userInfo
	for result.Next() {
		var scanUser userInfo
		err = result.Scan(&scanUser.Login, &scanUser.Web, &scanUser.Stego, &scanUser.Crypto)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, scanUser)
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Web > users[j].Web
	})
	for i, _ := range users {
		users[i].RelativeWeb = i + 1
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Stego > users[j].Stego
	})
	for i, _ := range users {
		users[i].RelativeStego = i + 1
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Crypto > users[j].Crypto
	})
	for i, _ := range users {
		users[i].RelativeCrypto = i + 1
	}

	respStruct := struct {
		TasksInfo map[string]int
		UsersInfo []userInfo
	}{categoriesAmount, users}
	c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
	c.Header("Access-Control-Allow-Credentials", "true")
	c.JSON(200, respStruct)
}

func isLoged(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Writer.WriteHeader(401)
		return
	}

	c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
	c.Header("Access-Control-Allow-Credentials", "true")
	c.String(200, "flag{qwert}")
}

func logout(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	session.Values["authenticated"] = false
	session.Save(c.Request, c.Writer)
	c.Header("Access-Control-Allow-Origin", "http://localhost:3000")
	c.Header("Access-Control-Allow-Credentials", "true")
}
