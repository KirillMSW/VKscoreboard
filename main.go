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
	"sort"
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

var store = sessions.NewCookieStore([]byte("SECRET"))
var db *sql.DB

func main() {
	onStartup()
	fmt.Println("Begining app")
	router := gin.Default()
	router.POST("/api/login", login)
	router.POST("/api/register", register)
	router.GET("/api/secret", secret)
	router.GET("/api/scoreboard", getScoreboard)
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
	_, err = db.Exec("INSERT INTO users (login, password) VALUES (?,?)", login, hash)
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
	c.JSON(200, respStruct)
}
