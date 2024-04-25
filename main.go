package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

// cookie handling
var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

func getUserName(request *http.Request) (userName string) {
	if cookie, err := request.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			userName = cookieValue["name"]
		}
	}
	return userName
}

func setSession(userName string, response http.ResponseWriter) {
	value := map[string]string{
		"name": userName,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

func clearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

// Login handler

func loginHandler(response http.ResponseWriter, request *http.Request) {
	name := request.FormValue("email")
	pass := GetMD5Hash(request.FormValue("password"))

	db, err := sql.Open("mysql", "root:Shruti@991001@tcp(localhost:3306)/cyza?charset=utf8")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id,username,email FROM users WHERE email=? AND password=?", name, pass)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	user := []string{}
	for rows.Next() {
		var id int
		var username string
		var email string

		err = rows.Scan(&id, &username, &email)
		if err != nil {
			log.Fatal(err)
		}
		user = append(user, username)
	}

	redirectTarget := "/"
	if len(user) != 0 {
		setSession(name, response)
		redirectTarget = "/edit"
	}
	http.Redirect(response, request, redirectTarget, http.StatusFound)
}

// logout handler

func logoutHandler(response http.ResponseWriter, request *http.Request) {
	clearSession(response)
	http.Redirect(response, request, "/", http.StatusFound)
}

func indexPageHandler(response http.ResponseWriter, request *http.Request) {
	t, _ := template.ParseFiles("home.gtpl")
	t.Execute(response, nil)
}

func internalPageHandler(response http.ResponseWriter, request *http.Request) {
	userName := getUserName(request)
	if userName != "" {
		db, err := sql.Open("mysql", "root:Shruti@991001@tcp(localhost:3306)/cyza?charset=utf8")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		rows, err := db.Query("SELECT email,full_name,phone,address,created FROM users WHERE email=?", userName)
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()

		user := make([]interface{}, 5) // Use interface{} slice to handle different types including NULL
		for rows.Next() {
			var email, full_name, phone, address, created sql.NullString
			err = rows.Scan(&email, &full_name, &phone, &address, &created)
			if err != nil {
				log.Fatal(err)
			}
			user = append(user, email, full_name, phone, address, created)
		}

		t, _ := template.ParseFiles("dash.gtpl")
		t.Execute(response, user)
	} else {
		http.Redirect(response, request, "/", http.StatusFound)
	}
}

// Register handler
func registerHandler(response http.ResponseWriter, request *http.Request) {
	var msg string
	if request.Method == http.MethodPost {
		name := request.FormValue("name")
		password := GetMD5Hash(request.FormValue("password"))
		email := request.FormValue("email")

		db, err := sql.Open("mysql", "root:Shruti@991001@tcp(localhost:3306)/cyza?charset=utf8")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		rows, err := db.Query("SELECT email FROM users WHERE email=?", email)
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()

		user := []string{}
		for rows.Next() {
			var _email string
			err = rows.Scan(&_email)
			if err != nil {
				log.Fatal(err)
			}
			user = append(user, _email)
		}

		if len(user) != 0 {
			msg = "User exists"
		} else {
			stmt, err := db.Prepare("INSERT INTO users SET username=?, password=?, email=? ")
			if err != nil {
				log.Fatal(err)
			}
			defer stmt.Close()

			_, err = stmt.Exec(name, password, email)
			if err != nil {
				log.Fatal(err)
			}

			msg = "User added"
		}
	}
	t, _ := template.ParseFiles("register.gtpl")
	t.Execute(response, msg)
}

// Lost Password Handler
func lostHandler(response http.ResponseWriter, request *http.Request) {
	var msg string

	if request.Method == http.MethodPost {
		email := request.FormValue("email")

		db, err := sql.Open("mysql", "root:Shruti@991001@tcp(localhost:3306)/cyza?charset=utf8")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		rows, err := db.Query("SELECT email,password FROM users WHERE email=?", email)
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()

		user := []string{}
		for rows.Next() {
			var _email, _password sql.NullString
			err = rows.Scan(&_email, &_password)
			if err != nil {
				log.Fatal(err)
			}
			user = append(user, _email.String, _password.String)
		}

		if len(user) != 0 {
			h := GetMD5Hash(email)
			msg = "Email Sent to : " + email
			path := "http://localhost:8000/reset?token=" + h
			fmt.Println(path)

			_, err := db.Query("UPDATE users SET reset_hash=? WHERE email=?", h, email)
			if err != nil {
				log.Fatal(err)
			}

			send(path, email)
		} else {
			msg = "Email don't exists"
		}
	}
	t, _ := template.ParseFiles("lost.gtpl")
	t.Execute(response, msg)
}

func resetHandler(response http.ResponseWriter, request *http.Request) {
	msg := ""
	token := request.FormValue("token")
	pass := request.FormValue("password")
	if request.Method == http.MethodPost {
		if token != "" && pass != "" {
			db, err := sql.Open("mysql", "root:Shruti@991001@tcp(localhost:3306)/cyza?charset=utf8")
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()

			_, err = db.Query("UPDATE users SET password=? WHERE reset_hash=?", pass, token)
			if err != nil {
				log.Fatal(err)
			}

			http.Redirect(response, request, "/", http.StatusFound)
		}
	}
	t, _ := template.ParseFiles("forgot.gtpl")
	t.Execute(response, msg)
}

func profilHandler(response http.ResponseWriter, request *http.Request) {
	userName := getUserName(request)
	if userName != "" {
		if request.Method == http.MethodPost {
			full_name := request.FormValue("full_name")
			address := request.FormValue("address")
			phone := request.FormValue("phone")

			db, err := sql.Open("mysql", "root:Shruti@991001@tcp(localhost:3306)/cyza?charset=utf8")
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()

			_, err = db.Query("UPDATE users SET full_name=?, address=?, phone=? WHERE email=?", full_name, address, phone, userName)
			if err != nil {
				log.Fatal(err)
			}

			http.Redirect(response, request, "/internal", http.StatusFound)
		}
		t, _ := template.ParseFiles("profile.gtpl")
		t.Execute(response, nil)

	} else {
		http.Redirect(response, request, "/", http.StatusFound)
	}
}

func editHandler(response http.ResponseWriter, request *http.Request) {
	userName := getUserName(request)
	if userName != "" {
		db, err := sql.Open("mysql", "root:Shruti@991001@tcp(localhost:3306)/cyza?charset=utf8")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		if request.Method == http.MethodGet {
			rows, err := db.Query("SELECT email,full_name,phone,address,created FROM users WHERE email=?", userName)
			if err != nil {
				log.Fatal(err)
			}
			defer rows.Close()

			user := make([]interface{}, 5) // Use interface{} slice to handle different types including NULL
			for rows.Next() {
				var email, full_name, phone, address, created sql.NullString
				err = rows.Scan(&email, &full_name, &phone, &address, &created)
				if err != nil {
					log.Fatal(err)
				}
				user = append(user, email, full_name, phone, address, created)
			}

			t, _ := template.ParseFiles("edit.gtpl")
			t.Execute(response, user)
		} else {
			full_name := request.FormValue("full_name")
			address := request.FormValue("address")
			phone := request.FormValue("phone")

			_, err := db.Query("UPDATE users SET full_name=?, address=?, phone=? WHERE email=?", full_name, address, phone, userName)
			if err != nil {
				log.Fatal(err)
			}

			http.Redirect(response, request, "/internal", http.StatusFound)
		}
	} else {
		http.Redirect(response, request, "/", http.StatusFound)
	}
}

// server main method

var router = mux.NewRouter()

func main() {
	router.HandleFunc("/", indexPageHandler)
	router.HandleFunc("/internal", internalPageHandler)
	router.HandleFunc("/login", loginHandler).Methods(http.MethodPost)
	router.HandleFunc("/register", registerHandler).Methods(http.MethodPost, http.MethodGet)
	router.HandleFunc("/lost", lostHandler).Methods(http.MethodPost, http.MethodGet)
	router.HandleFunc("/reset", resetHandler).Methods(http.MethodPost, http.MethodGet)
	router.HandleFunc("/profil", profilHandler).Methods(http.MethodPost, http.MethodGet)
	router.HandleFunc("/edit", editHandler).Methods(http.MethodPost, http.MethodGet)
	router.HandleFunc("/logout", logoutHandler).Methods(http.MethodPost)

	router.HandleFunc("/api/login", ApiLoginHandler).Methods(http.MethodPost, http.MethodGet)
	router.HandleFunc("/api/register", ApiRegisterHandler).Methods(http.MethodPost, http.MethodGet)

	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))
	http.Handle("/", router)
	http.ListenAndServe(":8000", nil)
}

// func checkErr(err error) {
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// }

func send(body string, to string) {
	from := "chiheb.design@gmail.com"
	pass := ""

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Your Password\n\n" +
		body

	err := smtp.SendMail("smtp.gmail.com:25",
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}

}

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

type Message struct {
	Name  string `json:"name"`
	Error bool   `json:"error"`
}

// API Login

func ApiLoginHandler(response http.ResponseWriter, request *http.Request) {
	email := request.FormValue("email")
	pass := request.FormValue("password")
	fmt.Println(email)
	fmt.Println(pass)

	db, err := sql.Open("mysql", "root:Shruti@991001@tcp(localhost:3306)/cyza?charset=utf8")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id,username,email FROM users WHERE email=? AND password=?", email, pass)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	user := []string{}
	for rows.Next() {
		var id int
		var username string
		var email string

		err = rows.Scan(&id, &username, &email)
		if err != nil {
			log.Fatal(err)
		}
		user = append(user, username)
		fmt.Println(id)
	}

	if len(user) != 0 {
		if err := json.NewEncoder(response).Encode(Message{Name: "Logged", Error: false}); err != nil {
			log.Fatal(err)
		}

	} else {
		if err := json.NewEncoder(response).Encode(Message{Name: "Error : Bad request", Error: true}); err != nil {
			log.Fatal(err)
		}
	}

}

// API Register
func ApiRegisterHandler(response http.ResponseWriter, request *http.Request) {
	name := request.FormValue("name")
	password := request.FormValue("password")
	email := request.FormValue("email")

	if name != "" && password != "" && email != "" {
		db, err := sql.Open("mysql", "root:Shruti@991001@tcp(localhost:3306)/cyza?charset=utf8")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		rows, err := db.Query("SELECT email FROM users WHERE email=?", email)
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()

		user := []string{}
		for rows.Next() {
			var _email string
			err = rows.Scan(&_email)
			if err != nil {
				log.Fatal(err)
			}
			user = append(user, _email)
		}

		if len(user) != 0 {
			if err := json.NewEncoder(response).Encode(Message{Name: "User Exists", Error: true}); err != nil {
				log.Fatal(err)
			}

		} else {

			stmt, err := db.Prepare("INSERT INTO users SET username=?, password=?, email=? ")
			if err != nil {
				log.Fatal(err)
			}
			defer stmt.Close()

			_, err = stmt.Exec(name, password, email)
			if err != nil {
				log.Fatal(err)
			}

			if err := json.NewEncoder(response).Encode(Message{Name: "User added", Error: false}); err != nil {
				log.Fatal(err)
			}

		}
	} else {
		if err := json.NewEncoder(response).Encode(Message{Name: "Error : Bad request", Error: true}); err != nil {
			log.Fatal(err)
		}
	}
}
