package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"gorm.io/gorm"
)

func setUpRoutes(mux *http.ServeMux, db *gorm.DB) {

	mux.HandleFunc("GET /alive/", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, "hello")
	})

	mux.HandleFunc("GET /hello/", func(writer http.ResponseWriter, request *http.Request) {
		//println(request.URL.Path)
		user := getAuthedUser(writer, request, db)
		if user == nil {
			writer.WriteHeader(404)
			return
		}
		fmt.Fprintf(writer, "hello \n")
		fmt.Fprintf(writer, "logged in as user %s", user.Name)

	})

	mux.HandleFunc("GET /list/", func(writer http.ResponseWriter, request *http.Request) {
		user := getAuthedUser(writer, request, db)
		if user == nil {
			writer.WriteHeader(404)
			return
		}
		var userfiles []UserFiles
		db.Find(&userfiles, "user_id=?", user.ID)
		//list, err := os.ReadDir(fmt.Sprintf("baskets/%d", user.ID))
		// if err != nil {
		// 	return
		// }
		for _, listentry := range userfiles {
			//writer.Write([]byte(listentry.Name()))
			writer.Write([]byte(listentry.FileName))
			writer.Write([]byte("\n"))
		}
	})

	mux.HandleFunc("POST /createUser/", func(writer http.ResponseWriter, req *http.Request) {
		username := req.Header.Get("username")
		//println(username)
		user := User{
			Name: username,
		}
		password := req.Header.Get("password")
		pwHash := sha256.New()
		pwHash.Write([]byte(password))
		userPw := UserPw{
			Pwhash: pwHash.Sum(nil),
		}
		db.Create(&user)
		userPw.UserId = user.ID
		db.Create(&userPw)
		aJson, _ := json.Marshal(user)
		writer.Write(aJson)
		//fmt.Fprintf(writer, "hello")
	})

	mux.HandleFunc("GET /login/", func(writer http.ResponseWriter, req *http.Request) {
		user, isLoggedIn := login(writer, req, db)
		if !isLoggedIn {
			writer.WriteHeader(404)
			return
		}
		createSession(writer, user, db)
		fmt.Fprintf(writer, "hello")
	})

	mux.HandleFunc("POST /upload/", func(writer http.ResponseWriter, req *http.Request) {
		user := getAuthedUser(writer, req, db)
		if user == nil {
			writer.WriteHeader(404)
			return
		}
		var title string = req.Header.Get("title")
		userfile := UserFiles{
			UserId:   user.ID,
			FileName: title,
		}
		db.Create(&userfile)
		path := filepath.Join("baskets", fmt.Sprintf("%d", user.ID), fmt.Sprintf("%d", userfile.ID))
		file, err := os.Create(path)
		if err != nil {
			return
		}
		defer file.Close()

		//byteFile := bytes.Buffer{}
		byteFile, err := io.ReadAll(req.Body)
		if err != nil {
			print("read error")
		}
		//_, err = file.Read(byteFile)
		_, err = file.Write(byteFile)
		if err != nil {
			print("writeerror")
		}
		//io.Copy(file, &byteFile)
	})

	mux.HandleFunc("GET /download/", func(writer http.ResponseWriter, req *http.Request) {
		user := getAuthedUser(writer, req, db)
		if user == nil {
			writer.WriteHeader(404)
			return
		}
		var title string = req.Header.Get("title")
		userfile := UserFiles{}
		db.First(&userfile, "file_name=? AND user_id = ?", title, user.ID)
		path := filepath.Join("baskets", fmt.Sprintf("%d", user.ID), fmt.Sprintf("%d", userfile.ID))
		file, err := os.Open(path)
		if err != nil {
			return
		}
		defer file.Close()

		//byteFile := bytes.Buffer{}
		byteFile, err := io.ReadAll(file)
		if err != nil {
			print("read error")
		}
		//_, err = file.Read(byteFile)
		_, err = writer.Write(byteFile)
		if err != nil {
			print("writeerror")
		}
		//io.Copy(file, &byteFile)
	})
}

func createSession(writer http.ResponseWriter, user *User, db *gorm.DB) {
	token := GenerateSecureToken(16)
	println(token)
	writer.Header().Add("token", token)
	tokenHash := sha256.New()
	tokenHash.Write([]byte(token))
	//hashString := string(tokenHash.Sum(nil))
	session := Session{
		Hash:   tokenHash.Sum(nil),
		UserId: user.ID,
	}
	db.Create(&session)
}

func login(writer http.ResponseWriter, req *http.Request, db *gorm.DB) (*User, bool) {
	username := req.Header.Get("username")
	password := req.Header.Get("password")
	user := findUser(username, password, db)
	if user == nil {
		writer.WriteHeader(401)
		writer.Write([]byte("Not authenticated"))
		return nil, false
	}
	path := filepath.Join("baskets/", fmt.Sprintf("%d", user.ID))
	os.Mkdir(path, 0777)
	return user, true
}

func authMW(before http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, req *http.Request) {
		token := req.Header.Get("token")
		tokenHash := sha256.New()
		tokenHash.Write([]byte(token))
		session := &Session{}
		db.Where("hash=?", tokenHash.Sum(nil)).First(session)
		if len(session.Hash) == 0 {
			writer.WriteHeader(401)
			writer.Write([]byte("Not authenticated"))
			return
		}
		before(writer, req)
	}
}

func GenerateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func authenticateRequest(req *http.Request, db *gorm.DB) bool {
	token := req.Header.Get("token")
	tokenHash := sha256.New()
	tokenHash.Write([]byte(token))
	session := &Session{}
	db.Where("hash=?", tokenHash.Sum(nil)).First(session)
	if len(session.Hash) != 0 {
		return true
	}
	return false
}

func getAuthedUser(writer http.ResponseWriter, req *http.Request, db *gorm.DB) *User {
	token := req.Header.Get("token")
	tokenHash := sha256.New()
	tokenHash.Write([]byte(token))
	session := &Session{}
	db.Where("hash=?", tokenHash.Sum(nil)).First(session)
	if len(session.Hash) == 0 {
		writer.WriteHeader(401)
		writer.Write([]byte("Not authenticated"))
		return nil
	}
	user := &User{}
	db.First(user, session.UserId)
	return user
}

type Session struct {
	Hash   []byte
	UserId uint
	gorm.Model
}

func findUser(username string, password string, db *gorm.DB) *User {
	pwHash := sha256.New()
	pwHash.Write([]byte(password))
	user := &User{}
	//db.Raw("SELECT * FROM users WHERE name = ? AND id IN (SELECT user_id FROM user_pws WHERE pwhash = ?)", username, pwHash).Scan(user)
	userPw := UserPw{}
	//db.Raw("SELECT pwhash, user_id from user_pws WHERE user_id IN (SELECT ID FROM users WHERE name = ?)", username).Scan(&userpw)
	userId := User{}
	db.Where("name=?", username).First(&userId)
	db.Where("pwhash=?", pwHash.Sum(nil)).Where("user_id=?", userId.ID).First(&userPw)
	if !slices.Equal(pwHash.Sum(nil), userPw.Pwhash) {
		return nil
	}
	user.ID = userPw.UserId
	return user
}

/*
// Logger is a middleware handler that does request logging

	type Logger struct {
		handler http.Handler
	}

// ServeHTTP handles the request by passing it to the real
// handler and logging the request details

	func (l *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		l.handler.ServeHTTP(w, r)
		log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	}

// NewLogger constructs a new Logger middleware handler

	func NewLogger(handlerToWrap http.Handler) *Logger {
		return &Logger{handlerToWrap}
	}
*/
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	// WriteHeader(int) is not called if our response implicitly returns 200 OK, so
	// we default to that status code.
	return &loggingResponseWriter{w, http.StatusOK}
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func wrapHandlerWithLogging(wrappedHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Printf("--> %s %s from %s", req.Method, req.URL.Path, req.RemoteAddr)

		lrw := NewLoggingResponseWriter(w)
		wrappedHandler.ServeHTTP(lrw, req)

		statusCode := lrw.statusCode
		log.Printf("<-- %d %s", statusCode, http.StatusText(statusCode))
	})
}
