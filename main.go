package main

import (
	"net/http"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type User struct {
	Name string
	gorm.Model
}

type UserPw struct {
	UserId uint
	Pwhash []byte
}

type UserFiles struct {
	UserId   uint
	FileName string
	gorm.Model
}

func main() {
	print("hej")

	err := os.Mkdir("baskets", 0777)
	if err != nil {
		print(err.Error())
	}

	//os.Mkdir("baskets", os.ModeDir)

	mux := http.NewServeMux()

	db := initDB()

	setUpRoutes(mux, db)

	err2 := http.ListenAndServe("localhost:8060", wrapHandlerWithLogging(mux))
	if err2 != nil {
		println(err2.Error())
	}

}

var db *gorm.DB

func initDB() *gorm.DB {
	dsn := "adan2936:zuCoo2ehohth@tcp(mysql.dsv.su.se:3306)/adan2936?charset=utf8mb4&parseTime=True&loc=Local"
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {

	}

	migrateTables(db)

	//user := User{Name: "Jinzhu", Age: 18, Birthday: time.Now()}
	//result := db.Create(&user) // pass pointer of data to Create

	//println(user.UserId)             // returns inserted data's primary key
	//println(result.Error)        // returns error
	//println(result.RowsAffected) // returns inserted records count

	return db
}

func migrateTables(db *gorm.DB) {
	err := db.AutoMigrate(&User{}, &Session{}, &UserPw{}, &UserFiles{})
	if err != nil {
		println(err.Error())
	}
}

/*
package main

import (
	"context"
	"github.com/jackc/pgx/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/http"
	"time"
)

type User struct {
	Name     string
	Age      int
	Birthday time.Time
}

func main() {
	print("hej")
	mux := http.NewServeMux()

	databaseUrl := "postgres://postgres:mypassword@localhost:5432/postgres"
	conn, err := pgx.Connect(context.Background(), databaseUrl)

	db := initDB()

	setUpRoutes(mux, db)

	err2 := http.ListenAndServe("localhost:8060", mux)
	if err2 != nil {
		println(err2.Error())
	}

}

func initDB() *gorm.DB {
	dsn := "host=localhost user=postgres password=mysecretpassword dbname=postgres port=5432 sslmode=disable TimeZone=Europe/Stockholm"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {

	}

	migrateTables(db)

	//user := User{Name: "Jinzhu", Age: 18, Birthday: time.Now()}
	//result := db.Create(&user) // pass pointer of data to Create

	//println(user.UserId)             // returns inserted data's primary key
	//println(result.Error)        // returns error
	//println(result.RowsAffected) // returns inserted records count

	return db
}

func migrateTables(db *gorm.DB) {
	err := db.AutoMigrate(&User{}, &Session{})
	if err != nil {
		println(err.Error())
	}
}
*/
