package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var collection *mongo.Collection
var ctx = context.TODO()

func main() {
	opts := options.Client().ApplyURI("mongodb://localhost:27017")

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		panic(err)
	}

	collection = client.Database("users").Collection("tokens")

	defer client.Disconnect(ctx)

	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/refresh", Refresh)

	err = nil
	_, err = collection.Find(ctx, bson.M{"UserID": creds.ID})
	if err != nil {
		_, err := collection.UpdateMany(
			ctx,
			bson.D{{Key: "UserID", Value: creds.ID}},
			bson.D{
				{Key: "$set", Value: bson.M{"refreshToken": hash}},
			},
		)
		if err != nil {
			panic(err)
		}
	} else {
		tokens := bson.D{
			{Key: "UserID", Value: creds.ID},
			{Key: "refreshToken", Value: hash},
		}
		err = nil
		_, err = collection.InsertOne(ctx, tokens)
		if err != nil {
			panic(err)
		}
	}

	log.Fatal(http.ListenAndServe(":8000", nil))
}

var jwtKey = []byte("my_secret_key")

type Credentials struct {
	ID string `json:"ID"`
}

var creds Credentials

var hash []byte

type Claims struct {
	ID   string `json:"ID"`
	Type string `json:"Type"`
	jwt.StandardClaims
}

func Signin(w http.ResponseWriter, r *http.Request) {
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	createTime := time.Now()
	expirationTimeA := createTime.Add(15 * time.Minute)
	expirationTimeR := createTime.Add(360 * time.Minute)
	claims := &Claims{
		ID:   creds.ID,
		Type: "access",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTimeA.Unix(),
			IssuedAt:  createTime.Unix(),
		},
	}

	accesstoken := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	tokenStringA, err := accesstoken.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	claims = &Claims{
		ID:   creds.ID,
		Type: "refresh",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTimeR.Unix(),
			IssuedAt:  createTime.Unix(),
		},
	}

	refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStringR, err := refreshtoken.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = nil
	hash, err = bcrypt.GenerateFromPassword([]byte(tokenStringR), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "accesstoken",
		Value:   tokenStringA,
		Expires: expirationTimeA,
	})
	http.SetCookie(w, &http.Cookie{
		Name:    "refreshtoken",
		Value:   tokenStringR,
		Expires: expirationTimeR,
	})
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	refresh, err := r.Cookie("refreshtoken")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	access, err := r.Cookie("refreshtoken")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := refresh.Value
	rclaims := &Claims{}
	aclaims := Claims{}
	rtkn, err := jwt.ParseWithClaims(tknStr, rclaims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !rtkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tknStr = access.Value

	atkn, err := jwt.ParseWithClaims(tknStr, rclaims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !atkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if rclaims.IssuedAt != aclaims.IssuedAt && rclaims.ID != aclaims.ID {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if time.Unix(rclaims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	createTime := time.Now()
	expirationTimeA := createTime.Add(15 * time.Minute)
	expirationTimeR := createTime.Add(360 * time.Minute)

	rclaims.ExpiresAt = expirationTimeR.Unix()
	rclaims.IssuedAt = createTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, rclaims)
	creds.ID = rclaims.ID

	err = nil
	tokenStringR, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	aclaims.ExpiresAt = expirationTimeA.Unix()
	aclaims.IssuedAt = createTime.Unix()
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, rclaims)
	tokenStringA, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = nil
	hash, err = bcrypt.GenerateFromPassword([]byte(tokenStringR), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "accesstoken",
		Value:   tokenStringA,
		Expires: expirationTimeA,
	})
	http.SetCookie(w, &http.Cookie{
		Name:    "refreshtoken",
		Value:   tokenStringR,
		Expires: expirationTimeR,
	})
}
