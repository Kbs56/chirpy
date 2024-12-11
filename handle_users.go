package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kbs56/chirpy/internal/auth"
	"github.com/kbs56/chirpy/internal/database"
)

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Token not found", err)
		return
	}

	err = cfg.db.RevokeToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error revoking token", err)
		return
	}

	respondWithJSON(w, http.StatusNoContent, struct{}{})
	return
}

func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized", err)
		return
	}

	tokenInfo, err := cfg.db.GetRefreshTokenAndExpiry(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized", err)
		return
	}

	if tokenInfo.ExpiresAt.Before(time.Now()) {
		respondWithError(w, http.StatusUnauthorized, "Refresh token is expired", err)
		return
	}

	if tokenInfo.RevokedAt.Time != (time.Time{}) {
		respondWithError(w, http.StatusUnauthorized, "Refresh token is revoked", err)
		return
	}

	dbUser, err := cfg.db.GetUserFromRefreshToken(r.Context(), tokenInfo.Token)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "User not found", err)
		return
	}

	type response struct {
		Token string `json:"token"`
	}

	jwt, err := auth.MakeJWT(dbUser, cfg.jwtSecret, time.Hour*1)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating JWT", err)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		Token: jwt,
	})
	return
}

func (cfg *apiConfig) handleLoginUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}

	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters", err)
		return
	}

	if params.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required", nil)
		return
	}

	if params.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required", nil)
		return
	}

	dbUser, err := cfg.db.GetUserInfo(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "User not found", nil)
		return
	}

	checkPassword := auth.CheckPasswordHash(params.Password, dbUser.HashedPassword)
	if checkPassword != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect Password", nil)
		return
	}

	expirationTime := time.Hour
	if params.ExpiresInSeconds > 0 && params.ExpiresInSeconds < 3600 {
		expirationTime = time.Duration(params.ExpiresInSeconds) * time.Second
	}

	accessToken, err := auth.MakeJWT(dbUser.ID, cfg.jwtSecret, expirationTime)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create JWT for user", err)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"Could not create Refresh Token for user",
			err,
		)
		return
	}

	err = cfg.db.InsertRefreshToken(r.Context(), database.InsertRefreshTokenParams{
		Token:     refreshToken,
		UserID:    dbUser.ID,
		ExpiresAt: time.Now().UTC().Add(time.Hour * 24 * 60),
	})
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"Error inserting refresh token for user",
			err,
		)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		User: User{
			ID:        dbUser.ID,
			CreatedAt: dbUser.CreatedAt,
			UpdatedAt: dbUser.UpdatedAt,
			Email:     dbUser.Email,
		},
		Token:        accessToken,
		RefreshToken: refreshToken,
	})
}

func (cfg *apiConfig) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type response struct {
		User
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters", err)
		return
	}

	if params.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required", nil)
		return
	}

	if params.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required", nil)
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create user", err)
		return
	}

	user, err := cfg.db.CreateUser(
		r.Context(),
		database.CreateUserParams{Email: params.Email, HashedPassword: hashedPassword},
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not create user", err)
	}

	respondWithJSON(w, http.StatusCreated, response{
		User: User{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		},
	})
}
