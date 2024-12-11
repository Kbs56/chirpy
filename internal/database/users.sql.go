// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: users.sql

package database

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING id, created_at, updated_at, email
`

type CreateUserParams struct {
	Email          string
	HashedPassword string
}

type CreateUserRow struct {
	ID        uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	Email     string
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (CreateUserRow, error) {
	row := q.db.QueryRowContext(ctx, createUser, arg.Email, arg.HashedPassword)
	var i CreateUserRow
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
	)
	return i, err
}

const deleteAllUsers = `-- name: DeleteAllUsers :exec
DELETE FROM users
`

func (q *Queries) DeleteAllUsers(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllUsers)
	return err
}

const getUserInfoByEmail = `-- name: GetUserInfoByEmail :one
SELECT id, created_at, updated_at, email, hashed_password
FROM users
WHERE email = $1 LIMIT 1
`

func (q *Queries) GetUserInfoByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserInfoByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
	)
	return i, err
}

const getUserInfoByUuid = `-- name: GetUserInfoByUuid :one
SELECT id, created_at, updated_at, email, hashed_password
FROM users
WHERE id = $1
`

func (q *Queries) GetUserInfoByUuid(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserInfoByUuid, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
	)
	return i, err
}

const updateEmailAndPassword = `-- name: UpdateEmailAndPassword :one
UPDATE users
SET email = $1, hashed_password = $2, updated_at = CURRENT_TIMESTAMP
WHERE id = $3
returning id, created_at, updated_at, email, hashed_password
`

type UpdateEmailAndPasswordParams struct {
	Email          string
	HashedPassword string
	ID             uuid.UUID
}

func (q *Queries) UpdateEmailAndPassword(ctx context.Context, arg UpdateEmailAndPasswordParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateEmailAndPassword, arg.Email, arg.HashedPassword, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
	)
	return i, err
}