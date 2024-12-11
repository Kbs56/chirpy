-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING id, created_at, updated_at, email;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserInfoByEmail :one
SELECT *
FROM users
WHERE email = $1 LIMIT 1;

-- name: GetUserInfoByUuid :one
SELECT *
FROM users
WHERE id = $1;

-- name: UpdateEmailAndPassword :one
UPDATE users
SET email = $1, hashed_password = $2, updated_at = CURRENT_TIMESTAMP
WHERE id = $3
returning *;

-- name: UpgradeUserToChirpyRed :exec
UPDATE users
SET is_chirpy_red = TRUE
where id = $1;
