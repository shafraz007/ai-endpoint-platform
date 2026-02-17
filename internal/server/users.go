package server

import (
	"context"
	"errors"
	"strings"
	"time"
)

type User struct {
	ID                 int
	Username           string
	PasswordHash       string
	Role               string
	MustChangePassword bool
	LastLogin          *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func GetUserByUsername(ctx context.Context, username string) (*User, error) {
	if DB == nil {
		return nil, errors.New("database not initialized")
	}
	query := `
	SELECT id, username, password_hash, role, must_change_password, last_login, created_at, updated_at
	FROM users
	WHERE username = $1
	`

	row := DB.QueryRow(ctx, query, username)
	var user User
	if err := row.Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.Role,
		&user.MustChangePassword,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &user, nil
}

func CreateUser(ctx context.Context, username, passwordHash, role string, mustChangePassword bool) error {
	if DB == nil {
		return errors.New("database not initialized")
	}
	query := `
	INSERT INTO users (username, password_hash, role, must_change_password)
	VALUES ($1, $2, $3, $4)
	`
	_, err := DB.Exec(ctx, query, username, passwordHash, role, mustChangePassword)
	return err
}

func UpdateUserPassword(ctx context.Context, username, newPasswordHash string, mustChangePassword bool) error {
	if DB == nil {
		return errors.New("database not initialized")
	}
	query := `
	UPDATE users
	SET password_hash = $1,
		must_change_password = $2,
		updated_at = CURRENT_TIMESTAMP
	WHERE username = $3
	`
	_, err := DB.Exec(ctx, query, newPasswordHash, mustChangePassword, username)
	return err
}

func UpdateLastLogin(ctx context.Context, username string) error {
	if DB == nil {
		return errors.New("database not initialized")
	}
	query := `
	UPDATE users
	SET last_login = CURRENT_TIMESTAMP,
		updated_at = CURRENT_TIMESTAMP
	WHERE username = $1
	`
	_, err := DB.Exec(ctx, query, username)
	return err
}

func AnyAdminExists(ctx context.Context) (bool, error) {
	if DB == nil {
		return false, errors.New("database not initialized")
	}
	var count int
	err := DB.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func EnsureDefaultAdmin(ctx context.Context, username, passwordHash string) (bool, error) {
	exists, err := AnyAdminExists(ctx)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}

	username = strings.TrimSpace(username)
	if username == "" {
		username = "admin"
	}
	if err := CreateUser(ctx, username, passwordHash, "admin", true); err != nil {
		return false, err
	}
	return true, nil
}
