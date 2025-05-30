package models

import (
	"database/sql"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

type QuestionAuthor struct {
	ID        int
	Email     string
	CreatedAt time.Time
}

type Question struct {
	ID              int
	AuthorID        int
	Title           string
	Content         string
	CreatedAt       time.Time
	DeletedAt       *time.Time
	IsAuthorBlocked bool
}

type Answer struct {
	ID         int
	QuestionID int
	UserID     int
	Content    string
	CreatedAt  time.Time
}

type AnswerWithEmail struct {
	Answer
	UserEmail string
}

type BlockedEmail struct {
	ID        int
	Email     string
	BlockedAt time.Time
	BlockedBy int // user_id of the admin who blocked
	Reason    string
}

type BlockedEmailWithQuestions struct {
	Email     string
	BlockedAt time.Time
	BlockedBy string
	Reason    string
	Questions []Question
}

type DB struct {
	*sql.DB
}

func (db *DB) MigrateDB() error {
	// Check if we need to migrate by looking for author_id in questions table
	var hasAuthorID bool
	err := db.QueryRow(`
		SELECT COUNT(*) > 0 
		FROM pragma_table_info('questions') 
		WHERE name='author_id'
	`).Scan(&hasAuthorID)

	if err != nil {
		return err
	}

	if !hasAuthorID {
		log.Println("Migrating database to new schema...")

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		// Backup existing data
		var questions []struct {
			ID        int
			UserID    int
			Title     string
			Content   string
			CreatedAt time.Time
			Email     string
		}

		// Get existing questions with user emails
		rows, err := tx.Query(`
			SELECT q.id, q.user_id, q.title, q.content, q.created_at, u.email
			FROM questions q
			JOIN users u ON q.user_id = u.id
		`)
		if err != nil && err != sql.ErrNoRows {
			tx.Rollback()
			return err
		}

		if err != sql.ErrNoRows {
			defer rows.Close()
			for rows.Next() {
				var q struct {
					ID        int
					UserID    int
					Title     string
					Content   string
					CreatedAt time.Time
					Email     string
				}
				if err := rows.Scan(&q.ID, &q.UserID, &q.Title, &q.Content, &q.CreatedAt, &q.Email); err != nil {
					tx.Rollback()
					return err
				}
				questions = append(questions, q)
			}
		}

		// Drop existing tables
		dropTables := []string{"answers", "questions", "question_authors"}
		for _, table := range dropTables {
			_, err = tx.Exec(`DROP TABLE IF EXISTS ` + table)
			if err != nil {
				tx.Rollback()
				return err
			}
		}

		// Create new tables
		_, err = tx.Exec(`
			CREATE TABLE question_authors (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				email TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		`)
		if err != nil {
			tx.Rollback()
			return err
		}

		_, err = tx.Exec(`
			CREATE TABLE questions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				author_id INTEGER NOT NULL,
				title TEXT NOT NULL,
				content TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				deleted_at DATETIME,
				FOREIGN KEY (author_id) REFERENCES question_authors(id)
			)
		`)
		if err != nil {
			tx.Rollback()
			return err
		}

		_, err = tx.Exec(`
			CREATE TABLE answers (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				question_id INTEGER NOT NULL,
				user_id INTEGER NOT NULL,
				content TEXT NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (question_id) REFERENCES questions(id),
				FOREIGN KEY (user_id) REFERENCES users(id)
			)
		`)
		if err != nil {
			tx.Rollback()
			return err
		}

		// Restore the data
		emailToAuthorID := make(map[string]int64)

		// Migrate existing data if we had any
		if len(questions) > 0 {
			for _, q := range questions {
				// Create or get question author
				var authorID int64
				if id, ok := emailToAuthorID[q.Email]; ok {
					authorID = id
				} else {
					result, err := tx.Exec("INSERT INTO question_authors (email) VALUES (?)", q.Email)
					if err != nil {
						tx.Rollback()
						return err
					}
					authorID, err = result.LastInsertId()
					if err != nil {
						tx.Rollback()
						return err
					}
					emailToAuthorID[q.Email] = authorID
				}

				// Create question
				_, err = tx.Exec(`
					INSERT INTO questions (id, author_id, title, content, created_at)
					VALUES (?, ?, ?, ?, ?)
				`, q.ID, authorID, q.Title, q.Content, q.CreatedAt)
				if err != nil {
					tx.Rollback()
					return err
				}
			}
		}

		err = tx.Commit()
		if err != nil {
			return err
		}

		log.Println("Migration completed successfully")
	}

	return nil
}

func InitDB(dataSourceName string) (*DB, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	dbWrapper := &DB{db}

	// Run migrations first (this will create/recreate tables if needed)
	if err = dbWrapper.MigrateDB(); err != nil {
		return nil, err
	}

	return dbWrapper, nil
}

func (db *DB) CreateTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS question_authors (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS questions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			author_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			deleted_at DATETIME,
			FOREIGN KEY (author_id) REFERENCES question_authors(id)
		)`,
		`CREATE TABLE IF NOT EXISTS answers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			question_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			content TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (question_id) REFERENCES questions(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS blocked_emails (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL,
			blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			blocked_by INTEGER NOT NULL,
			reason TEXT,
			FOREIGN KEY (blocked_by) REFERENCES users(id)
		)`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			return err
		}
	}

	return nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Check if an email is blocked
func (db *DB) IsEmailBlocked(email string) (bool, error) {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM blocked_emails WHERE email = ?)", email).Scan(&exists)
	return exists, err
}

// Block an email
func (db *DB) BlockEmail(email string, blockedBy int, reason string) error {
	// Start a transaction since we're doing multiple operations
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	// Insert into blocked_emails
	_, err = tx.Exec(`
		INSERT INTO blocked_emails (email, blocked_by, reason)
		VALUES (?, ?, ?)
	`, email, blockedBy, reason)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Soft delete all questions from this author
	_, err = tx.Exec(`
		UPDATE questions 
		SET deleted_at = CURRENT_TIMESTAMP 
		WHERE author_id IN (
			SELECT id FROM question_authors WHERE email = ?
		) AND deleted_at IS NULL
	`, email)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// Soft delete a question
func (db *DB) SoftDeleteQuestion(questionID int) error {
	_, err := db.Exec(`
		UPDATE questions 
		SET deleted_at = CURRENT_TIMESTAMP 
		WHERE id = ? AND deleted_at IS NULL
	`, questionID)
	return err
}

// Get blocked emails with blocker information and their questions
func (db *DB) GetBlockedEmails() ([]BlockedEmailWithQuestions, error) {
	// First get all blocked emails
	rows, err := db.Query(`
		SELECT be.email, be.blocked_at, u.email as blocked_by, be.reason
		FROM blocked_emails be
		JOIN users u ON be.blocked_by = u.id
		ORDER BY be.blocked_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blockedEmails []BlockedEmailWithQuestions

	for rows.Next() {
		var be BlockedEmailWithQuestions
		if err := rows.Scan(&be.Email, &be.BlockedAt, &be.BlockedBy, &be.Reason); err != nil {
			return nil, err
		}

		// For each blocked email, get their questions
		questionRows, err := db.Query(`
			SELECT q.id, q.author_id, q.title, q.content, q.created_at, q.deleted_at
			FROM questions q
			JOIN question_authors qa ON q.author_id = qa.id
			WHERE qa.email = ?
			ORDER BY q.created_at DESC
		`, be.Email)
		if err != nil {
			return nil, err
		}
		defer questionRows.Close()

		for questionRows.Next() {
			var q Question
			if err := questionRows.Scan(&q.ID, &q.AuthorID, &q.Title, &q.Content, &q.CreatedAt, &q.DeletedAt); err != nil {
				return nil, err
			}
			be.Questions = append(be.Questions, q)
		}

		blockedEmails = append(blockedEmails, be)
	}

	return blockedEmails, nil
}
