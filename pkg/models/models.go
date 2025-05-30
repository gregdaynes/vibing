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
	ID        int
	AuthorID  int
	Title     string
	Content   string
	CreatedAt time.Time
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
