package handlers

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"

	"questionapp/pkg/models"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

type Application struct {
	DB                *models.DB
	Store             *sessions.CookieStore
	Templates         map[string]*template.Template
	AllowRegistration bool
}

// Template data structure
type TemplateData struct {
	IsLoggedIn bool
	UserEmail  string
	Data       interface{}
	Funcs      template.FuncMap
}

// Get user session data
func (app *Application) getSessionData(r *http.Request) (bool, int, string) {
	session, _ := app.Store.Get(r, "session-name")
	userID, ok := session.Values["user_id"].(int)
	if !ok {
		return false, 0, ""
	}

	var email string
	err := app.DB.QueryRow("SELECT email FROM users WHERE id = ?", userID).Scan(&email)
	if err != nil {
		return false, 0, ""
	}

	return true, userID, email
}

func (app *Application) Home(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling home request")

	isLoggedIn, _, email := app.getSessionData(r)

	// Different query based on login status
	var rows *sql.Rows
	var err error

	if isLoggedIn {
		// Logged in users see all questions
		rows, err = app.DB.Query(`
			SELECT q.id, q.author_id, q.title, q.content, q.created_at 
			FROM questions q 
			ORDER BY q.created_at DESC
		`)
	} else {
		// Non-logged in users only see questions with answers
		rows, err = app.DB.Query(`
			SELECT DISTINCT q.id, q.author_id, q.title, q.content, q.created_at 
			FROM questions q 
			INNER JOIN answers a ON q.id = a.question_id
			ORDER BY q.created_at DESC
		`)
	}

	if err != nil {
		log.Printf("Error querying questions: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	questions := []models.Question{}
	for rows.Next() {
		var q models.Question
		err = rows.Scan(&q.ID, &q.AuthorID, &q.Title, &q.Content, &q.CreatedAt)
		if err != nil {
			log.Printf("Error scanning question: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		questions = append(questions, q)
	}

	data := TemplateData{
		IsLoggedIn: isLoggedIn,
		UserEmail:  email,
		Data:       questions,
	}

	err = app.Templates["home.html"].ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Helper function to check if a question has answers
func (app *Application) hasAnswers(questionID int) (bool, error) {
	var count int
	err := app.DB.QueryRow("SELECT COUNT(*) FROM answers WHERE question_id = ?", questionID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (app *Application) AskQuestion(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		content := r.FormValue("content")

		// First, get or create the user
		var userID int
		err := app.DB.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
		if err != nil {
			// If user doesn't exist, create new user
			result, err := app.DB.Exec("INSERT INTO users (email) VALUES (?)", email)
			if err != nil {
				log.Printf("Error creating user: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			id, _ := result.LastInsertId()
			userID = int(id)
		}

		// Create the question - use first few words as title
		words := strings.Fields(content)
		title := content
		if len(words) > 5 {
			title = strings.Join(words[:5], " ") + "..."
		}

		// Now create the question
		_, err = app.DB.Exec(`
			INSERT INTO questions (user_id, title, content)
			VALUES (?, ?, ?)
		`, userID, title, content)

		if err != nil {
			log.Printf("Error inserting question: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	err := app.Templates["home.html"].ExecuteTemplate(w, "layout", nil)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Helper function to mask email addresses
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email // Return original if not a valid email
	}
	return parts[0] + "@***"
}

// Update TemplateData to include helper functions
func (app *Application) newTemplateData(r *http.Request) TemplateData {
	isLoggedIn, _, email := app.getSessionData(r)
	return TemplateData{
		IsLoggedIn: isLoggedIn,
		UserEmail:  email,
		Funcs: template.FuncMap{
			"maskEmail": MaskEmail,
		},
	}
}

// Update ViewQuestion handler to use the new template data
func (app *Application) ViewQuestion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid question ID", http.StatusBadRequest)
		return
	}

	var question models.Question
	err = app.DB.QueryRow(`
		SELECT id, author_id, title, content, created_at
		FROM questions WHERE id = ?
	`, id).Scan(&question.ID, &question.AuthorID, &question.Title, &question.Content, &question.CreatedAt)

	if err != nil {
		log.Printf("Error finding question: %v", err)
		http.Error(w, "Question not found", http.StatusNotFound)
		return
	}

	// Check visibility permissions
	hasAnswers, err := app.hasAnswers(id)
	if err != nil {
		log.Printf("Error checking answers: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	isLoggedIn, _, _ := app.getSessionData(r)
	if !isLoggedIn && !hasAnswers {
		http.Error(w, "You must be logged in to view unanswered questions", http.StatusForbidden)
		return
	}

	// Get author's email
	var authorEmail string
	err = app.DB.QueryRow("SELECT email FROM question_authors WHERE id = ?", question.AuthorID).Scan(&authorEmail)
	if err != nil {
		log.Printf("Error getting author email: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch answers
	rows, err := app.DB.Query(`
		SELECT a.id, a.user_id, a.content, a.created_at, u.email
		FROM answers a
		JOIN users u ON a.user_id = u.id
		WHERE a.question_id = ?
		ORDER BY a.created_at DESC
	`, id)
	if err != nil {
		log.Printf("Error querying answers: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	answersWithEmail := []models.AnswerWithEmail{}
	for rows.Next() {
		var a models.AnswerWithEmail
		err = rows.Scan(&a.ID, &a.UserID, &a.Content, &a.CreatedAt, &a.UserEmail)
		if err != nil {
			log.Printf("Error scanning answer: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		answersWithEmail = append(answersWithEmail, a)
	}

	data := app.newTemplateData(r)
	data.Data = struct {
		Question    models.Question
		AuthorEmail string
		Answers     []models.AnswerWithEmail
	}{
		Question:    question,
		AuthorEmail: authorEmail,
		Answers:     answersWithEmail,
	}

	err = app.Templates["question.html"].ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (app *Application) AnswerQuestion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, _ := app.Store.Get(r, "session-name")
	userID, ok := session.Values["user_id"].(int)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	vars := mux.Vars(r)
	questionID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid question ID", http.StatusBadRequest)
		return
	}

	content := r.FormValue("content")
	_, err = app.DB.Exec(`
		INSERT INTO answers (question_id, user_id, content)
		VALUES (?, ?, ?)
	`, questionID, userID, content)

	if err != nil {
		log.Printf("Error inserting answer: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/question/"+vars["id"], http.StatusSeeOther)
}

func (app *Application) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var user models.User
		err := app.DB.QueryRow("SELECT id, email, password_hash FROM users WHERE email = ?", email).Scan(&user.ID, &user.Email, &user.PasswordHash)
		if err != nil {
			if err == sql.ErrNoRows {
				if !app.AllowRegistration {
					log.Printf("Registration attempt when disabled for email: %s", email)
					http.Error(w, "New user registration is currently disabled", http.StatusForbidden)
					return
				}

				// Create new user
				hashedPassword, err := models.HashPassword(password)
				if err != nil {
					log.Printf("Error hashing password: %v", err)
					http.Error(w, "Error creating user", http.StatusInternalServerError)
					return
				}

				result, err := app.DB.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", email, hashedPassword)
				if err != nil {
					log.Printf("Error creating user: %v", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				id, _ := result.LastInsertId()
				user.ID = int(id)
			} else {
				log.Printf("Error querying user: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// User exists, verify password
			if !models.CheckPasswordHash(password, user.PasswordHash) {
				log.Printf("Invalid password attempt for user: %s", email)
				http.Error(w, "Invalid email or password", http.StatusUnauthorized)
				return
			}
		}

		session, _ := app.Store.Get(r, "session-name")
		session.Values["user_id"] = user.ID
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := app.newTemplateData(r)
	data.Data = struct {
		AllowRegistration bool
	}{
		AllowRegistration: app.AllowRegistration,
	}

	err := app.Templates["login.html"].ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (app *Application) AskForm(w http.ResponseWriter, r *http.Request) {
	err := app.Templates["ask_form.html"].ExecuteTemplate(w, "layout", nil)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (app *Application) SubmitQuestion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	content := r.FormValue("content")

	// First, create or get the question author
	var authorID int
	err := app.DB.QueryRow("SELECT id FROM question_authors WHERE email = ?", email).Scan(&authorID)
	if err == sql.ErrNoRows {
		// Create new question author
		result, err := app.DB.Exec("INSERT INTO question_authors (email) VALUES (?)", email)
		if err != nil {
			log.Printf("Error creating question author: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		id, _ := result.LastInsertId()
		authorID = int(id)
	} else if err != nil {
		log.Printf("Error checking question author: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create the question - use first few words as title
	words := strings.Fields(content)
	title := content
	if len(words) > 5 {
		title = strings.Join(words[:5], " ") + "..."
	}

	// Now create the question
	_, err = app.DB.Exec(`
		INSERT INTO questions (author_id, title, content)
		VALUES (?, ?, ?)
	`, authorID, title, content)

	if err != nil {
		log.Printf("Error inserting question: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *Application) Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session-name")
	session.Options.MaxAge = -1 // This will delete the cookie
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
