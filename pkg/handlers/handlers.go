package handlers

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
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
	IsLoggedIn   bool
	UserEmail    string
	Data         interface{}
	Funcs        template.FuncMap
	FlashMessage *FlashMessage
}

type FlashMessage struct {
	Type    string // "success", "error", etc.
	Title   string
	Content string
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

	isLoggedIn, _, _ := app.getSessionData(r)

	var rows *sql.Rows
	var err error

	if isLoggedIn {
		rows, err = app.DB.Query(`
			SELECT q.id, q.author_id, q.title, q.content, q.created_at, q.deleted_at,
				   EXISTS(SELECT 1 FROM blocked_emails be 
						 JOIN question_authors qa ON qa.email = be.email 
						 WHERE qa.id = q.author_id) as is_author_blocked
			FROM questions q 
			WHERE (q.deleted_at IS NULL OR 
				   (q.deleted_at IS NOT NULL AND q.deleted_at > datetime('now', '-14 days')))
			ORDER BY q.created_at DESC
		`)
	} else {
		rows, err = app.DB.Query(`
			SELECT DISTINCT q.id, q.author_id, q.title, q.content, q.created_at, q.deleted_at,
				   EXISTS(SELECT 1 FROM blocked_emails be 
						 JOIN question_authors qa ON qa.email = be.email 
						 WHERE qa.id = q.author_id) as is_author_blocked
			FROM questions q 
			INNER JOIN answers a ON q.id = a.question_id
			WHERE q.deleted_at IS NULL
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
		err = rows.Scan(&q.ID, &q.AuthorID, &q.Title, &q.Content, &q.CreatedAt, &q.DeletedAt, &q.IsAuthorBlocked)
		if err != nil {
			log.Printf("Error scanning question: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		questions = append(questions, q)
	}

	data := app.newTemplateData(r)
	data.Data = questions

	// Check for flash message in URL parameters
	if msgType := r.URL.Query().Get("msg_type"); msgType != "" {
		data.FlashMessage = &FlashMessage{
			Type:    msgType,
			Title:   r.URL.Query().Get("msg_title"),
			Content: r.URL.Query().Get("msg_content"),
		}
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

// Helper function to set a flash message
func (app *Application) setFlashMessage(w http.ResponseWriter, r *http.Request, msgType, title, content string) {
	log.Printf("Attempting to set flash message: type=%s, title=%s", msgType, title)
	session, err := app.Store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		return
	}

	// Store the flash message in the session
	session.Values["flash"] = FlashMessage{
		Type:    msgType,
		Title:   title,
		Content: content,
	}
	log.Printf("Flash message stored in session.Values")

	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %v", err)
		return
	}
	log.Printf("Session saved successfully with flash message")
}

// Update template data creation to include flash messages
func (app *Application) newTemplateData(r *http.Request) TemplateData {
	log.Printf("Creating new template data")
	isLoggedIn, _, email := app.getSessionData(r)

	// Get flash message if any
	var flashMessage *FlashMessage
	session, err := app.Store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session in newTemplateData: %v", err)
		return TemplateData{
			IsLoggedIn: isLoggedIn,
			UserEmail:  email,
		}
	}

	// Check for flash message in session values
	if flash, ok := session.Values["flash"].(FlashMessage); ok {
		log.Printf("Found flash message in session: %+v", flash)
		flashMessage = &flash
		// Clear the flash message
		delete(session.Values, "flash")
		err = session.Save(r, nil)
		if err != nil {
			log.Printf("Error saving session after clearing flash: %v", err)
		} else {
			log.Printf("Flash message cleared from session")
		}
	} else {
		log.Printf("No flash message found in session")
	}

	return TemplateData{
		IsLoggedIn:   isLoggedIn,
		UserEmail:    email,
		FlashMessage: flashMessage,
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

	isLoggedIn, _, _ := app.getSessionData(r)

	var question models.Question
	var query string
	if isLoggedIn {
		query = `
			SELECT q.id, q.author_id, q.title, q.content, q.created_at, q.deleted_at,
				   EXISTS(SELECT 1 FROM blocked_emails be 
						 JOIN question_authors qa ON qa.email = be.email 
						 WHERE qa.id = q.author_id) as is_author_blocked
			FROM questions q
			WHERE q.id = ? AND (q.deleted_at IS NULL OR q.deleted_at > datetime('now', '-14 days'))
		`
	} else {
		query = `
			SELECT q.id, q.author_id, q.title, q.content, q.created_at, q.deleted_at,
				   EXISTS(SELECT 1 FROM blocked_emails be 
						 JOIN question_authors qa ON qa.email = be.email 
						 WHERE qa.id = q.author_id) as is_author_blocked
			FROM questions q
			WHERE q.id = ? AND q.deleted_at IS NULL
		`
	}

	err = app.DB.QueryRow(query, id).Scan(
		&question.ID,
		&question.AuthorID,
		&question.Title,
		&question.Content,
		&question.CreatedAt,
		&question.DeletedAt,
		&question.IsAuthorBlocked,
	)

	if err != nil {
		log.Printf("Error finding question: %v", err)
		http.Error(w, "Question not found", http.StatusNotFound)
		return
	}

	// Check visibility permissions for non-deleted questions
	if question.DeletedAt == nil {
		hasAnswers, err := app.hasAnswers(id)
		if err != nil {
			log.Printf("Error checking answers: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !isLoggedIn && !hasAnswers {
			http.Error(w, "You must be logged in to view unanswered questions", http.StatusForbidden)
			return
		}
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

	// Check if email is blocked
	isBlocked, err := app.DB.IsEmailBlocked(email)
	if err != nil {
		log.Printf("Error checking if email is blocked: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if isBlocked {
		// Redirect with error message
		redirectURL := fmt.Sprintf("/?msg_type=error&msg_title=%s&msg_content=%s",
			url.QueryEscape("Submission Blocked"),
			url.QueryEscape("This email address has been blocked from submitting questions."))
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	// First, create or get the question author
	var authorID int
	err = app.DB.QueryRow("SELECT id FROM question_authors WHERE email = ?", email).Scan(&authorID)
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

	// Redirect with success message in URL parameters
	redirectURL := fmt.Sprintf("/?msg_type=success&msg_title=%s&msg_content=%s",
		url.QueryEscape("Question Submitted Successfully"),
		url.QueryEscape("Your question has been submitted and you'll be notified by email when it receives an answer."))

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (app *Application) Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session-name")
	session.Options.MaxAge = -1 // This will delete the cookie
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *Application) DeleteQuestion(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	isLoggedIn, _, _ := app.getSessionData(r)
	if !isLoggedIn {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	questionID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid question ID", http.StatusBadRequest)
		return
	}

	err = app.DB.SoftDeleteQuestion(questionID)
	if err != nil {
		log.Printf("Error deleting question: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect with success message
	redirectURL := fmt.Sprintf("/?msg_type=success&msg_title=%s&msg_content=%s",
		url.QueryEscape("Question Deleted"),
		url.QueryEscape("The question has been successfully deleted."))

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (app *Application) BlockEmail(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	isLoggedIn, userID, _ := app.getSessionData(r)
	if !isLoggedIn {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	reason := r.FormValue("reason")

	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Block the email
	err := app.DB.BlockEmail(email, userID, reason)
	if err != nil {
		log.Printf("Error blocking email: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect with success message
	redirectURL := fmt.Sprintf("/?msg_type=success&msg_title=%s&msg_content=%s",
		url.QueryEscape("Email Blocked"),
		url.QueryEscape(fmt.Sprintf("The email address %s has been blocked.", email)))

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (app *Application) BlockedEmails(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	isLoggedIn, _, _ := app.getSessionData(r)
	if !isLoggedIn {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	blockedEmails, err := app.DB.GetBlockedEmails()
	if err != nil {
		log.Printf("Error getting blocked emails: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := app.newTemplateData(r)
	data.Data = blockedEmails

	err = app.Templates["blocked_emails.html"].ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (app *Application) LoadTemplates() error {
	log.Println("Loading templates...")

	// Define our template functions
	funcMap := template.FuncMap{
		"len": func(a interface{}) int {
			switch v := a.(type) {
			case []models.Answer:
				return len(v)
			case []models.AnswerWithEmail:
				return len(v)
			default:
				return 0
			}
		},
		"maskEmail": MaskEmail,
	}

	// Load each template paired with the layout
	templateFiles := []string{
		"home.html",
		"login.html",
		"ask.html",
		"question.html",
		"ask_form.html",
		"blocked_emails.html",
	}

	for _, tf := range templateFiles {
		t, err := template.New("layout.html").Funcs(funcMap).ParseFiles(
			"ui/templates/layout.html",
			"ui/templates/"+tf,
		)
		if err != nil {
			return fmt.Errorf("error parsing template %s: %v", tf, err)
		}
		app.Templates[tf] = t
	}

	log.Println("Templates loaded successfully")
	return nil
}
