package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"questionapp/pkg/models"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
)

type API struct {
	DB        *models.DB
	Validator *validator.Validate
}

func NewAPI(db *models.DB) *API {
	return &API{
		DB:        db,
		Validator: validator.New(),
	}
}

func (api *API) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			log.Printf("Error encoding response: %v", err)
		}
	}
}

func (api *API) respondError(w http.ResponseWriter, status int, message string) {
	api.respondJSON(w, status, ErrorResponse{
		Error: message,
		Code:  status,
	})
}

// GET /api/questions
func (api *API) ListQuestions(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	var isAuthenticated bool
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			_, err := validateToken(parts[1])
			isAuthenticated = err == nil
		}
	}

	// Build the query based on authentication status
	query := `
		SELECT q.id, q.author_id, q.title, q.content, q.created_at, q.deleted_at,
			   EXISTS(SELECT 1 FROM blocked_emails be 
					 JOIN question_authors qa ON qa.email = be.email 
					 WHERE qa.id = q.author_id) as is_author_blocked,
			   qa.email as author_email
		FROM questions q
		JOIN question_authors qa ON q.author_id = qa.id
		WHERE 1=1
	`

	// For unauthenticated users:
	// - Only show non-deleted questions
	// - Only show questions with answers
	if !isAuthenticated {
		query += `
			AND q.deleted_at IS NULL
			AND EXISTS (SELECT 1 FROM answers WHERE question_id = q.id)
		`
	} else {
		// For authenticated users:
		// - Show deleted questions only within 14 days
		query += `
			AND (q.deleted_at IS NULL OR q.deleted_at > datetime('now', '-14 days'))
		`
	}

	query += " ORDER BY q.created_at DESC"

	rows, err := api.DB.Query(query)
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error fetching questions")
		return
	}
	defer rows.Close()

	var questions []QuestionResponse
	for rows.Next() {
		var q QuestionResponse
		var authorEmail string
		err = rows.Scan(
			&q.ID, &q.AuthorEmail, &q.Title, &q.Content, &q.CreatedAt,
			&q.DeletedAt, &q.IsAuthorBlocked, &authorEmail,
		)
		if err != nil {
			api.respondError(w, http.StatusInternalServerError, "Error scanning questions")
			return
		}
		q.AuthorEmail = authorEmail

		// Fetch answers for each question
		answerRows, err := api.DB.Query(`
			SELECT a.id, a.content, a.created_at, u.email
			FROM answers a
			JOIN users u ON a.user_id = u.id
			WHERE a.question_id = ?
			ORDER BY a.created_at DESC
		`, q.ID)
		if err != nil {
			api.respondError(w, http.StatusInternalServerError, "Error fetching answers")
			return
		}
		defer answerRows.Close()

		q.Answers = make([]AnswerResponse, 0)
		for answerRows.Next() {
			var a AnswerResponse
			err = answerRows.Scan(&a.ID, &a.Content, &a.CreatedAt, &a.UserEmail)
			if err != nil {
				api.respondError(w, http.StatusInternalServerError, "Error scanning answers")
				return
			}
			q.Answers = append(q.Answers, a)
		}
		answerRows.Close() // Close the inner rows before starting the next iteration

		questions = append(questions, q)
	}

	api.respondJSON(w, http.StatusOK, questions)
}

// GET /api/questions/{id}
func (api *API) GetQuestion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.respondError(w, http.StatusBadRequest, "Invalid question ID")
		return
	}

	// Check if user is authenticated
	var isAuthenticated bool
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			_, err := validateToken(parts[1])
			isAuthenticated = err == nil
		}
	}

	// First check if the question exists and if it's deleted
	var isDeleted bool
	var deletedAt sql.NullTime
	err = api.DB.QueryRow(`
		SELECT deleted_at IS NOT NULL, deleted_at
		FROM questions
		WHERE id = ?
	`, id).Scan(&isDeleted, &deletedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			api.respondError(w, http.StatusNotFound, "Question not found")
		} else {
			api.respondError(w, http.StatusInternalServerError, "Error checking question status")
		}
		return
	}

	// Handle deleted questions based on authentication status
	if isDeleted {
		if !isAuthenticated {
			// Don't reveal deletion status to unauthenticated users
			api.respondError(w, http.StatusNotFound, "Question not found")
			return
		}

		// For authenticated users, check deletion window and provide specific message
		if time.Since(deletedAt.Time) > 14*24*time.Hour {
			api.respondError(w, http.StatusNotFound, "This question was deleted and is no longer available")
			return
		}
	}

	// For non-deleted questions, check if there are answers for unauthorized users
	if !isAuthenticated && !isDeleted {
		var hasAnswers bool
		err = api.DB.QueryRow(`
			SELECT EXISTS(SELECT 1 FROM answers WHERE question_id = ?)
		`, id).Scan(&hasAnswers)
		if err != nil {
			api.respondError(w, http.StatusInternalServerError, "Error checking answers")
			return
		}

		if !hasAnswers {
			api.respondError(w, http.StatusUnauthorized, "You must be logged in to view unanswered questions")
			return
		}
	}

	// Now fetch the full question with author details
	var q QuestionResponse
	var authorEmail string
	err = api.DB.QueryRow(`
		SELECT q.id, q.author_id, q.title, q.content, q.created_at, q.deleted_at,
			   EXISTS(SELECT 1 FROM blocked_emails be 
					 JOIN question_authors qa ON qa.email = be.email 
					 WHERE qa.id = q.author_id) as is_author_blocked,
			   qa.email as author_email
		FROM questions q
		JOIN question_authors qa ON q.author_id = qa.id
		WHERE q.id = ?
	`, id).Scan(
		&q.ID, &q.AuthorEmail, &q.Title, &q.Content, &q.CreatedAt,
		&q.DeletedAt, &q.IsAuthorBlocked, &authorEmail,
	)

	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error fetching question")
		return
	}
	q.AuthorEmail = authorEmail

	// Fetch answers
	rows, err := api.DB.Query(`
		SELECT a.id, a.content, a.created_at, u.email
		FROM answers a
		JOIN users u ON a.user_id = u.id
		WHERE a.question_id = ?
		ORDER BY a.created_at DESC
	`, id)
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error fetching answers")
		return
	}
	defer rows.Close()

	q.Answers = make([]AnswerResponse, 0)
	for rows.Next() {
		var a AnswerResponse
		err = rows.Scan(&a.ID, &a.Content, &a.CreatedAt, &a.UserEmail)
		if err != nil {
			api.respondError(w, http.StatusInternalServerError, "Error scanning answers")
			return
		}
		q.Answers = append(q.Answers, a)
	}

	api.respondJSON(w, http.StatusOK, q)
}

// POST /api/questions
func (api *API) CreateQuestion(w http.ResponseWriter, r *http.Request) {
	var req CreateQuestionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := api.Validator.Struct(req); err != nil {
		api.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check if email is blocked
	isBlocked, err := api.DB.IsEmailBlocked(req.Email)
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error checking email status")
		return
	}
	if isBlocked {
		api.respondError(w, http.StatusForbidden, "This email address has been blocked")
		return
	}

	// Create or get author
	var authorID int
	err = api.DB.QueryRow("SELECT id FROM question_authors WHERE email = ?", req.Email).Scan(&authorID)
	if err != nil {
		result, err := api.DB.Exec("INSERT INTO question_authors (email) VALUES (?)", req.Email)
		if err != nil {
			api.respondError(w, http.StatusInternalServerError, "Error creating author")
			return
		}
		id, _ := result.LastInsertId()
		authorID = int(id)
	}

	// Create title from content
	words := strings.Fields(req.Content)
	title := req.Content
	if len(words) > 5 {
		title = strings.Join(words[:5], " ") + "..."
	}

	result, err := api.DB.Exec(`
		INSERT INTO questions (author_id, title, content)
		VALUES (?, ?, ?)
	`, authorID, title, req.Content)
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error creating question")
		return
	}

	id, _ := result.LastInsertId()
	api.respondJSON(w, http.StatusCreated, map[string]int{"id": int(id)})
}

// POST /api/questions/{id}/answers
func (api *API) CreateAnswer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	questionID, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.respondError(w, http.StatusBadRequest, "Invalid question ID")
		return
	}

	var req CreateAnswerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := api.Validator.Struct(req); err != nil {
		api.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get user from auth context (simplified for example)
	userID := r.Context().Value("user_id").(int)

	result, err := api.DB.Exec(`
		INSERT INTO answers (question_id, user_id, content)
		VALUES (?, ?, ?)
	`, questionID, userID, req.Content)
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error creating answer")
		return
	}

	id, _ := result.LastInsertId()
	api.respondJSON(w, http.StatusCreated, map[string]int{"id": int(id)})
}

// DELETE /api/questions/{id}
func (api *API) DeleteQuestion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.respondError(w, http.StatusBadRequest, "Invalid question ID")
		return
	}

	err = api.DB.SoftDeleteQuestion(id)
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error deleting question")
		return
	}

	api.respondJSON(w, http.StatusNoContent, nil)
}

// GET /api/blocked-emails
func (api *API) ListBlockedEmails(w http.ResponseWriter, r *http.Request) {
	blockedEmails, err := api.DB.GetBlockedEmails()
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error fetching blocked emails")
		return
	}

	var response []BlockedEmailResponse
	for _, be := range blockedEmails {
		response = append(response, BlockedEmailResponse{
			Email:     be.Email,
			BlockedAt: be.BlockedAt,
			BlockedBy: be.BlockedBy,
			Reason:    be.Reason,
			Questions: make([]QuestionResponse, 0), // Questions will be populated if needed
		})
	}

	api.respondJSON(w, http.StatusOK, response)
}

// POST /api/blocked-emails
func (api *API) BlockEmail(w http.ResponseWriter, r *http.Request) {
	var req BlockEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := api.Validator.Struct(req); err != nil {
		api.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get user from auth context (simplified for example)
	userID := r.Context().Value("user_id").(int)

	err := api.DB.BlockEmail(req.Email, userID, req.Reason)
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error blocking email")
		return
	}

	api.respondJSON(w, http.StatusCreated, nil)
}

// POST /api/auth/login
func (api *API) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := api.Validator.Struct(req); err != nil {
		api.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get user from database
	var user struct {
		ID           int
		Email        string
		PasswordHash string
	}
	err := api.DB.QueryRow("SELECT id, email, password_hash FROM users WHERE email = ?", req.Email).Scan(
		&user.ID, &user.Email, &user.PasswordHash,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			api.respondError(w, http.StatusUnauthorized, "Invalid email or password")
			return
		}
		api.respondError(w, http.StatusInternalServerError, "Error fetching user")
		return
	}

	// Verify password
	if !models.CheckPasswordHash(req.Password, user.PasswordHash) {
		api.respondError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	// Generate JWT token
	token, err := generateToken(user.ID, user.Email)
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	api.respondJSON(w, http.StatusOK, LoginResponse{Token: token})
}
