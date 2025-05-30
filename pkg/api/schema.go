package api

import "time"

// Request Types
type CreateQuestionRequest struct {
	Email   string `json:"email" validate:"required,email"`
	Content string `json:"content" validate:"required,min=10"`
}

type CreateAnswerRequest struct {
	Content string `json:"content" validate:"required,min=10"`
}

type BlockEmailRequest struct {
	Email  string `json:"email" validate:"required,email"`
	Reason string `json:"reason" validate:"required"`
}

// Response Types
type QuestionResponse struct {
	ID              int              `json:"id"`
	Title           string           `json:"title"`
	Content         string           `json:"content"`
	AuthorEmail     string           `json:"authorEmail"`
	CreatedAt       time.Time        `json:"createdAt"`
	DeletedAt       *time.Time       `json:"deletedAt,omitempty"`
	IsAuthorBlocked bool             `json:"isAuthorBlocked"`
	Answers         []AnswerResponse `json:"answers,omitempty"`
}

type AnswerResponse struct {
	ID        int       `json:"id"`
	Content   string    `json:"content"`
	UserEmail string    `json:"userEmail"`
	CreatedAt time.Time `json:"createdAt"`
}

type BlockedEmailResponse struct {
	Email     string             `json:"email"`
	BlockedAt time.Time          `json:"blockedAt"`
	BlockedBy string             `json:"blockedBy"`
	Reason    string             `json:"reason"`
	Questions []QuestionResponse `json:"questions,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}
