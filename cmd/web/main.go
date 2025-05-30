package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"questionapp/pkg/api"
	"questionapp/pkg/handlers"
	"questionapp/pkg/models"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	log.Println("Starting application...")

	// Initialize the database
	db, err := models.InitDB("./questions.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create tables
	if err := db.CreateTables(); err != nil {
		log.Fatal(err)
	}

	// Initialize session store with a strong key
	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		sessionKey = "your-secret-key-replace-in-production"
		log.Println("Warning: Using default session key. Set SESSION_KEY environment variable in production.")
	}

	// Check registration toggle
	allowRegistration, _ := strconv.ParseBool(os.Getenv("ALLOW_REGISTRATION"))
	if !allowRegistration {
		log.Println("Registration is disabled by default. Set ALLOW_REGISTRATION=true to enable new user registration.")
	}

	store := sessions.NewCookieStore([]byte(sessionKey))

	// Configure session store
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	}

	// Initialize application
	app := &handlers.Application{
		DB:                db,
		Store:             store,
		Templates:         make(map[string]*template.Template),
		AllowRegistration: allowRegistration,
	}

	// Load templates
	err = app.LoadTemplates()
	if err != nil {
		log.Fatal(err)
	}

	// Initialize API
	apiHandler := api.NewAPI(db)

	// Create router
	r := mux.NewRouter()

	// Web routes
	r.HandleFunc("/", app.Home).Methods("GET")
	r.HandleFunc("/login", app.Login).Methods("GET", "POST")
	r.HandleFunc("/logout", app.Logout).Methods("GET")
	r.HandleFunc("/ask", app.AskForm).Methods("GET")
	r.HandleFunc("/submit-question", app.SubmitQuestion).Methods("POST")
	r.HandleFunc("/question/{id:[0-9]+}", app.ViewQuestion).Methods("GET")
	r.HandleFunc("/question/{id:[0-9]+}/answer", app.AnswerQuestion).Methods("POST")
	r.HandleFunc("/question/{id:[0-9]+}/delete", app.DeleteQuestion).Methods("POST")
	r.HandleFunc("/block-email", app.BlockEmail).Methods("POST")
	r.HandleFunc("/blocked-emails", app.BlockedEmails).Methods("GET")

	// API documentation
	r.HandleFunc("/api/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/swagger/index.html", http.StatusMovedPermanently)
	}).Methods("GET")

	// Serve OpenAPI specification
	r.HandleFunc("/api/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		http.ServeFile(w, r, filepath.Join("api", "openapi.yaml"))
	}).Methods("GET")

	// API routes with middleware
	apiRouter := r.PathPrefix("/api").Subrouter()
	apiRouter.Use(api.CORSMiddleware)

	// Authentication endpoint
	apiRouter.HandleFunc("/auth/login", apiHandler.Login).Methods("POST", "OPTIONS")

	// Public API endpoints
	apiRouter.HandleFunc("/questions", apiHandler.ListQuestions).Methods("GET", "OPTIONS")
	apiRouter.HandleFunc("/questions", apiHandler.CreateQuestion).Methods("POST", "OPTIONS")
	apiRouter.HandleFunc("/questions/{id:[0-9]+}", apiHandler.GetQuestion).Methods("GET", "OPTIONS")

	// Protected API endpoints
	protected := apiRouter.NewRoute().Subrouter()
	protected.Use(api.AuthMiddleware)
	protected.HandleFunc("/questions/{id:[0-9]+}", apiHandler.DeleteQuestion).Methods("DELETE", "OPTIONS")
	protected.HandleFunc("/questions/{id:[0-9]+}/answers", apiHandler.CreateAnswer).Methods("POST", "OPTIONS")
	protected.HandleFunc("/blocked-emails", apiHandler.ListBlockedEmails).Methods("GET", "OPTIONS")
	protected.HandleFunc("/blocked-emails", apiHandler.BlockEmail).Methods("POST", "OPTIONS")

	// Serve static files
	fileServer := http.FileServer(http.Dir("./ui/static"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fileServer))

	// Start the server
	log.Println("Starting server on :8080")
	log.Println("API documentation available at http://localhost:8080/api/docs")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
