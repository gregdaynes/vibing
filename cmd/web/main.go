package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"questionapp/pkg/handlers"
	"questionapp/pkg/models"

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
	allowRegistration := os.Getenv("ALLOW_REGISTRATION")
	if allowRegistration == "" {
		allowRegistration = "false" // Default to disabling registration
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

	// Load templates
	log.Println("Loading templates...")
	templates := make(map[string]*template.Template)

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
		"maskEmail": handlers.MaskEmail,
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
			log.Fatalf("Error parsing template %s: %v", tf, err)
		}
		templates[tf] = t
	}

	log.Println("Templates loaded successfully")

	// Initialize the application
	app := &handlers.Application{
		DB:                db,
		Store:             store,
		Templates:         templates,
		AllowRegistration: strings.ToLower(allowRegistration) == "true",
	}

	// Create router
	r := mux.NewRouter()

	// Define routes
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

	// Serve static files
	fileServer := http.FileServer(http.Dir("./static/"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fileServer))

	// Start the server
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
