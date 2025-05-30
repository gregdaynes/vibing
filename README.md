# Q&A Web Application

A simple web application built with Go that allows users to ask questions and provide answers. Users are identified by their email addresses.

## Features

- User authentication via email
- Ask questions
- View all questions
- View individual questions
- Post answers to questions
- Modern UI with Tailwind CSS

## Prerequisites

- Go 1.24 or later
- SQLite 3.49 or later

## Setup

1. Clone the repository
2. Set up the environment variable for session key:
   ```bash
   export SESSION_KEY=your-secret-key
   ```

3. Run the application:
   ```bash
   go mod tidy
   go run cmd/web/main.go
   ```

4. Open your browser and navigate to `http://localhost:8080`

## Project Structure

```
.
├── cmd
│   └── web
│       └── main.go           # Application entry point
├── pkg
│   ├── handlers
│   │   └── handlers.go       # HTTP request handlers
│   └── models
│       └── models.go         # Database models and operations
├── ui
│   └── templates            # HTML templates
│       ├── layout.html      # Base template
│       ├── home.html        # Home page template
│       ├── login.html       # Login page template
│       ├── ask.html         # Ask question page template
│       └── question.html    # Question detail page template
└── static                   # Static assets (CSS, JS)
    ├── css
    └── js
```

## Database

The application uses SQLite as its database. The database file will be created automatically when you first run the application.

## Security

- Session management is handled using secure cookies
- User authentication is email-based
- No passwords are required, making it simple to use while maintaining user identity

## Contributing

Feel free to submit issues and enhancement requests! 