package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/logging"
	"github.com/shafraz007/ai-endpoint-platform/internal/migrations"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
	"golang.org/x/crypto/bcrypt"
)

var agentsTemplate *template.Template
var detailTemplate *template.Template
var loginTemplate *template.Template
var changePasswordTemplate *template.Template
var sessionTimeoutTemplate *template.Template

func init() {
	var err error
	agentsTemplate, err = template.ParseFiles("cmd/server/templates/agents.html")
	if err != nil {
		log.Printf("Warning: Failed to parse agents template: %v", err)
	}

	detailTemplate, err = template.ParseFiles("cmd/server/templates/agent-detail.html")
	if err != nil {
		log.Printf("Warning: Failed to parse agent-detail template: %v", err)
	}

	loginTemplate, err = template.ParseFiles("cmd/server/templates/login.html")
	if err != nil {
		log.Printf("Warning: Failed to parse login template: %v", err)
	}

	changePasswordTemplate, err = template.ParseFiles("cmd/server/templates/change-password.html")
	if err != nil {
		log.Printf("Warning: Failed to parse change-password template: %v", err)
	}

	sessionTimeoutTemplate, err = template.ParseFiles("cmd/server/templates/session-timeout.html")
	if err != nil {
		log.Printf("Warning: Failed to parse session-timeout template: %v", err)
	}
}

func heartbeatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var hb transport.HeartbeatRequest

	if r.Body == nil {
		http.Error(w, "Request body is empty", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()

	err := json.NewDecoder(r.Body).Decode(&hb)
	if err != nil {
		log.Printf("JSON decode error: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if hb.AgentID == "" || hb.Hostname == "" {
		http.Error(w, "Missing required fields: agent_id, hostname", http.StatusBadRequest)
		return
	}

	err = server.UpsertAgent(
		hb.AgentID,
		hb.Hostname,
		hb.Domain,
		hb.PublicIP,
		hb.PrivateIP,
		hb.Status,
		hb.AgentVersion,
		hb.LastLogin,
		hb.LastReboot,
		hb.Timezone,
		hb.HardwareVendor,
		hb.HardwareModel,
		hb.HardwareSerialNumber,
		hb.Motherboard,
		hb.BIOSManufacturer,
		hb.BIOSVersion,
		hb.BIOSVersionDate,
		hb.Processor,
		hb.Memory,
		hb.VideoCard,
		hb.Sound,
		hb.SystemDrive,
		hb.MACAddresses,
		hb.Disks,
		hb.Drives,
		hb.OSEdition,
		hb.OSVersion,
		hb.OSBuild,
		hb.Windows11Eligible,
		hb.DotNetVersion,
		hb.OfficeVersion,
		hb.AntivirusName,
		hb.AntiSpywareName,
		hb.FirewallName,
		hb.TLS12Compatible,
	)
	if err != nil {
		log.Printf("Database error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("Heartbeat received from agent: %s (%s)", hb.AgentID, hb.Hostname)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "received"})
}

func agentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	agents, err := server.GetAllAgents(ctx)
	if err != nil {
		log.Printf("Error fetching agents: %v", err)
		http.Error(w, "Failed to fetch agents", http.StatusInternalServerError)
		return
	}

	// Count online and offline agents
	onlineCount := 0
	for _, a := range agents {
		if a.Status == "online" {
			onlineCount++
		}
	}
	offlineCount := len(agents) - onlineCount

	// Prepare template data
	data := map[string]interface{}{
		"Agents":        agents,
		"TotalAgents":   len(agents),
		"OnlineAgents":  onlineCount,
		"OfflineAgents": offlineCount,
		"LastUpdated":   time.Now().Format("2006-01-02 15:04:05"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if agentsTemplate != nil {
		err = agentsTemplate.Execute(w, data)
		if err != nil {
			log.Printf("Error rendering template: %v", err)
			http.Error(w, "Template render error", http.StatusInternalServerError)
		}
	} else {
		http.Error(w, "Template not loaded", http.StatusInternalServerError)
	}
}

func agentDetailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract agent ID from URL path
	agentID := r.URL.Path[len("/agents/"):]
	log.Printf("agentDetailHandler: extracted agentID=%s", agentID)
	if agentID == "" {
		http.Error(w, "Agent ID not provided", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	agent, err := server.GetAgentByID(ctx, agentID)
	if err != nil {
		log.Printf("Error fetching agent (id=%s): %v", agentID, err)
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	log.Printf("Found agent: %v", agent)

	// Create template data with JSON fields marked as safe (not HTML-escaped)
	data := map[string]interface{}{
		"Agent":      agent,
		"DisksJSON":  template.JS(agent.Disks),
		"DrivesJSON": template.JS(agent.Drives),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if detailTemplate != nil {
		log.Printf("Detail template is loaded, executing...")
		err = detailTemplate.Execute(w, data)
		if err != nil {
			log.Printf("Error rendering template: %v", err)
			http.Error(w, "Template render error: "+err.Error(), http.StatusInternalServerError)
		} else {
			log.Printf("Template rendered successfully")
		}
	} else {
		log.Printf("Detail template is nil")
		http.Error(w, "Template not loaded", http.StatusInternalServerError)
	}
}

func requireAdminPage(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig, allowMustChange bool) (*server.User, bool) {
	_, user, err := authorizeAdminSession(w, r, cfg, true)
	if err != nil {
		next := sanitizeNextPath(r.URL.RequestURI())
		target := "/session-timeout"
		if next != "" {
			target = target + "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, target, http.StatusFound)
		return nil, false
	}
	if user.MustChangePassword && !allowMustChange {
		http.Redirect(w, r, "/admin/change-password", http.StatusFound)
		return nil, false
	}
	return user, true
}

func renderLogin(w http.ResponseWriter, message, next string) {
	if loginTemplate == nil {
		http.Error(w, "Template not loaded", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Error": message,
		"Next":  next,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginTemplate.Execute(w, data); err != nil {
		log.Printf("Error rendering login template: %v", err)
		http.Error(w, "Template render error", http.StatusInternalServerError)
	}
}

func renderChangePassword(w http.ResponseWriter, message, next string) {
	if changePasswordTemplate == nil {
		http.Error(w, "Template not loaded", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Error": message,
		"Next":  next,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := changePasswordTemplate.Execute(w, data); err != nil {
		log.Printf("Error rendering change-password template: %v", err)
		http.Error(w, "Template render error", http.StatusInternalServerError)
	}
}

func renderSessionTimeout(w http.ResponseWriter, next string) {
	if sessionTimeoutTemplate == nil {
		http.Error(w, "Template not loaded", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Next": next,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := sessionTimeoutTemplate.Execute(w, data); err != nil {
		log.Printf("Error rendering session-timeout template: %v", err)
		http.Error(w, "Template render error", http.StatusInternalServerError)
	}
}

func sanitizeNextPath(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "/") {
		return ""
	}
	if strings.HasPrefix(raw, "//") {
		return ""
	}
	return raw
}

func loginHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			renderLogin(w, "Invalid form data", "")
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		next := sanitizeNextPath(r.FormValue("next"))

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		user, err := authenticateUser(ctx, username, password)
		if err != nil {
			renderLogin(w, "Invalid username or password", next)
			return
		}

		if err := issueAdminSessionCookie(w, r, cfg, user.Username); err != nil {
			log.Printf("Admin login token error: %v", err)
			renderLogin(w, "Failed to create session", next)
			return
		}
		_ = server.UpdateLastLogin(ctx, user.Username)

		if user.MustChangePassword {
			if next != "" {
				http.Redirect(w, r, "/admin/change-password?next="+url.QueryEscape(next), http.StatusFound)
				return
			}
			http.Redirect(w, r, "/admin/change-password", http.StatusFound)
			return
		}
		if next != "" {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/agents", http.StatusFound)
	}
}

func changePasswordHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := requireAdminPage(w, r, cfg, true)
		if !ok {
			return
		}

		if r.Method == http.MethodGet {
			next := sanitizeNextPath(r.URL.Query().Get("next"))
			renderChangePassword(w, "", next)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			next := sanitizeNextPath(r.FormValue("next"))
			renderChangePassword(w, "Invalid form data", next)
			return
		}

		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")
		next := sanitizeNextPath(r.FormValue("next"))
		if strings.TrimSpace(newPassword) == "" {
			renderChangePassword(w, "New password is required", next)
			return
		}
		if newPassword != confirmPassword {
			renderChangePassword(w, "New password and confirmation do not match", next)
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
			renderChangePassword(w, "Current password is incorrect", next)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			renderChangePassword(w, "Failed to update password", next)
			return
		}
		if err := server.UpdateUserPassword(ctx, user.Username, string(hash), false); err != nil {
			log.Printf("UpdateUserPassword error: %v", err)
			renderChangePassword(w, "Failed to update password", next)
			return
		}

		if next != "" {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/agents", http.StatusFound)
	}
}

func main() {
	cfg := config.LoadServerConfig()
	logCloser, err := logging.Setup("server", cfg.LogDir, cfg.LogToConsole)
	if err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}
	defer logCloser.Close()

	// Initialize database
	if err := server.InitDB(cfg.DatabaseURL); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer server.CloseDB()

	// Run migrations (optionally reset and run from scratch when MIGRATIONS_RESET=true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if os.Getenv("MIGRATIONS_RESET") == "true" {
		log.Println("MIGRATIONS_RESET=true: recreating DB and running migrations from scratch")
		if err := migrations.RecreateAndRunMigrations(ctx, server.DB); err != nil {
			log.Fatalf("Failed to recreate and run migrations: %v", err)
		}
	} else {
		if err := migrations.RunMigrations(ctx, server.DB); err != nil {
			log.Fatalf("Failed to run migrations: %v", err)
		}
	}

	defaultHash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash default admin password: %v", err)
	}
	created, err := server.EnsureDefaultAdmin(ctx, "admin", string(defaultHash))
	if err != nil {
		log.Fatalf("Failed to seed default admin: %v", err)
	}
	if created {
		log.Println("Seeded default admin user (username: admin). Please change the password on first login.")
	}

	// Setup HTTP server with custom router
	mux := http.NewServeMux()

	// API endpoint for heartbeats
	mux.HandleFunc("/api/heartbeat", heartbeatHandler)

	// Commands endpoints (JWT protected)
	mux.HandleFunc("/api/commands", commandsHandler(cfg))
	mux.HandleFunc("/api/commands/next", commandPollHandler(cfg))
	mux.HandleFunc("/api/commands/ack", commandAckHandler(cfg))

	// Metrics endpoints
	mux.HandleFunc("/api/metrics", metricsRouter(cfg))
	mux.HandleFunc("/api/metrics/stream", metricsStreamHandler(cfg))

	// Admin session endpoints
	mux.HandleFunc("/admin/login", adminLoginHandler(cfg))
	mux.HandleFunc("/admin/logout", adminLogoutHandler())

	// Health check endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	// Agents list handler
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminPage(w, r, cfg, false); !ok {
			return
		}
		agentsHandler(w, r)
	})

	// Agent detail handler (must have trailing slash to match /agents/...)
	mux.HandleFunc("/agents/", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminPage(w, r, cfg, false); !ok {
			return
		}
		log.Printf("Route /agents/ handler called for path: %s", r.URL.Path)
		agentID := strings.TrimPrefix(r.URL.Path, "/agents/")
		log.Printf("Extracted agent ID: %s", agentID)
		if agentID != "" {
			agentDetailHandler(w, r)
		} else {
			log.Printf("Agent ID is empty, returning 404")
			http.NotFound(w, r)
		}
	})

	// Login routes
	mux.HandleFunc("/login", loginHandler(cfg))
	mux.HandleFunc("/admin/change-password", changePasswordHandler(cfg))
	mux.HandleFunc("/session-timeout", func(w http.ResponseWriter, r *http.Request) {
		next := sanitizeNextPath(r.URL.Query().Get("next"))
		renderSessionTimeout(w, next)
	})

	// Root handler - login or redirect
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		_, user, err := authorizeAdminSession(w, r, cfg, true)
		if err == nil {
			if user.MustChangePassword {
				http.Redirect(w, r, "/admin/change-password", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/agents", http.StatusFound)
			return
		}

		renderLogin(w, "", "")
	})

	httpServer := &http.Server{
		Addr:           ":" + cfg.Port,
		Handler:        mux,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		MaxHeaderBytes: cfg.MaxHeaderBytes,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting server on port %s", cfg.Port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Background goroutine to mark agents offline periodically
	go func() {
		ticker := time.NewTicker(cfg.OfflineCheckInterval)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-cfg.OfflineTimeout)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			count, err := server.MarkAgentsOffline(ctx, cutoff)
			cancel()
			if err != nil {
				log.Printf("Error marking agents offline: %v", err)
				continue
			}
			if count > 0 {
				log.Printf("Marked %d agent(s) offline (last_seen before %s)", count, cutoff.Format(time.RFC3339))
			}
		}
	}()

	// Graceful shutdown handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down server...")
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	log.Println("Server stopped")
}
