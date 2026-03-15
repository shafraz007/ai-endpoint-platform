package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"github.com/shafraz007/ai-endpoint-platform/internal/server"
	"github.com/shafraz007/ai-endpoint-platform/internal/transport"
)

func schedulesHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleScheduleList(w, r, cfg)
		case http.MethodPost:
			handleScheduleCreate(w, r, cfg)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func scheduleHandler(cfg config.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			handleScheduleUpdate(w, r, cfg)
		case http.MethodDelete:
			handleScheduleDelete(w, r, cfg)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func handleScheduleList(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil {
			limit = parsed
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	schedules, err := server.ListSchedules(ctx, limit)
	if err != nil {
		log.Printf("ListSchedules error: %v", err)
		http.Error(w, "Failed to list schedules", http.StatusInternalServerError)
		return
	}

	resp := make([]transport.Schedule, 0, len(schedules))
	for _, item := range schedules {
		resp = append(resp, mapScheduleToTransport(item))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleScheduleCreate(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	_, user, err := authorizeAdminRequest(w, r, cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req transport.ScheduleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	schedule := server.Schedule{
		Name:                  req.Name,
		Kind:                  req.Kind,
		TargetScope:           req.TargetScope,
		TargetAgentID:         req.TargetAgentID,
		TargetGroupID:         req.TargetGroupID,
		CommandType:           req.CommandType,
		Payload:               req.Payload,
		RunAt:                 req.RunAt,
		RepeatIntervalSeconds: req.RepeatIntervalSeconds,
		RecurrenceRule:        req.RecurrenceRule,
		Enabled:               req.Enabled,
		NextRunAt:             req.NextRunAt,
		CreatedBy:             user.Username,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	created, err := server.CreateSchedule(ctx, schedule)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(mapScheduleToTransport(*created))
}

func handleScheduleUpdate(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	id, ok := parseIDFromPath(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid schedule id", http.StatusBadRequest)
		return
	}

	var req transport.ScheduleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	schedule := server.Schedule{
		Name:                  req.Name,
		Kind:                  req.Kind,
		TargetScope:           req.TargetScope,
		TargetAgentID:         req.TargetAgentID,
		TargetGroupID:         req.TargetGroupID,
		CommandType:           req.CommandType,
		Payload:               req.Payload,
		RunAt:                 req.RunAt,
		RepeatIntervalSeconds: req.RepeatIntervalSeconds,
		RecurrenceRule:        req.RecurrenceRule,
		Enabled:               req.Enabled,
		NextRunAt:             req.NextRunAt,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	updated, err := server.UpdateSchedule(ctx, int64(id), schedule)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mapScheduleToTransport(*updated))
}

func handleScheduleDelete(w http.ResponseWriter, r *http.Request, cfg config.ServerConfig) {
	if _, _, err := authorizeAdminRequest(w, r, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	id, ok := parseIDFromPath(r.URL.Path)
	if !ok {
		http.Error(w, "Invalid schedule id", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := server.DeleteSchedule(ctx, int64(id)); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func mapScheduleToTransport(item server.Schedule) transport.Schedule {
	return transport.Schedule{
		ID:                    item.ID,
		Name:                  item.Name,
		Kind:                  item.Kind,
		TargetScope:           item.TargetScope,
		TargetAgentID:         item.TargetAgentID,
		TargetGroupID:         item.TargetGroupID,
		CommandType:           item.CommandType,
		Payload:               item.Payload,
		RunAt:                 item.RunAt,
		RepeatIntervalSeconds: item.RepeatIntervalSeconds,
		RecurrenceRule:        item.RecurrenceRule,
		Enabled:               item.Enabled,
		LastRunAt:             item.LastRunAt,
		NextRunAt:             item.NextRunAt,
		CreatedBy:             item.CreatedBy,
		CreatedAt:             item.CreatedAt,
		UpdatedAt:             item.UpdatedAt,
	}
}
