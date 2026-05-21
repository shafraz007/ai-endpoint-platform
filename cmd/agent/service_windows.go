package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/shafraz007/ai-endpoint-platform/internal/config"
	"golang.org/x/sys/windows/svc"
)

const windowsServiceName = "ArmadaAgent"

type armadaService struct {
	cfg config.AgentConfig
}

func tryRunWindowsService(cfg config.AgentConfig) bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("Windows service detection failed; continuing in console mode: %v", err)
		return false
	}
	if !isService {
		return false
	}

	log.Printf("Running as Windows service: %s", windowsServiceName)
	if err := svc.Run(windowsServiceName, &armadaService{cfg: cfg}); err != nil {
		log.Printf("Windows service run failed: %v", err)
	}
	return true
}

func (s *armadaService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runAgent(ctx, s.cfg)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case change := <-req:
			switch change.Cmd {
			case svc.Interrogate:
				status <- change.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()

				select {
				case err := <-done:
					if err != nil && !strings.Contains(strings.ToLower(err.Error()), "context canceled") {
						log.Printf("Service stop returned error: %v", err)
					}
				case <-time.After(8 * time.Second):
					log.Printf("Service stop timed out waiting for agent loop to exit")
				}
				return false, 0
			default:
			}
		case err := <-done:
			if err != nil && !strings.Contains(strings.ToLower(err.Error()), "context canceled") {
				log.Printf("Service worker exited with error: %v", err)
			}
			return false, 0
		}
	}
}
