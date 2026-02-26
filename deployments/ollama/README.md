Ollama Docker setup (Linux)

1) Start Ollama (CPU)

  cd deployments/ollama
  docker compose up -d

2) Optional: Start Ollama with NVIDIA GPU

  cd deployments/ollama
  docker compose -f docker-compose.yml -f docker-compose.nvidia.yml up -d

3) Verify API

  curl http://localhost:11434/api/tags

4) Pull a model

  docker exec -it ollama ollama pull llama3.2

5) Quick test

  curl http://localhost:11434/api/chat -d '{
    "model": "llama3.2",
    "messages": [{"role":"user", "content":"hello"}],
    "stream": false
  }'

6) Point agent to Ollama

  export AGENT_AI_PROVIDER=ollama
  export AGENT_AI_ENDPOINT=http://localhost:11434/v1/chat/completions
  export AGENT_AI_MODEL=llama3.2
  export AGENT_AI_API_KEY=

  go run ./cmd/agent

Notes
- Data is persisted in Docker volume ollama_data.
- Stop with: docker compose down
- Remove data with: docker volume rm deployments_ollama_data (project/volume name may vary)
