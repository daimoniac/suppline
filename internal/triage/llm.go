package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type chatMessage struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []toolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type toolDef struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type completion struct {
	Content   string
	ToolCalls []toolCall
	Tokens    int
}

// Client calls an OpenAI-compatible /chat/completions endpoint.
type Client struct {
	BaseURL string
	Model   string
	APIKey  string
	HTTP    *http.Client
}

func (c *Client) Complete(ctx context.Context, messages []chatMessage, tools []toolDef) (completion, error) {
	body := map[string]any{
		"model":       c.Model,
		"messages":    messages,
		"temperature": 0,
	}
	if len(tools) > 0 {
		body["tools"] = tools
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return completion{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(raw))
	if err != nil {
		return completion{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 3 * time.Minute}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return completion{}, fmt.Errorf("llm request: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return completion{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return completion{}, fmt.Errorf("llm status %d: %s", resp.StatusCode, truncate(string(payload), 500))
	}
	var parsed struct {
		Choices []struct {
			Message chatMessage `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return completion{}, fmt.Errorf("decode llm response: %w", err)
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return completion{}, fmt.Errorf("llm error: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return completion{}, fmt.Errorf("llm response had no choices")
	}
	return completion{
		Content:   parsed.Choices[0].Message.Content,
		ToolCalls: parsed.Choices[0].Message.ToolCalls,
		Tokens:    parsed.Usage.TotalTokens,
	}, nil
}

func truncate(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n]
}
