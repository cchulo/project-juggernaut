// Command stdioserver is a small stdio MCP server used by the tests: it
// exposes `echo` (returns its input), `env` (returns the values of the named
// environment variables, to prove token and secret injection) and `whoenv`
// (lists every JUGGERNAUT_/TEST_ variable name it sees).
package main

import (
	"context"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoIn struct {
	Text string `json:"text"`
}

type envIn struct {
	Names []string `json:"names"`
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "stdioserver", Version: "test"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "returns text"}, func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Text}}}, nil, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "env", Description: "returns env values"}, func(_ context.Context, _ *mcp.CallToolRequest, in envIn) (*mcp.CallToolResult, any, error) {
		var parts []string
		for _, n := range in.Names {
			parts = append(parts, n+"="+os.Getenv(n))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(parts, ";")}}}, nil, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "secret_tool", Description: "hidden by exposure rules in tests"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "you should not see this"}}}, nil, nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "whoenv", Description: "lists variable names"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		var names []string
		for _, kv := range os.Environ() {
			k, _, _ := strings.Cut(kv, "=")
			if strings.HasPrefix(k, "JUGGERNAUT_") || strings.HasPrefix(k, "TEST_") {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(names, ",")}}}, nil, nil
	})
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
