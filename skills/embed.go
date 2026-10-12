// Package skills embeds the skill texts, so the MCP server can serve them as
// prompts from a binary installed without this repository.
package skills

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed */SKILL.md
var FS embed.FS

// Text returns one skill's SKILL.md, "" when there is no such skill.
func Text(name string) string {
	b, _ := FS.ReadFile(name + "/SKILL.md")
	return string(b)
}

// Names lists the embedded skills in name order.
func Names() []string {
	dirs, _ := fs.ReadDir(FS, ".")
	var names []string
	for _, d := range dirs {
		if d.IsDir() {
			names = append(names, d.Name())
		}
	}
	return names
}

// Description returns the description line of a skill's frontmatter.
func Description(name string) string {
	for _, line := range strings.Split(Text(name), "\n") {
		if rest, ok := strings.CutPrefix(line, "description: "); ok {
			return rest
		}
	}
	return ""
}
