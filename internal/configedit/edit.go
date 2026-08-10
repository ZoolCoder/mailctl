// Package configedit makes small, comment-preserving changes to a mailctl
// config file. It edits the YAML node tree rather than round-tripping through
// the config structs, which would delete every comment in the file.
//
// Comments, key order, and quoting all survive an edit, because the
// yaml.Node tree carries them. Blank lines do not: yaml.Node has no node
// representing a blank line, so re-encoding the tree drops every blank line
// in the file, not just ones near the edited section. Callers that edit a
// hand-formatted file should tell the operator; see main's
// noteConfigRewritten.
package configedit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"gopkg.in/yaml.v3"
)

// AddMailbox appends a mailbox to a domain.
func AddMailbox(path, domain, address, passwordEnv string) error {
	return edit(path, func(d *yaml.Node) error {
		list, err := ensureSequence(d, domain, "mailboxes")
		if err != nil {
			return err
		}
		for _, item := range list.Content {
			if strings.EqualFold(scalarField(item, "address"), address) {
				return fmt.Errorf("mailbox %s is already in the config for %s", address, domain)
			}
		}

		entry := mapping(
			"address", address,
		)
		if passwordEnv != "" {
			appendPair(entry, "passwordEnv", passwordEnv)
		}
		list.Content = append(list.Content, entry)
		return nil
	}, domain)
}

// RemoveMailbox drops a mailbox from a domain. It does not delete the mailbox
// at the provider; that happens on the next apply with -prune.
func RemoveMailbox(path, domain, address string) error {
	return edit(path, func(d *yaml.Node) error {
		list, err := mutableSequence(d, domain, "mailboxes")
		if err != nil {
			return err
		}
		kept := list.Content[:0]
		found := false
		for _, item := range list.Content {
			if strings.EqualFold(scalarField(item, "address"), address) {
				found = true
				continue
			}
			kept = append(kept, item)
		}
		if !found {
			return fmt.Errorf("mailbox %s is not in the config for %s", address, domain)
		}
		list.Content = kept
		return nil
	}, domain)
}

// AddAlias appends an alias to a domain.
func AddAlias(path, domain, match string, to []string) error {
	return edit(path, func(d *yaml.Node) error {
		list, err := ensureSequence(d, domain, "aliases")
		if err != nil {
			return err
		}
		for _, item := range list.Content {
			if strings.EqualFold(scalarField(item, "match"), match) {
				return fmt.Errorf("alias %s is already in the config for %s", match, domain)
			}
		}

		entry := mapping("match", match)
		targets := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, address := range to {
			targets.Content = append(targets.Content, scalar(address))
		}
		entry.Content = append(entry.Content, scalar("to"), targets)
		list.Content = append(list.Content, entry)
		return nil
	}, domain)
}

// RemoveAlias drops an alias from a domain.
func RemoveAlias(path, domain, match string) error {
	return edit(path, func(d *yaml.Node) error {
		list, err := mutableSequence(d, domain, "aliases")
		if err != nil {
			return err
		}
		kept := list.Content[:0]
		found := false
		for _, item := range list.Content {
			if strings.EqualFold(scalarField(item, "match"), match) {
				found = true
				continue
			}
			kept = append(kept, item)
		}
		if !found {
			return fmt.Errorf("alias %s is not in the config for %s", match, domain)
		}
		list.Content = kept
		return nil
	}, domain)
}

// edit loads the file, hands the requested domain's mapping node to mutate,
// and commits the result. The write is transactional: commit validates the
// rendered document before path is touched, so a mutate that would produce
// an invalid config leaves the original file untouched.
func edit(path string, mutate func(domain *yaml.Node) error, domainName string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config %s: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	if len(doc.Content) == 0 {
		return fmt.Errorf("config %s is empty", path)
	}
	root := doc.Content[0]

	domains := findSequence(root, "domains")
	if domains == nil {
		return fmt.Errorf("config %s has no domains list", path)
	}
	var target *yaml.Node
	for _, item := range domains.Content {
		if strings.EqualFold(scalarField(item, "name"), domainName) {
			target = item
			break
		}
	}
	if target == nil {
		return fmt.Errorf("domain %s is not in %s", domainName, path)
	}

	if err := mutate(target); err != nil {
		return err
	}

	var out strings.Builder
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&doc); err != nil {
		return fmt.Errorf("render config %s: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("render config %s: %w", path, err)
	}

	return commit(path, domainName, []byte(out.String()), info.Mode().Perm())
}

// commit validates rendered before path is ever touched: it writes rendered
// to a sibling temp file, confirms that file still loads through
// config.Load, and only then renames it over path. A rejected edit leaves
// path byte-identical to before the call. The rename is also what makes the
// replacement atomic and permission-preserving: os.WriteFile in place would
// truncate path directly, follow a symlink at path into whatever it points
// to, and leave a half-written file behind if interrupted.
func commit(path, domainName string, rendered []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp config near %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(rendered); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write temp config %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("set permissions on temp config %s: %w", tmpPath, err)
	}

	if _, err := config.Load(tmpPath, os.Getenv); err != nil {
		return fmt.Errorf("edit to domain %s would leave %s unloadable, so it was not written: %w",
			domainName, path, err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace config %s: %w", path, err)
	}
	return nil
}

func findSequence(mappingNode *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mappingNode.Content); i += 2 {
		if mappingNode.Content[i].Value == key {
			return mappingNode.Content[i+1]
		}
	}
	return nil
}

// ensureSequence returns the sequence node under key on an add path, creating
// an empty one if key is absent and replacing it in place if it is a bare
// null scalar (e.g. "mailboxes:" with no value, which the encoder would
// otherwise silently discard any append to). It refuses to hand back a node
// this package cannot safely append to: a YAML alias, since appending to an
// alias node never reaches the anchor it points to, or an anchored sequence,
// since appending there would also be visible to every domain that aliases
// the anchor.
func ensureSequence(mappingNode *yaml.Node, domain, key string) (*yaml.Node, error) {
	existing := findSequence(mappingNode, key)
	if existing == nil {
		list := &yaml.Node{Kind: yaml.SequenceNode}
		mappingNode.Content = append(mappingNode.Content, scalar(key), list)
		return list, nil
	}

	switch {
	case existing.Kind == yaml.AliasNode:
		return nil, fmt.Errorf(
			"domain %s: %s is a YAML alias to &%s; edit the anchor directly instead",
			domain, key, existing.Value)
	case existing.Kind == yaml.SequenceNode:
		if existing.Anchor != "" {
			return nil, fmt.Errorf(
				"domain %s: %s is anchored as &%s and shared with other domains; edit the anchor directly instead",
				domain, key, existing.Anchor)
		}
		return existing, nil
	case isNullScalar(existing):
		existing.Kind = yaml.SequenceNode
		existing.Tag = ""
		existing.Value = ""
		existing.Style = 0
		existing.Content = nil
		return existing, nil
	default:
		return nil, fmt.Errorf("domain %s: %s is not a sequence", domain, key)
	}
}

// mutableSequence is ensureSequence's counterpart for a remove path: it never
// creates or repairs anything, and treats a missing, null, or alias section
// alike, since none of them has anything for the caller to remove. It refuses
// an anchored sequence for the same reason ensureSequence does.
func mutableSequence(mappingNode *yaml.Node, domain, key string) (*yaml.Node, error) {
	existing := findSequence(mappingNode, key)
	if existing == nil || isNullScalar(existing) {
		return nil, fmt.Errorf("domain %s has no %s block", domain, key)
	}
	if existing.Kind == yaml.AliasNode {
		return nil, fmt.Errorf(
			"domain %s: %s is a YAML alias to &%s; edit the anchor directly instead",
			domain, key, existing.Value)
	}
	if existing.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("domain %s: %s is not a sequence", domain, key)
	}
	if existing.Anchor != "" {
		return nil, fmt.Errorf(
			"domain %s: %s is anchored as &%s and shared with other domains; edit the anchor directly instead",
			domain, key, existing.Anchor)
	}
	return existing, nil
}

func isNullScalar(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

func scalarField(mappingNode *yaml.Node, key string) string {
	for i := 0; i+1 < len(mappingNode.Content); i += 2 {
		if mappingNode.Content[i].Value == key {
			return mappingNode.Content[i+1].Value
		}
	}
	return ""
}

func scalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func mapping(pairs ...string) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode}
	for i := 0; i+1 < len(pairs); i += 2 {
		appendPair(node, pairs[i], pairs[i+1])
	}
	return node
}

func appendPair(mappingNode *yaml.Node, key, value string) {
	mappingNode.Content = append(mappingNode.Content, scalar(key), scalar(value))
}
