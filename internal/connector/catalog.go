package connector

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
)

//go:embed templates/*.yaml
var embeddedTemplates embed.FS

// Catalog is the set of connectors this process knows.
type Catalog struct {
	list []*Connector
	byID map[string]*Connector
}

// Connectors returns every connector, built-in first, then by title.
func (c *Catalog) Connectors() []*Connector { return c.list }

// Connector returns one connector.
func (c *Catalog) Connector(id string) (*Connector, bool) {
	x, ok := c.byID[id]
	return x, ok
}

// Action looks up connector and action together.
func (c *Catalog) Action(connectorID, actionID string) (*Connector, *Action, bool) {
	conn, ok := c.byID[connectorID]
	if !ok {
		return nil, nil, false
	}
	a, ok := conn.Action(actionID)
	return conn, a, ok
}

// ParseTemplate decodes and validates one YAML connector template.
func ParseTemplate(data []byte, source string) (*Connector, error) {
	var c Connector
	if err := yaml.UnmarshalWithOptions(data, &c, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	// YAML decodes numbers into several Go types; a JSON round trip gives
	// bodies, defaults and test inputs the float64/map[string]any shapes the
	// expression language works with.
	for i := range c.Actions {
		a := &c.Actions[i]
		a.Request.Body = jsonShape(a.Request.Body)
		for j := range a.Inputs {
			a.Inputs[j].Default = jsonShape(a.Inputs[j].Default)
		}
		a.OutputFields = make([]string, 0, len(a.Output))
		for name := range a.Output {
			a.OutputFields = append(a.OutputFields, name)
		}
		sort.Strings(a.OutputFields)
	}
	if c.TestInputs != nil {
		if m, ok := jsonShape(c.TestInputs).(map[string]any); ok {
			c.TestInputs = m
		}
	}
	c.Source = source
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return &c, nil
}

func jsonShape(v any) any {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(raw, &out) != nil {
		return v
	}
	return out
}

// Load builds a catalog from the built-in connector, the embedded
// templates and, when dir is set, every *.yaml file in dir. A deployment
// template may not reuse the ID of a shipped one.
func Load(dir string) (*Catalog, error) {
	cat := &Catalog{byID: map[string]*Connector{}}
	add := func(c *Connector) error {
		if _, dup := cat.byID[c.ID]; dup {
			return fmt.Errorf("connector %s is defined twice", c.ID)
		}
		cat.byID[c.ID] = c
		cat.list = append(cat.list, c)
		return nil
	}
	builtin := builtinConnector()
	if err := builtin.Validate(); err != nil {
		return nil, err
	}
	_ = add(builtin)
	entries, err := embeddedTemplates.ReadDir("templates")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		data, err := embeddedTemplates.ReadFile("templates/" + e.Name())
		if err != nil {
			return nil, err
		}
		c, err := ParseTemplate(data, "builtin")
		if err != nil {
			return nil, fmt.Errorf("templates/%s: %w", e.Name(), err)
		}
		if err := add(c); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(dir) != "" {
		files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			c, err := ParseTemplate(data, filepath.Base(f))
			if err != nil {
				return nil, err
			}
			if err := add(c); err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
			}
		}
	}
	sort.SliceStable(cat.list[1:], func(i, j int) bool {
		return cat.list[1+i].Title < cat.list[1+j].Title
	})
	return cat, nil
}

// DirEnv names the directory of deployment connector templates.
const DirEnv = "AGENTFLOW_CONNECTOR_DIR"

var (
	defaultOnce    sync.Once
	defaultCatalog *Catalog
)

// Default returns the process catalog: shipped templates plus those in
// AGENTFLOW_CONNECTOR_DIR. A broken deployment template is logged and the
// directory ignored, so one bad file cannot take the platform down.
func Default() *Catalog {
	defaultOnce.Do(func() {
		cat, err := Load(os.Getenv(DirEnv))
		if err != nil {
			log.Printf("connector templates in %s ignored: %v", os.Getenv(DirEnv), err)
			cat, err = Load("")
			if err != nil {
				panic(fmt.Sprintf("shipped connector templates are invalid: %v", err))
			}
		}
		defaultCatalog = cat
	})
	return defaultCatalog
}
