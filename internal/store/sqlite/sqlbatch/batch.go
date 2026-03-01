package sqlbatch

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type FlushOptions struct {
	MaxStatementsPerChunk int
	MaxBytesPerChunk      int
}

type TableBatch struct {
	Name       string
	Statements []string
}

type Batch struct {
	tables map[string]*TableBatch
	order  []string
}

func New() *Batch {
	return &Batch{
		tables: make(map[string]*TableBatch),
		order:  make([]string, 0, 8),
	}
}

func (b *Batch) Add(table, stmt string) {
	if strings.TrimSpace(stmt) == "" {
		return
	}
	tb, ok := b.tables[table]
	if !ok {
		tb = &TableBatch{Name: table}
		b.tables[table] = tb
		b.order = append(b.order, table)
	}
	tb.Statements = append(tb.Statements, strings.TrimSpace(stmt))
}

func (b *Batch) Empty() bool {
	return len(b.order) == 0
}

func (b *Batch) TableCount(table string) int {
	tb, ok := b.tables[table]
	if !ok {
		return 0
	}
	return len(tb.Statements)
}

func (b *Batch) TotalStatementCount() int {
	total := 0
	for _, table := range b.order {
		total += len(b.tables[table].Statements)
	}
	return total
}

func (b *Batch) TableByteSize(table string) int {
	tb, ok := b.tables[table]
	if !ok {
		return 0
	}
	size := 0
	for _, stmt := range tb.Statements {
		size += len(stmt) + 2
	}
	return size
}

func (b *Batch) TotalByteSize() int {
	total := 0
	for _, table := range b.order {
		total += b.TableByteSize(table)
	}
	return total
}

func (b *Batch) Tables() []string {
	return append([]string(nil), b.order...)
}

func (b *Batch) FlushInOrder(ctx context.Context, execer Execer, opts FlushOptions) error {
	for _, table := range b.order {
		tb := b.tables[table]
		if len(tb.Statements) == 0 {
			continue
		}
		for _, chunk := range chunkStatements(tb.Statements, opts) {
			if len(chunk) == 0 {
				continue
			}
			if _, err := execer.ExecContext(ctx, strings.Join(chunk, ";\n")+";"); err != nil {
				return fmt.Errorf("flush table %s: %w", table, err)
			}
		}
	}
	return nil
}

func chunkStatements(stmts []string, opts FlushOptions) [][]string {
	maxStatements := opts.MaxStatementsPerChunk
	maxBytes := opts.MaxBytesPerChunk
	if maxStatements <= 0 {
		maxStatements = len(stmts)
	}
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}

	chunks := make([][]string, 0, max(1, len(stmts)))
	current := make([]string, 0, min(maxStatements, len(stmts)))
	currentBytes := 0

	flush := func() {
		if len(current) == 0 {
			return
		}
		chunks = append(chunks, current)
		current = make([]string, 0, min(maxStatements, len(stmts)))
		currentBytes = 0
	}

	for _, stmt := range stmts {
		stmtBytes := len(stmt) + 2
		if len(current) > 0 && (len(current) >= maxStatements || currentBytes+stmtBytes > maxBytes) {
			flush()
		}
		current = append(current, stmt)
		currentBytes += stmtBytes
	}
	flush()

	return chunks
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
