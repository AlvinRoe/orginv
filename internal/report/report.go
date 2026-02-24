package report

import (
	"context"

	"github.com/AlvinRoe/orginv/internal/store/sqlite"
)

type Exporter struct {
	store *sqlite.Store
}

func NewExporter(store *sqlite.Store) *Exporter {
	return &Exporter{store: store}
}

func (e *Exporter) ExportCSV(ctx context.Context, outputPath string) error {
	return e.store.ExportCSVReport(ctx, outputPath)
}
