package sqlite

import (
	"context"
	"fmt"
	"os"
)

type ReportData struct {
	Headers []string
	Records [][]string
}

func (s *Store) QueryReportData(ctx context.Context) (ReportData, error) {
	queryBytes, err := os.ReadFile(s.reportSQLPath)
	if err != nil {
		return ReportData{}, fmt.Errorf("failed to read report sql from %q: %w", s.reportSQLPath, err)
	}
	query := string(queryBytes)

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return ReportData{}, err
	}
	defer rows.Close()

	headers, err := rows.Columns()
	if err != nil {
		return ReportData{}, err
	}

	records := make([][]string, 0, 256)
	for rows.Next() {
		vals := make([]interface{}, len(headers))
		valPtrs := make([]interface{}, len(headers))
		for i := range vals {
			valPtrs[i] = &vals[i]
		}
		if err := rows.Scan(valPtrs...); err != nil {
			return ReportData{}, err
		}
		record := make([]string, len(headers))
		for i, v := range vals {
			record[i] = stringifyDBValue(v)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return ReportData{}, err
	}
	return ReportData{Headers: headers, Records: records}, nil
}
