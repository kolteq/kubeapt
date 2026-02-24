// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package worker

import "runtime"

// WorkerLimit caps concurrency to the scheduler limit and available work.
func WorkerLimit(total int) int {
	if total <= 0 {
		return 1
	}
	limit := runtime.GOMAXPROCS(0)
	if limit < 1 {
		limit = 1
	}
	if total < limit {
		return total
	}
	return limit
}
