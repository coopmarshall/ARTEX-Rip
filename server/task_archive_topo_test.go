package server

import (
	"reflect"
	"testing"
)

// TestTopoTaskIDsDeduplicatesInput is a regression test for a real bug: a
// duplicate id with no incoming edge (indegree 0) was queued, and thus
// emitted, once per occurrence in the input slice instead of once overall.
// Reachable in practice via orderColdTaskArchiveBatch if two distinct
// archive rows ever reference the same task_id (taskToArchive[taskID]
// would then silently collapse to one archive id, duplicated in the
// output, while the other archive id's intended topological position is
// lost -- it still appears via the trailing "not seen" fallback, but out
// of order).
func TestTopoTaskIDsDeduplicatesInput(t *testing.T) {
	out := topoTaskIDs([]string{"1", "1", "2"}, nil, false)
	if len(out) != 2 {
		t.Fatalf("topoTaskIDs with a duplicate id = %v (len %d), want 2 unique ids", out, len(out))
	}
	seen := map[string]bool{}
	for _, id := range out {
		if seen[id] {
			t.Fatalf("id %q appears more than once in %v", id, out)
		}
		seen[id] = true
	}
}

// TestTopoTaskIDsArchiveOrdersDependentBeforeSource covers the
// archive/delete direction (restore=false): per the doc comment ("orders
// ... dependent->source for archive/delete"), the dependent must be
// archived/deleted before the source it depends on.
func TestTopoTaskIDsArchiveOrdersDependentBeforeSource(t *testing.T) {
	// "2" depends on "1" (sources["2"] = ["1"]).
	out := topoTaskIDs([]string{"2", "1"}, map[string][]string{"2": {"1"}}, false)
	if !reflect.DeepEqual(out, []string{"2", "1"}) {
		t.Fatalf("archive-direction order = %v, want [2 1] (dependent before source)", out)
	}
}

// TestTopoTaskIDsRestoreOrdersSourceBeforeDependent covers the restore
// direction (restore=true): per the doc comment ("orders source->dependent
// for restore"), the source must be restored before the dependent that
// needs it.
func TestTopoTaskIDsRestoreOrdersSourceBeforeDependent(t *testing.T) {
	out := topoTaskIDs([]string{"2", "1"}, map[string][]string{"2": {"1"}}, true)
	if !reflect.DeepEqual(out, []string{"1", "2"}) {
		t.Fatalf("restore-direction order = %v, want [1 2] (source before dependent)", out)
	}
}

// TestTopoTaskIDsHandlesCycleWithoutHanging is the stated design intent
// ("cycles are impossible at creation, but stable fallback keeps a damaged
// database operable"): a cycle must not infinite-loop or drop ids, just
// fall back to emitting whatever never reached indegree 0.
func TestTopoTaskIDsHandlesCycleWithoutHanging(t *testing.T) {
	out := topoTaskIDs([]string{"1", "2"}, map[string][]string{"1": {"2"}, "2": {"1"}}, false)
	if len(out) != 2 {
		t.Fatalf("cyclic input: got %v, want both ids present via the fallback", out)
	}
}

// TestTopoTaskIDsIgnoresEdgesOutsideTheIDSet covers a source/dependent
// reference to an id not in the batch -- it must be silently ignored
// rather than introduce a phantom node or panic on a nil map lookup.
func TestTopoTaskIDsIgnoresEdgesOutsideTheIDSet(t *testing.T) {
	out := topoTaskIDs([]string{"1"}, map[string][]string{"1": {"999"}, "999": {"1"}}, false)
	if !reflect.DeepEqual(out, []string{"1"}) {
		t.Fatalf("got %v, want [1] with the out-of-set id ignored", out)
	}
}

func TestNormalizeArchiveIDsRejectsEmptyTooManyAndInvalid(t *testing.T) {
	if _, err := normalizeArchiveIDs(nil); err == nil {
		t.Error("empty input should error")
	}
	many := make([]int64, 101)
	for i := range many {
		many[i] = int64(i + 1)
	}
	if _, err := normalizeArchiveIDs(many); err == nil {
		t.Error("over 100 ids should error")
	}
	if _, err := normalizeArchiveIDs([]int64{0}); err == nil {
		t.Error("id 0 should error")
	}
	if _, err := normalizeArchiveIDs([]int64{-1}); err == nil {
		t.Error("negative id should error")
	}
}

func TestNormalizeArchiveIDsDeduplicatesPreservingOrder(t *testing.T) {
	out, err := normalizeArchiveIDs([]int64{3, 1, 3, 2, 1})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, []int64{3, 1, 2}) {
		t.Fatalf("got %v, want [3 1 2] (first-occurrence order, deduplicated)", out)
	}
}
