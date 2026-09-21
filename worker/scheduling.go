package worker

import "slices"

// Prioritize the longest remaining dependency chain. Store hashes are only a
// deterministic tie-breaker, not an estimate of how urgently a build is needed.
func poolPriorities(deps map[string][]string) map[string]int {
	consumers := map[string][]string{}
	for drv, inputs := range deps {
		for _, input := range inputs {
			consumers[input] = append(consumers[input], drv)
		}
	}
	priority := map[string]int{}
	var visit func(string) int
	visit = func(drv string) int {
		if priority[drv] == 0 {
			priority[drv] = 1
			for _, consumer := range consumers[drv] {
				priority[drv] = max(priority[drv], 1+visit(consumer))
			}
		}
		return priority[drv]
	}
	for drv := range deps {
		visit(drv)
	}
	return priority
}

func poolOrder(specs map[string]string, priority map[string]int) []string {
	order := sortedKeys(specs)
	slices.SortStableFunc(order, func(a, b string) int { return priority[b] - priority[a] })
	return order
}
