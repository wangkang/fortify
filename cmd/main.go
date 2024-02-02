package cmd

func Execute() int {
	if err := root.Execute(); err == nil {
		return 0
	} else {
		return 1
	}
}
