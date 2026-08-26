package main

import "path"

func matchGlobs(globs []string, candidate string) bool {
	for _, glob := range globs {
		match, err := path.Match(glob, candidate)
		if match && err == nil {
			return true
		}
	}
	return false
}

func validateGlobs(globs []string) error {
	for _, glob := range globs {
		_, err := path.Match(glob, "")
		if err != nil {
			return err
		}
	}
	return nil
}
